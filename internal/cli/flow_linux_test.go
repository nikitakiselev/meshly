//go:build linux

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/engine/enginetest"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/lock"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/pairing"
	"github.com/nikitakiselev/meshly/internal/preflight"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// testNode is one meshly node on a fake kernel.
type testNode struct {
	t      *testing.T
	app    *App
	k      *enginetest.Kernel
	root   string
	now    time.Time
	output strings.Builder // everything ever printed
}

func newTestNode(t *testing.T, start time.Time) *testNode {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"sys/module/wireguard", "usr/sbin", "proc/net"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"usr/sbin/nft", "proc/net/udp", "proc/net/udp6"} {
		if err := os.WriteFile(filepath.Join(root, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	n := &testNode{t: t, k: enginetest.New(), root: root, now: start}
	paths := store.RootedPaths(root, os.Getuid())
	clock := func() time.Time { return n.now }
	sys := &preflight.System{
		NFT: n.k.NFT(), Links: n.k.LinkOps(), Root: root, Euid: 0, KernelRe: "6.1.0",
		Exec: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("not available") },
	}
	n.app = &App{
		Stdin: strings.NewReader(""), Paths: paths, Now: clock,
		Journal: journal.Open(paths.JournalFile(), clock), Sys: sys, Euid: 0, LockTimeout: time.Second, Arch: "amd64",
		// A network of its own until a test connects two nodes.
		Pairing:  pairing.NewMemory().View(netip.Addr{}, nil),
		Hostname: func() (string, error) { return "testhost", nil },
	}
	n.app.Engine = &engine.Engine{Links: n.k.LinkOps(), WG: n.k.WGOps(), FW: n.k.NFT(), Paths: paths, LoadKeys: paths.LoadKeys, Now: clock,
		Progress: func(s string) { n.app.printf("  %s\n", s) }}
	return n
}

// sibling is a second meshly process on the same node: the same root and
// kernel, its own App, journal and output.
func (n *testNode) sibling() *testNode {
	s := &testNode{t: n.t, k: n.k, root: n.root, now: n.now}
	app := *n.app
	clock := func() time.Time { return s.now }
	app.Now = clock
	app.Journal = journal.Open(app.Paths.JournalFile(), clock)
	app.Stdin = strings.NewReader("")
	app.WaitContext, app.After = nil, nil
	eng := *n.app.Engine
	eng.Now = clock
	eng.Progress = func(m string) { s.app.printf("  %s\n", m) }
	app.Engine = &eng
	s.app = &app
	return s
}

// run executes a command and returns exit code, stdout and stderr.
func (n *testNode) run(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	n.app.Stdout, n.app.Stderr = &o, &e
	code := n.app.Main(args)
	n.output.WriteString(o.String() + e.String())
	return code, o.String(), e.String()
}

func (n *testNode) must(args ...string) string {
	n.t.Helper()
	code, out, errOut := n.run(args...)
	if code != 0 {
		n.t.Fatalf("meshly %s: exit %d\n%s%s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

func (n *testNode) expect(code int, args ...string) string {
	n.t.Helper()
	got, out, errOut := n.run(args...)
	if got != code {
		n.t.Fatalf("meshly %s: exit %d, want %d\n%s%s", strings.Join(args, " "), got, code, out, errOut)
	}
	return out + errOut
}

func (n *testNode) secrets() []string {
	var s []string
	for _, f := range []string{"wireguard.key"} {
		b, err := os.ReadFile(filepath.Join(n.app.Paths.KeysDir, f))
		if err == nil {
			s = append(s, strings.TrimSpace(string(b)))
		}
	}
	return s
}

var start = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// The VPN addresses of vps and home in the default network: the source of
// their connections through the tunnel.
var (
	vpsVPN  = netip.MustParseAddr("10.100.0.1")
	homeVPN = netip.MustParseAddr("10.100.0.2")
)

// newPair returns two nodes on one in-memory pairing network: vps,
// initialized with a public endpoint, and an empty home. Dials from home
// pass only through a working tunnel (see tunnelUp) and come from its VPN
// address.
func newPair(t *testing.T) (vps, home *testNode, mem *pairing.Memory) {
	t.Helper()
	vps, home = newTestNode(t, start), newTestNode(t, start)
	mem = pairing.NewMemory()
	vps.app.Pairing = mem.View(vpsVPN, nil)
	home.app.Pairing = mem.View(homeVPN, tunnelUp(vps, home))
	vps.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820")
	return vps, home, mem
}

// pair connects home to vps with invite and join.
func pair(t *testing.T) (vps, home *testNode) {
	t.Helper()
	vps, home, _ = newPair(t)
	inv := startInvite(t, vps)
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("meshly join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("meshly invite: exit %d\n%s", code, out)
	}
	return vps, home
}

// tunnelUp lets a dial from b to a through only while the fake WireGuard
// devices of both nodes have each other's public key as a peer with the same
// preshared key: what a handshake needs. Like a TCP SYN being retransmitted,
// it waits a little for the other side to catch up before it fails.
func tunnelUp(a, b *testNode) func(netip.AddrPort) error {
	return func(netip.AddrPort) error {
		deadline := time.Now().Add(2 * time.Second)
		for {
			err := tunnelState(a, b)
			if err == nil || time.Now().After(deadline) {
				return err
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
}

func tunnelState(a, b *testNode) error {
	da, _ := a.k.WGOps().Observe("meshly0")
	db, _ := b.k.WGOps().Observe("meshly0")
	switch {
	case da == nil || db == nil:
		return errors.New("no tunnel: a WireGuard interface is missing")
	case !hasPeer(da, db.PublicKey) || !hasPeer(db, da.PublicKey):
		return errors.New("no tunnel: the nodes do not know each other's key")
	case a.k.PresharedKey(db.PublicKey) != b.k.PresharedKey(da.PublicKey):
		return errors.New("no tunnel: the preshared keys differ")
	}
	return nil
}

func hasPeer(d *wg.Device, key string) bool {
	_, ok := d.Peer(key)
	return ok
}

// syncBuffer is a bytes.Buffer safe for one writer and concurrent readers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

var codeRe = regexp.MustCompile(`^m1[a-z2-7]+$`)

// terminal is where a command in the background writes: once gone, every
// write fails the way it does to the terminal of a closed SSH session.
type terminal struct {
	w    io.Writer
	gone *atomic.Bool
}

func (t terminal) Write(p []byte) (int, error) {
	if t.gone.Load() {
		return 0, syscall.EIO
	}
	return t.w.Write(p)
}

// inviteRun is a `meshly invite` running in the background.
type inviteRun struct {
	t       *testing.T
	n       *testNode
	code    string       // the first line of stdout
	stdout  bytes.Buffer // stdout after the code line
	stderr  syncBuffer
	gone    atomic.Bool // the terminal is gone: see hangUp
	cancels chan context.CancelFunc
	expiry  chan time.Time
	done    chan int
	drained chan struct{}
	expired sync.Once
	waited  sync.Once
	exit    int
	out     string
}

// startInvite runs `meshly invite` in a goroutine and returns once it has
// printed the code. Ctrl+C is simulated through WaitContext and the end of
// the invite through After.
func startInvite(t *testing.T, n *testNode, args ...string) *inviteRun {
	t.Helper()
	r := &inviteRun{t: t, n: n, cancels: make(chan context.CancelFunc, 1), expiry: make(chan time.Time),
		done: make(chan int, 1), drained: make(chan struct{})}
	n.app.WaitContext = func(c context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(c)
		select {
		case r.cancels <- cancel:
		default:
		}
		return ctx, cancel
	}
	n.app.After = func(time.Duration) <-chan time.Time { return r.expiry }
	pr, pw := io.Pipe()
	n.app.Stdout, n.app.Stderr = terminal{pw, &r.gone}, terminal{&r.stderr, &r.gone}
	go func() {
		code := n.app.Main(append([]string{"invite"}, args...))
		_ = pw.Close()
		r.done <- code
	}()
	first := make(chan string, 1)
	go func() {
		defer close(r.drained)
		br := bufio.NewReader(pr)
		line, _ := br.ReadString('\n')
		first <- line
		_, _ = io.Copy(&r.stdout, br)
	}()
	t.Cleanup(func() {
		r.cancel()
		r.wait()
	})
	line := <-first
	r.code = strings.TrimSuffix(line, "\n")
	if !codeRe.MatchString(r.code) || line != r.code+"\n" {
		code, out := r.wait()
		t.Fatalf("meshly invite: the first line of stdout is not the code (exit %d): %q\n%s", code, line, out)
	}
	return r
}

// cancel simulates Ctrl+C.
func (r *inviteRun) cancel() {
	select {
	case f := <-r.cancels:
		f()
		r.cancels <- f
	default:
	}
}

// hangUp simulates the end of the SSH session the invite runs in: the
// terminal is gone and SIGHUP arrives.
func (r *inviteRun) hangUp() {
	r.gone.Store(true)
	r.cancel()
}

// expire ends the invite's validity.
func (r *inviteRun) expire() { r.expired.Do(func() { close(r.expiry) }) }

// wait returns the exit code and everything printed except the code line.
func (r *inviteRun) wait() (exit int, out string) {
	r.waited.Do(func() {
		select {
		case r.exit = <-r.done:
		case <-time.After(20 * time.Second):
			r.t.Fatal("meshly invite did not finish")
		}
		<-r.drained
		r.out = r.stdout.String() + r.stderr.String()
		r.n.output.WriteString(r.out)
	})
	return r.exit, r.out
}

// waitFor waits until the running invite has printed s to stderr.
func (r *inviteRun) waitFor(s string) {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(r.stderr.String(), s) {
		if time.Now().After(deadline) {
			r.t.Fatalf("meshly invite did not print %q:\n%s", s, r.stderr.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// joinWith runs `meshly join` with code on stdin.
func joinWith(n *testNode, code string, args ...string) (int, string, string) {
	n.app.Stdin = strings.NewReader(code + "\n")
	return n.run(append([]string{"join"}, args...)...)
}

func TestFlowAndSecrets(t *testing.T) {
	vps, home := pair(t)

	// Policy commands.
	if out := vps.must("allow", "22/tcp", "from", "home"); !strings.Contains(out, "Allowed") {
		t.Fatal(out)
	}
	if out := vps.must("allow", "22/tcp", "from", "home"); !strings.Contains(out, "Already allowed") {
		t.Fatal(out)
	}
	vps.must("allow", "ping", "from", "home")
	vps.expect(ExitConflict, "allow", "22/tcp", "from", "nobody")
	vps.expect(ExitUsage, "allow", "70000/tcp", "from", "home")
	vps.expect(ExitUsage, "allow", "22/sctp", "from", "home")
	vps.expect(ExitUsage, "allow", "22/tcp", "to", "home")

	// Dry run changes nothing.
	scripts, cfgBefore := len(vps.k.Scripts), readFile(t, vps.app.Paths.ConfigFile())
	if out := vps.must("allow", "8080/tcp", "from", "home", "--dry-run"); !strings.Contains(out, "Dry run") || !strings.Contains(out, "table inet meshly") {
		t.Fatalf("dry run output:\n%s", out)
	}
	if len(vps.k.Scripts) != scripts || readFile(t, vps.app.Paths.ConfigFile()) != cfgBefore {
		t.Fatal("dry run changed state")
	}

	// Machine-readable output is valid JSON with stable schemas.
	var st map[string]any
	if err := json.Unmarshal([]byte(vps.must("status", "--json")), &st); err != nil || st["schema"] != "meshly.status/v1" {
		t.Fatalf("status --json: %v %v", err, st["schema"])
	}
	var rules map[string]any
	if err := json.Unmarshal([]byte(vps.must("rules", "--json")), &rules); err != nil || rules["schema"] != "meshly.rules/v1" {
		t.Fatalf("rules --json: %v", err)
	}
	code, out, _ := home.run("doctor", "--json")
	if code != 0 && code != ExitWarnings && code != ExitProblems {
		t.Fatalf("doctor exit %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc["schema"] != "meshly.doctor/v1" {
		t.Fatalf("doctor --json: %v\n%s", err, out)
	}
	vps.must("logs", "--json")
	vps.must("logs")
	vps.must("status")
	home.must("status")

	// Lifecycle.
	vps.must("set", "mtu", "1380")
	vps.expect(ExitUsage, "set", "mtu", "100")
	vps.expect(ExitConflict, "set", "cidr", "10.200.0.0/24") // a peer exists
	vps.must("stop")
	if _, ok := vps.k.Links["meshly0"]; ok || vps.k.Table != "" {
		t.Fatal("stop left kernel objects")
	}
	vps.expect(ExitConflict, "restart")
	vps.must("start")
	if _, ok := vps.k.Links["meshly0"]; !ok || vps.k.Table == "" {
		t.Fatal("start did not restore the link")
	}
	vps.must("deny", "ping", "from", "home")
	vps.expect(ExitDeclined, "revoke", "home")
	vps.must("revoke", "home", "--yes")
	if out := vps.must("revoke", "home", "--yes"); !strings.Contains(out, "nothing to revoke") {
		t.Fatal(out)
	}

	// Never a secret in any output, the journal or the config.
	all := vps.output.String() + home.output.String()
	all += readFile(t, vps.app.Paths.JournalFile()) + readFile(t, vps.app.Paths.ConfigFile())
	for _, n := range []*testNode{vps, home} {
		for _, s := range n.secrets() {
			if len(s) < 40 {
				t.Fatalf("unexpected key file format: %d bytes", len(s))
			}
			if strings.Contains(all, s) {
				t.Fatal("a private key appears in output, the journal or the config")
			}
		}
	}
	// Never a flush of the whole ruleset, never a foreign table.
	for _, s := range append(vps.k.Scripts, home.k.Scripts...) {
		if strings.Contains(s, "flush") || regexp.MustCompile(`(?m)^table (ip|ip6|inet) (?:[^m]|m[^e])`).MatchString(s) {
			t.Fatalf("script touches foreign objects:\n%s", s)
		}
	}

	// Reset removes everything of meshly.
	vps.must("reset", "--yes")
	if vps.k.Table != "" || len(vps.k.Links) != 0 {
		t.Fatal("reset left kernel objects")
	}
	vps.expect(ExitNotInit, "allow", "22/tcp", "from", "home")
	if out := vps.must("status"); !strings.Contains(out, "not initialized") {
		t.Fatal(out)
	}
}

func TestExitCodes(t *testing.T) {
	n := newTestNode(t, time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC))
	n.expect(ExitUsage)
	n.expect(ExitUsage, "frobnicate")
	n.must("help")
	n.must("help", "allow")
	n.must("--help")
	if out := n.must("version", "--short"); strings.TrimSpace(out) == "" {
		t.Fatal("empty version")
	}
	n.expect(ExitUsage, "logs", "-n", "-1")
	n.expect(ExitUsage, "logs", "-n", "0")
	n.expect(ExitUsage, "init")
	n.expect(ExitUsage, "init", "homelab", "--name", "Bad_Name")
	n.expect(ExitUsage, "init", "homelab", "--name", "vps", "--cidr", "8.8.8.0/24")
	n.expect(ExitUsage, "init", "homelab", "--name", "vps", "--endpoint", "example.com:51820")
	n.expect(ExitUsage, "init", "homelab", "--name", "vps", "--listen-port", "70000")
	n.expect(ExitUsage, "join", "--name", "home", "--listen-port", "70000")
	n.expect(ExitUsage, "join", "--name", "Bad_Name")
	n.expect(ExitUsage, "join", "--keepalive", "-1")
	n.expect(ExitNotInit, "allow", "22/tcp", "from", "home")
	n.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820", "--dry-run")
	if _, err := os.Stat(n.app.Paths.ConfigFile()); err == nil {
		t.Fatal("dry-run init saved a configuration")
	}
	n.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820")
	n.expect(ExitConflict, "init", "other", "--name", "vps")

	// Flags after positional arguments.
	n.must("set", "mtu", "1400", "--dry-run")

	// Not root.
	n.app.Euid = 1000
	n.expect(ExitPreflight, "start")
	n.app.Euid = 0

	// Busy: another operation holds the lock.
	l, err := lock.Acquire(n.app.Paths.LockFile(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	n.app.LockTimeout = 100 * time.Millisecond
	n.expect(ExitBusy, "stop")
	l.Release()

	// Unsupported firewall manager: nothing changes.
	if err := os.MkdirAll(filepath.Join(n.root, "etc/ufw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.root, "etc/ufw/ufw.conf"), []byte("ENABLED=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scripts := len(n.k.Scripts)
	n.expect(ExitPreflight, "set", "mtu", "1300")
	if len(n.k.Scripts) != scripts {
		t.Fatal("refused command changed the firewall")
	}
	// ... but reducing access still works.
	n.must("stop")

	// Rolled back / safe mode exit codes.
	_ = os.Remove(filepath.Join(n.root, "etc/ufw/ufw.conf"))
	n.must("start")
	n.k.Fail("link.mtu", 1)
	n.expect(ExitRolledBack, "set", "mtu", "1300")
	n.k.FailAfterEffect("link.mtu", -1) // the change and its revert both fail
	n.expect(ExitSafeMode, "set", "mtu", "1300")
	if _, ok := n.k.Links["meshly0"]; ok {
		t.Fatal("interface present in safe mode")
	}
	n.k.FailAfterEffect("link.mtu", 0)
	n.must("start")
	if _, ok := n.k.Links["meshly0"]; !ok {
		t.Fatal("start did not leave safe mode")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Without --endpoint, init uses the only public IPv4 address on the
// interfaces with the default route; a bare IP gets the listen port.
func TestEndpointDetection(t *testing.T) {
	start := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	la := func(a, link string) model.LinkAddr { return model.LinkAddr{Addr: netip.MustParseAddr(a), Link: link} }
	public := []model.LinkAddr{la("10.0.0.5", "eth0"), la("203.0.113.10", "eth0")}
	private := []model.LinkAddr{la("10.0.0.5", "eth0")}
	node := func(routes []model.LinkAddr) *testNode {
		n := newTestNode(t, start)
		n.k.DefaultRoute = routes
		return n
	}
	endpoint := func(n *testNode) string {
		t.Helper()
		cfg, err := n.app.Paths.LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		return endpointArg(cfg.Self.Endpoint) + fmt.Sprintf(" listen %d", cfg.Self.ListenPort)
	}
	initVPS := func(routes []model.LinkAddr, args ...string) (*testNode, string) {
		t.Helper()
		n := node(routes)
		return n, n.must(append([]string{"init", "homelab", "--name", "vps"}, args...)...)
	}

	for _, tt := range []struct {
		routes []model.LinkAddr
		args   []string
		want   string
		out    string
	}{
		{public, nil, "203.0.113.10:51820 listen 51820", "203.0.113.10:51820, detected on eth0"},
		{public, []string{"--endpoint", "auto", "--listen-port", "4000"}, "203.0.113.10:4000 listen 4000", "detected on eth0"},
		// A cloud server behind 1:1 NAT, or a home server.
		{private, nil, "none listen 51820", "no public IPv4 address"},
		{private, nil, "none listen 51820", "until this node has an endpoint, no other node can join it"},
		{nil, nil, "none listen 51820", "no public IPv4 address"},
		{append(public, la("198.51.100.20", "eth1")), nil, "none listen 51820", "198.51.100.20 on eth1, 203.0.113.10 on eth0"},
		{public, []string{"--endpoint", "none"}, "none listen 51820", "endpoint:     none (no other node can join this one until it has an endpoint: meshly set endpoint IP)"},
		{private, []string{"--endpoint", "198.51.100.7"}, "198.51.100.7:51820 listen 51820", "198.51.100.7:51820 (UDP 51820"},
		{private, []string{"--endpoint", "198.51.100.7", "--listen-port", "4000"}, "198.51.100.7:4000 listen 4000", ""},
		{private, []string{"--endpoint", "198.51.100.7:4000"}, "198.51.100.7:4000 listen 4000", ""},
	} {
		n, out := initVPS(tt.routes, tt.args...)
		if got := endpoint(n); got != tt.want || !strings.Contains(out, tt.out) {
			t.Errorf("init %v with %v: endpoint %s, want %s; output:\n%s", tt.args, tt.routes, got, tt.want, out)
		}
	}
	if out := node(public).must("init", "homelab", "--name", "vps", "--dry-run"); !strings.Contains(out, "203.0.113.10:51820, detected on eth0") {
		t.Errorf("dry-run init does not show the detected endpoint:\n%s", out)
	}

	// meshly set endpoint.
	n, _ := initVPS(private)
	if out := n.expect(ExitUsage, "set", "endpoint", "auto"); !strings.Contains(out, "no public IPv4 address") {
		t.Error(out)
	}
	n.k.DefaultRoute = public
	n.must("set", "endpoint", "auto")
	if got := endpoint(n); got != "203.0.113.10:51820 listen 51820" {
		t.Errorf("set endpoint auto: %s", got)
	}
	n.must("set", "endpoint", "198.51.100.7")
	if got := endpoint(n); got != "198.51.100.7:51820 listen 51820" {
		t.Errorf("set endpoint IP: %s", got)
	}
	n.must("set", "endpoint", "none")
	if got := endpoint(n); got != "none listen 51820" {
		t.Errorf("set endpoint none: %s", got)
	}
	n.expect(ExitUsage, "set", "endpoint", "example.com")
}

// meshly set peer-endpoint keeps the current port for a bare IP.
func TestSetPeerEndpoint(t *testing.T) {
	_, home := pair(t)
	peer := func() string {
		t.Helper()
		cfg, err := home.app.Paths.LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		return endpointArg(cfg.Peers[0].Endpoint)
	}
	home.must("set", "peer-endpoint", "vps", "198.51.100.7")
	if got := peer(); got != "198.51.100.7:51820" {
		t.Errorf("peer endpoint %s", got)
	}
	home.must("set", "peer-endpoint", "vps", "198.51.100.7:4000")
	home.must("set", "peer-endpoint", "vps", "198.51.100.8")
	if got := peer(); got != "198.51.100.8:4000" {
		t.Errorf("peer endpoint %s, want the port kept", got)
	}
	home.must("set", "peer-endpoint", "vps", "none")
	home.must("set", "peer-endpoint", "vps", "198.51.100.9")
	if got := peer(); got != "198.51.100.9:51820" {
		t.Errorf("peer endpoint %s", got)
	}
	home.expect(ExitUsage, "set", "peer-endpoint", "vps", "auto")
}

// tempKeys returns the temporary public key and the base64 secrets derived
// from an invite code.
func tempKeys(t *testing.T, code string) (tempPub string, secrets []string) {
	t.Helper()
	c, err := pairing.ParseCode(code, start)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := c.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	return sec.TempPublicKey(), []string{code, b64(sec.PrivateKey[:]), b64(sec.PresharedKey[:])}
}

func journalRecords(t *testing.T, n *testNode) []journal.Record {
	t.Helper()
	var rs []journal.Record
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, n.app.Paths.JournalFile())), "\n") {
		var r journal.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		rs = append(rs, r)
	}
	return rs
}

func hasRecord(rs []journal.Record, event, op, detailPrefix string) bool {
	return slices.ContainsFunc(rs, func(r journal.Record) bool {
		return r.Event == event && r.Op == op && strings.HasPrefix(r.Detail, detailPrefix)
	})
}

func (n *testNode) config() *model.Config {
	n.t.Helper()
	cfg, err := n.app.Paths.LoadConfig()
	if err != nil {
		n.t.Fatal(err)
	}
	return cfg
}

func (n *testNode) drift() []string {
	n.t.Helper()
	d, err := n.app.Engine.Drift(context.Background(), n.config())
	if err != nil {
		n.t.Fatal(err)
	}
	return d
}

func (n *testNode) device() *wg.Device {
	n.t.Helper()
	d, err := n.k.WGOps().Observe("meshly0")
	if err != nil || d == nil {
		n.t.Fatalf("no WireGuard device meshly0 (%v)", err)
	}
	return d
}

func (n *testNode) lastScript() string {
	if len(n.k.Scripts) == 0 {
		return ""
	}
	return n.k.Scripts[len(n.k.Scripts)-1]
}

// untouched fails unless nothing of meshly is left on n.
func (n *testNode) untouched() {
	n.t.Helper()
	if _, err := n.app.Paths.LoadConfig(); !errors.Is(err, store.ErrNotInitialized) {
		n.t.Errorf("config: %v, want none", err)
	}
	if l, _ := n.k.LinkOps().Observe("meshly0"); l.Exists {
		n.t.Error("interface meshly0 exists")
	}
	if n.k.Table != "" {
		n.t.Error("table inet meshly exists")
	}
	if n.app.Paths.KeysExist() {
		n.t.Error("wireguard.key exists")
	}
}

// armed fails unless the invite on n waits with the temporary peer.
func (n *testNode) armed(tempPub string) {
	n.t.Helper()
	if cfg := n.config(); len(cfg.Peers) != 0 {
		n.t.Errorf("vps has peers %s while the invite waits", peerNames(cfg))
	}
	if d := n.device(); len(d.Peers) != 1 || d.Peers[0].PublicKey != tempPub {
		n.t.Errorf("vps WireGuard peers %+v, want only the temporary peer", d.Peers)
	}
}

func TestPairFlow(t *testing.T) {
	vps, home, _ := newPair(t)
	inv := startInvite(t, vps)
	tempPub, secrets := tempKeys(t, inv.code)
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != 0 || !strings.Contains(out, `Joined network "homelab" as "home" (10.100.0.2).`) {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 || !strings.Contains(inv.stdout.String(), `Node "home" (10.100.0.2) joined. The invite is closed.`) {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
	// The engine's steps go to stderr; stdout has only the results.
	for _, o := range []struct{ name, stdout, stderr string }{{"join", out, errOut}, {"invite", inv.stdout.String(), inv.stderr.String()}} {
		if strings.Contains(o.stdout, "  - ") || !strings.Contains(o.stderr, "  - configure WireGuard") {
			t.Errorf("%s: the engine's steps are not on stderr only:\nstdout:\n%s\nstderr:\n%s", o.name, o.stdout, o.stderr)
		}
	}

	vcfg, hcfg := vps.config(), home.config()
	if len(vcfg.Peers) != 1 || vcfg.Peers[0].Name != "home" || vcfg.Peers[0].Address.String() != "10.100.0.2" ||
		vcfg.Peers[0].WGPublicKey != hcfg.Self.WGPublicKey {
		t.Errorf("vps peers %+v, home key %s", vcfg.Peers, hcfg.Self.WGPublicKey)
	}
	if len(hcfg.Peers) != 1 || hcfg.Peers[0].Name != "vps" || hcfg.Peers[0].WGPublicKey != vcfg.Self.WGPublicKey ||
		hcfg.Peers[0].Endpoint.String() != "203.0.113.10:51820" || hcfg.Network.ID != vcfg.Network.ID {
		t.Errorf("home config %+v", hcfg)
	}
	for _, n := range []*testNode{vps, home} {
		if d := n.drift(); len(d) != 0 {
			t.Errorf("drift: %v", d)
		}
	}
	if d := vps.device(); len(d.Peers) != 1 || d.Peers[0].PublicKey != hcfg.Self.WGPublicKey {
		t.Errorf("vps WireGuard peers %+v", d.Peers)
	}
	if d := home.device(); len(d.Peers) != 1 || d.Peers[0].PublicKey != vcfg.Self.WGPublicKey || d.PublicKey != hcfg.Self.WGPublicKey {
		t.Errorf("home WireGuard device %+v", d)
	}
	for _, k := range []string{tempPub, hcfg.Self.WGPublicKey} {
		if vps.k.PresharedKey(k) != (wgtypes.Key{}) {
			t.Error("a preshared key is left on vps")
		}
	}
	if home.k.PresharedKey(vcfg.Self.WGPublicKey) != (wgtypes.Key{}) {
		t.Error("a preshared key is left on home")
	}
	if strings.Contains(vps.lastScript(), "tcp . 51820") {
		t.Errorf("the pairing port is still allowed on vps:\n%s", vps.lastScript())
	}
	if _, err := vps.app.Paths.LoadInviteMarker(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("invite marker: %v", err)
	}
	rs := journalRecords(t, vps)
	if !hasRecord(rs, journal.EventAudit, "invite", "opened, expires ") || !hasRecord(rs, journal.EventCommit, "invite", "") ||
		!hasRecord(rs, journal.EventAudit, "invite", "closed: joined home") {
		t.Errorf("vps journal:\n%s", readFile(t, vps.app.Paths.JournalFile()))
	}

	// The code, the temporary key and the preshared key are nowhere.
	all := vps.output.String() + home.output.String()
	for _, n := range []*testNode{vps, home} {
		all += readFile(t, n.app.Paths.JournalFile()) + n.must("status", "--json")
	}
	for _, s := range secrets {
		if strings.Contains(all, s) {
			t.Fatalf("a secret of the invite code appears in output, a journal or status:\n%s", all)
		}
	}
}

func TestInviteRefusals(t *testing.T) {
	n := newTestNode(t, start)
	n.expect(ExitNotInit, "invite")
	n.expect(ExitUsage, "invite", "--ttl", "30s")
	n.expect(ExitUsage, "invite", "--ttl", "2h")
	n.expect(ExitUsage, "invite", "now")
	n.must("init", "homelab", "--name", "vps", "--endpoint", "none")
	if out := n.expect(ExitUsage, "invite"); !strings.Contains(out, "meshly set endpoint") {
		t.Errorf("invite without an endpoint:\n%s", out)
	}

	stopped := newTestNode(t, start)
	stopped.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820")
	stopped.must("stop")
	if out := stopped.expect(ExitConflict, "invite"); !strings.Contains(out, "meshly start") {
		t.Errorf("invite on a stopped link:\n%s", out)
	}

	vps, _ := pair(t)
	if out := vps.expect(ExitConflict, "invite"); !strings.Contains(out, "home") {
		t.Errorf("invite with a peer:\n%s", out)
	}
	for _, n := range []*testNode{n, stopped, vps} {
		if _, err := n.app.Paths.LoadInviteMarker(); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refused invite left a marker: %v", err)
		}
	}
}

func TestJoinCodeInput(t *testing.T) {
	vps, home, _ := newPair(t)
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)

	home.app.Stdin = strings.NewReader("")
	if out := home.expect(ExitUsage, "join", inv.code); !strings.Contains(out, "stdin") || strings.Contains(out, inv.code) {
		t.Errorf("join with the code as an argument:\n%s", out)
	}
	b := []byte(inv.code)
	b[20] = map[bool]byte{true: 'b', false: 'a'}[b[20] == 'a']
	for _, tt := range []struct {
		in   string
		code int
		want string
	}{
		{"hello", ExitInvalidCode, "damaged"},
		{string(b), ExitInvalidCode, "damaged"},
		{"m2" + inv.code[2:], ExitInvalidCode, "upgrade"},
		{strings.Repeat("a", 2000), ExitInvalidCode, "damaged"},
		{"", ExitUsage, "no invite code"},
	} {
		if code, out, errOut := joinWith(home, tt.in, "--name", "home"); code != tt.code || !strings.Contains(out+errOut, tt.want) {
			t.Errorf("join with %.20q: exit %d, want %d\n%s%s", tt.in, code, tt.code, out, errOut)
		}
	}
	home.now = vps.now.Add(16 * time.Minute)
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != ExitInvalidCode || !strings.Contains(out+errOut, "expired") {
		t.Errorf("join with an expired code: exit %d\n%s%s", code, out, errOut)
	}
	home.now = vps.now

	// Review Focus 3: without root, join stops before asking for the code.
	home.app.Euid = 1000
	in := strings.NewReader(inv.code + "\n")
	home.app.Stdin = in
	home.expect(ExitPreflight, "join", "--name", "home")
	if in.Len() != len(inv.code)+1 {
		t.Error("join read the code before checking for root")
	}
	home.app.Euid = 0

	home.untouched()
	vps.armed(tempPub)
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
}

func TestJoinUnreachable(t *testing.T) {
	vps, home, mem := newPair(t)
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	home.app.Pairing = mem.View(homeVPN, func(netip.AddrPort) error { return errors.New("udp blocked") })
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != ExitUnreachable {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	for _, s := range []string{"203.0.113.10:51820", "did not answer", "UDP port 51820", "Nothing was changed"} {
		if !strings.Contains(errOut, s) {
			t.Errorf("join output lacks %q:\n%s", s, errOut)
		}
	}
	home.untouched()
	vps.armed(tempPub)

	home.app.Pairing = mem.View(homeVPN, tunnelUp(vps, home))
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
}

// extraAddress adds an address on another interface to a fake kernel.
type extraAddress struct {
	preflight.Links
	used model.UsedPrefix
}

func (e extraAddress) UsedPrefixes(exclude string) ([]model.UsedPrefix, error) {
	u, err := e.Links.UsedPrefixes(exclude)
	return append(u, e.used), err
}

// Review Focus 4: the VPN network is taken on home.
func TestJoinPreflightConflictBeforeContact(t *testing.T) {
	vps, home, mem := newPair(t)
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	dials := 0
	up := tunnelUp(vps, home)
	home.app.Pairing = mem.View(homeVPN, func(to netip.AddrPort) error {
		dials++
		return up(to)
	})
	links := home.app.Sys.Links
	home.app.Sys.Links = extraAddress{links, model.UsedPrefix{Prefix: netip.MustParsePrefix("10.100.0.0/24"), Source: "address 10.100.0.5/24 on eth1"}}
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != ExitPreflight || !strings.Contains(errOut, "10.100.0.5/24 on eth1") {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if dials != 0 {
		t.Errorf("join contacted vps %d times before failing its preflight", dials)
	}
	home.untouched()
	vps.armed(tempPub)
	if strings.Contains(inv.stderr.String(), "did not confirm") {
		t.Errorf("vps saw a join:\n%s", inv.stderr.String())
	}

	home.app.Sys.Links = links
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
}

func TestJoinNameTaken(t *testing.T) {
	vps, home, _ := newPair(t)
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	code, out, errOut := joinWith(home, inv.code, "--name", "vps")
	if code != ExitConflict || !strings.Contains(errOut, `the name "vps" is already used`) {
		t.Fatalf("join --name vps: exit %d\n%s%s", code, out, errOut)
	}
	home.untouched()
	vps.armed(tempPub)

	home.app.Hostname = func() (string, error) { return "Home-Server.local", nil }
	if code, out, errOut := joinWith(home, inv.code); code != 0 || !strings.Contains(out, `as "home-server"`) {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
	if cfg := vps.config(); len(cfg.Peers) != 1 || cfg.Peers[0].Name != "home-server" {
		t.Errorf("vps peers: %s", peerNames(cfg))
	}
}

func TestJoinNameFromHostname(t *testing.T) {
	for in, want := range map[string]string{
		"Home-Server.local":     "home-server",
		"web_01":                "web-01",
		"db--1..x":              "db-1",
		strings.Repeat("a", 40): strings.Repeat("a", 32),
	} {
		if got, err := nodeNameFromHostname(in); got != want || err != nil {
			t.Errorf("nodeNameFromHostname(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"123", "", "---", "local"} {
		if got, err := nodeNameFromHostname(in); err == nil {
			t.Errorf("nodeNameFromHostname(%q) = %q, want an error", in, got)
		}
	}

	n := newTestNode(t, start)
	n.app.Hostname = func() (string, error) { return "123", nil }
	key, _ := wgtypes.GeneratePrivateKey()
	c, err := pairing.NewCode(netip.MustParseAddrPort("203.0.113.10:51820"), key.PublicKey().String(), netip.MustParsePrefix("10.100.0.0/24"), start.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := joinWith(n, c.String()); code != ExitUsage || !strings.Contains(errOut, "--name") {
		t.Errorf("join on host 123: exit %d\n%s%s", code, out, errOut)
	}
	n.untouched()
}

// inviteClosed checks that the invite on n, a node without peers, left
// nothing behind and that the journal ends with its closing record.
func (n *testNode) inviteClosed(detail string) {
	n.t.Helper()
	if d := n.drift(); len(d) != 0 {
		n.t.Errorf("drift after the invite: %v", d)
	}
	if d := n.device(); len(d.Peers) != 0 {
		n.t.Errorf("WireGuard peers left: %+v", d.Peers)
	}
	if strings.Contains(n.lastScript(), "tcp . 51820") {
		n.t.Error("the pairing port is still allowed")
	}
	if _, err := n.app.Paths.LoadInviteMarker(); !errors.Is(err, fs.ErrNotExist) {
		n.t.Errorf("invite marker: %v", err)
	}
	rs := journalRecords(n.t, n)
	if last := rs[len(rs)-1]; last.Event != journal.EventAudit || last.Op != "invite" || last.Detail != detail {
		n.t.Errorf("last journal record %+v, want audit %q", last, detail)
	}
}

func TestInviteCancelAndExpiry(t *testing.T) {
	vps, _, _ := newPair(t)
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	vps.armed(tempPub)
	inv.cancel()
	if code, out := inv.wait(); code != ExitDeclined || !strings.Contains(out, "cancelled") {
		t.Errorf("cancelled invite: exit %d\n%s", code, out)
	}
	vps.inviteClosed("closed: cancelled")
	if vps.k.PresharedKey(tempPub) != (wgtypes.Key{}) {
		t.Error("the preshared key is left")
	}

	inv = startInvite(t, vps, "--ttl", "5m")
	inv.expire()
	if code, out := inv.wait(); code != ExitUnreachable || !strings.Contains(out, "no node joined") {
		t.Errorf("expired invite: exit %d\n%s", code, out)
	}
	vps.inviteClosed("closed: expired")
}

// The SSH session of the invite closes: SIGHUP arrives and every write to
// the terminal fails. The invite cleans up all the same, armed or with a
// node that has yet to confirm.
func TestInviteHangUp(t *testing.T) {
	vps, home, mem := newPair(t)
	inv := startInvite(t, vps)
	inv.hangUp()
	if code, _ := inv.wait(); code != ExitDeclined {
		t.Errorf("armed invite hung up: exit %d", code)
	}
	vps.inviteClosed("closed: cancelled")

	// The undo comes from the hang-up, not from the confirmation deadline.
	vps.app.PairTimeouts = pairing.Timeouts{Connect: time.Second, Exchange: time.Second, Confirm: time.Hour}
	home.app.PairTimeouts = shortTimeouts
	inv = startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	var blocked atomic.Bool
	blocked.Store(true)
	home.app.Pairing = mem.View(homeVPN, blockReal(vps, home, tempPub, &blocked, inv.hangUp))
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != ExitRolledBack {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != ExitDeclined {
		t.Errorf("invite hung up with a node to confirm: exit %d\n%s", code, out)
	}
	if cfg := vps.config(); len(cfg.Peers) != 0 {
		t.Errorf("vps peers %s", peerNames(cfg))
	}
	if !hasRecord(journalRecords(t, vps), journal.EventCommit, "invite-undo", "") {
		t.Error("vps journal has no invite-undo")
	}
	vps.inviteClosed("closed: cancelled")
}

// The invite expires while the node that joined has yet to confirm: when
// the confirmation does not come, the undo ends the invite.
func TestInviteExpiresWhileUnconfirmed(t *testing.T) {
	vps, home, mem := newPair(t)
	vps.app.PairTimeouts, home.app.PairTimeouts = shortTimeouts, shortTimeouts
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	var blocked atomic.Bool
	blocked.Store(true)
	home.app.Pairing = mem.View(homeVPN, blockReal(vps, home, tempPub, &blocked, inv.expire))
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != ExitRolledBack {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	home.untouched()
	code, out := inv.wait()
	if code != ExitUnreachable || !strings.Contains(out, "the invite expired; the node that joined did not confirm the connection") ||
		strings.Contains(out, "no node joined") {
		t.Errorf("invite: exit %d\n%s", code, out)
	}
	vps.inviteClosed("closed: expired")
}

// blockReal makes the dials of home fail while its device uses its real key:
// the temporary tunnel works, the real one does not. hook runs on a blocked
// dial.
func blockReal(vps, home *testNode, tempPub string, blocked *atomic.Bool, hook func()) func(netip.AddrPort) error {
	up := tunnelUp(vps, home)
	return func(to netip.AddrPort) error {
		if blocked.Load() {
			if d, _ := home.k.WGOps().Observe("meshly0"); d != nil && d.PublicKey != tempPub {
				if hook != nil {
					hook()
				}
				return errors.New("blocked")
			}
		}
		return up(to)
	}
}

// shortTimeouts make a failing confirmation quick; relaxedTimeouts give a
// join that should work room on a loaded machine. The invite reads them as
// each join starts, so a test may switch between joins.
var (
	shortTimeouts   = pairing.Timeouts{Connect: time.Second, Exchange: time.Second, Confirm: 400 * time.Millisecond}
	relaxedTimeouts = pairing.Timeouts{Connect: time.Second, Exchange: time.Second, Confirm: 5 * time.Second}
)

func TestConfirmFailureRollsBackBoth(t *testing.T) {
	vps, home, mem := newPair(t)
	vps.app.PairTimeouts, home.app.PairTimeouts = shortTimeouts, shortTimeouts
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	var blocked atomic.Bool
	blocked.Store(true)
	home.app.Pairing = mem.View(homeVPN, blockReal(vps, home, tempPub, &blocked, nil))
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != ExitRolledBack || !strings.Contains(errOut, "sudo meshly join") {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	home.untouched()
	inv.waitFor(`Node "home" did not confirm the connection; its membership was undone.`)
	inv.waitFor("The code stays valid until")
	vps.armed(tempPub)
	if rs := journalRecords(t, vps); !hasRecord(rs, journal.EventCommit, "invite-undo", "") {
		t.Error("vps journal has no invite-undo")
	}
	if rs := journalRecords(t, home); !hasRecord(rs, journal.EventCommit, "join-undo", "") {
		t.Error("home journal has no join-undo")
	}

	blocked.Store(false)
	vps.app.PairTimeouts, home.app.PairTimeouts = relaxedTimeouts, relaxedTimeouts
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
}

// Review Focus 5: the SSH session of home closes (SIGHUP, which cancels like
// Ctrl+C) while it waits for the confirmation: home still rolls back.
func TestJoinCancelDuringConfirm(t *testing.T) {
	vps, home, mem := newPair(t)
	vps.app.PairTimeouts, home.app.PairTimeouts = shortTimeouts, shortTimeouts
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	var interrupt context.CancelFunc
	home.app.WaitContext = func(c context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(c)
		interrupt = cancel
		return ctx, cancel
	}
	var blocked, gone atomic.Bool
	blocked.Store(true)
	home.app.Pairing = mem.View(homeVPN, blockReal(vps, home, tempPub, &blocked, func() {
		// The SSH session closes: SIGHUP, and writes to the terminal fail.
		gone.Store(true)
		interrupt()
	}))
	var out, errOut bytes.Buffer
	home.app.Stdin = strings.NewReader(inv.code + "\n")
	home.app.Stdout, home.app.Stderr = terminal{&out, &gone}, terminal{&errOut, &gone}
	if code := home.app.Main([]string{"join", "--name", "home"}); code != ExitDeclined {
		t.Fatalf("join: exit %d\n%s%s", code, out.String(), errOut.String())
	}
	home.untouched()
	inv.waitFor(`Node "home" did not confirm`)
	inv.waitFor("The code stays valid until")
	vps.armed(tempPub)

	blocked.Store(false)
	home.app.WaitContext = nil
	vps.app.PairTimeouts, home.app.PairTimeouts = relaxedTimeouts, relaxedTimeouts
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
}

// A join that crashed with the temporary tunnel up left an interface and a
// table that belong to no saved configuration.
func TestJoinCleansLeftovers(t *testing.T) {
	vps, home, _ := newPair(t)
	inv := startInvite(t, vps)
	c, err := pairing.ParseCode(inv.code, start)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := c.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	pcfg, err := pairingConfig(c, sec, "home", "meshly0", 51820, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	pcfg.Firewall.Profile = model.ProfileNone
	if err := home.app.Paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	home.app.Stdout = io.Discard
	if err := home.app.Engine.ApplyOverlay(context.Background(), pcfg, "meshly0", joinerOverlay(c, sec)); err != nil {
		t.Fatal(err)
	}
	if l, _ := home.k.LinkOps().Observe("meshly0"); !l.Exists || home.k.Table == "" {
		t.Fatal("the simulated crash left nothing behind")
	}
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != 0 || !strings.Contains(errOut, "interrupted join") {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
	if d := home.drift(); len(d) != 0 {
		t.Errorf("drift on home: %v", d)
	}
}

// The confirmation got lost although WireGuard completed a handshake: the
// tunnel works, so home keeps its configuration and says what to check.
func TestJoinKeepsConfigAfterHandshake(t *testing.T) {
	vps, home, mem := newPair(t)
	vps.app.PairTimeouts, home.app.PairTimeouts = shortTimeouts, shortTimeouts
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	var blocked atomic.Bool
	blocked.Store(true)
	vpsKey := vps.config().Self.WGPublicKey
	home.app.Pairing = mem.View(homeVPN, blockReal(vps, home, tempPub, &blocked, func() {
		// The real tunnel is up, only the pairing exchange is lost.
		home.k.Handshake("meshly0", vpsKey, time.Now())
	}))
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != ExitError || !strings.Contains(errOut, "did not acknowledge") || !strings.Contains(errOut, "meshly status") {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if cfg := home.config(); len(cfg.Peers) != 1 || cfg.Peers[0].Name != "vps" {
		t.Errorf("home config peers: %s", peerNames(cfg))
	}
	if !home.app.Paths.KeysExist() {
		t.Error("home lost the key its configuration uses")
	}
	inv.waitFor(`Node "home" did not confirm`)
	inv.cancel()
	if code, out := inv.wait(); code != ExitDeclined {
		t.Errorf("invite: exit %d\n%s", code, out)
	}
}

// The kernel keeps the handshake of the temporary tunnel when the inviter's
// peer moves to the real tunnel: it proves nothing about the real one, so
// a join that is not confirmed still rolls back.
func TestJoinIgnoresTemporaryHandshake(t *testing.T) {
	vps, home, mem := newPair(t)
	vps.app.PairTimeouts, home.app.PairTimeouts = shortTimeouts, shortTimeouts
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	var blocked atomic.Bool
	blocked.Store(true)
	vpsKey := vps.config().Self.WGPublicKey
	gate := blockReal(vps, home, tempPub, &blocked, nil)
	home.app.Pairing = mem.View(homeVPN, func(to netip.AddrPort) error {
		if d, _ := home.k.WGOps().Observe("meshly0"); d != nil && d.PublicKey == tempPub {
			home.k.Handshake("meshly0", vpsKey, time.Now())
		}
		return gate(to)
	})
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != ExitRolledBack || !strings.Contains(errOut, "rolled back") {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	home.untouched()
	if rs := journalRecords(t, home); !hasRecord(rs, journal.EventCommit, "join-undo", "") {
		t.Error("home journal has no join-undo")
	}
	inv.waitFor(`Node "home" did not confirm the connection; its membership was undone.`)
	inv.waitFor("The code stays valid until")
	vps.armed(tempPub)
}

// A node that reaches the invite after another one joined is told the code
// was used: exit 4, and nothing changed on it.
func TestJoinCodeUsed(t *testing.T) {
	vps, home, mem := newPair(t)
	cfg := vps.config()
	c, err := pairing.NewCode(cfg.Self.Endpoint, cfg.Self.WGPublicKey, cfg.Network.CIDR, start.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	inviter, _ := c.Addresses()
	l, err := mem.View(inviter, nil).Listen(netip.AddrPortFrom(inviter, pairing.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		deadline := time.Now().Add(5 * time.Second)
		if _, err := pairing.ReadRequest(conn, deadline); err == nil {
			_ = pairing.WriteReject(conn, deadline, pairing.Reject{Reason: pairing.ReasonUsed, Message: "this invite was already used by another node"})
		}
	}()
	home.app.Pairing = mem.View(homeVPN, nil)
	code, out, errOut := joinWith(home, c.String(), "--name", "home")
	if code != ExitInvalidCode || !strings.Contains(errOut, "already used") {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	home.untouched()

	for reason, want := range map[string]int{pairing.ReasonUsed: ExitInvalidCode, pairing.ReasonNameTaken: ExitConflict, pairing.ReasonInvalid: ExitError} {
		err := refusal(context.Background(), &pairing.RejectError{Reject: pairing.Reject{Reason: reason, Message: "no"}})
		if got := codeOf(err); got != want {
			t.Errorf("refusal %s: exit %d, want %d", reason, got, want)
		}
	}
}

// A connection to the pairing port from another address than the joining
// node's, such as a local process over loopback, is closed unanswered: no
// welcome, no refusal, and the invite waits on for the node with the code.
func TestInviteIgnoresForeignSource(t *testing.T) {
	vps, home, mem := newPair(t)
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	port := netip.AddrPortFrom(vpsVPN, pairing.Port)
	stranger := testPublicKey(t)
	for _, from := range []netip.Addr{vpsVPN, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.100.0.3")} {
		for _, client := range []pairClient{helloWith("home", stranger), confirmWith(stranger)} {
			c, err := mem.View(from, nil).Dial(context.Background(), port)
			if err != nil {
				t.Fatalf("dial from %s: %v", from, err)
			}
			err = client(c, time.Now().Add(5*time.Second))
			c.Close()
			var rej *pairing.RejectError
			if err == nil || errors.As(err, &rej) {
				t.Fatalf("a request from %s was answered (%v); want the connection closed unanswered", from, err)
			}
		}
	}
	vps.armed(tempPub)

	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
	if cfg := vps.config(); len(cfg.Peers) != 1 || cfg.Peers[0].WGPublicKey != home.config().Self.WGPublicKey {
		t.Errorf("vps peers %+v, want only home", cfg.Peers)
	}
}

// testSession is an armed invite of network homelab on node vps, with no
// engine behind it: enough for the answers that change nothing.
func testSession(t *testing.T) *inviteSession {
	t.Helper()
	inviterKey := testPublicKey(t)
	cidr := netip.MustParsePrefix("10.100.0.0/24")
	code, err := pairing.NewCode(netip.MustParseAddrPort("203.0.113.10:51820"), inviterKey, cidr, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(code.Wipe)
	sec, err := code.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sec.Wipe)
	inviter, joiner := code.Addresses()
	base := &model.Config{
		Network: model.Network{Name: "homelab", CIDR: cidr},
		Self:    model.Self{Name: "vps", Address: inviter, WGPublicKey: inviterKey},
	}
	return &inviteSession{a: &App{}, ctx: context.Background(), code: code, sec: sec, joiner: joiner, base: base}
}

// commitForTest moves s to the committed state with node home of key.
func commitForTest(t *testing.T, s *inviteSession, key string) {
	m := s.base.Clone()
	m.Peers = []model.Peer{{Name: "home", Address: s.joiner, WGPublicKey: key}}
	s.member, s.timer = m, time.NewTimer(time.Hour)
	t.Cleanup(s.stopTimer)
}

func testPublicKey(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

// A client of the pairing port: it sends its request and returns the
// inviter's verdict.
type pairClient func(c net.Conn, deadline time.Time) error

func confirmWith(key string) pairClient {
	return func(c net.Conn, deadline time.Time) error {
		return pairing.SendConfirm(c, deadline, pairing.Confirm{WGPublicKey: key})
	}
}

func helloWith(name, key string) pairClient {
	return func(c net.Conn, deadline time.Time) error {
		_, err := pairing.RequestJoin(c, deadline, pairing.Hello{Protocol: pairing.Protocol, Name: name, WGPublicKey: key})
		return err
	}
}

// pending runs client against one end of a pipe and returns the other end
// with the request read from it, the way pairServer queues it.
func pending(t *testing.T, client pairClient) (inbound, <-chan error) {
	t.Helper()
	c, sc := net.Pipe()
	verdict := make(chan error, 1)
	go func() {
		defer c.Close()
		verdict <- client(c, time.Now().Add(5*time.Second))
	}()
	req, err := pairing.ReadRequest(sc, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return inbound{conn: sc, req: req}, verdict
}

func refused(err error) string {
	var rej *pairing.RejectError
	if errors.As(err, &rej) {
		return rej.Reject.Reason
	}
	return fmt.Sprintf("not refused (%v)", err)
}

// The invite's answers, state by state.
func TestInviteSessionAnswers(t *testing.T) {
	s := testSession(t)
	home, other := testPublicKey(t), testPublicKey(t)
	ask := func(client pairClient) (bool, error) {
		t.Helper()
		in, verdict := pending(t, client)
		defer in.conn.Close()
		confirmed, err := s.answer(in.conn, in.req)
		if err != nil {
			t.Fatal(err)
		}
		return confirmed, <-verdict
	}

	// Armed: nobody joined, so there is nothing to confirm.
	if ok, err := ask(confirmWith(home)); ok || refused(err) != pairing.ReasonInvalid {
		t.Errorf("confirm while armed: %v, %v", ok, err)
	}
	if ok, err := ask(helloWith("vps", home)); ok || refused(err) != pairing.ReasonNameTaken {
		t.Errorf("hello with the inviter's name: %v, %v", ok, err)
	}
	for _, key := range []string{s.base.Self.WGPublicKey, s.sec.TempPublicKey()} {
		if ok, err := ask(helloWith("home", key)); ok || refused(err) != pairing.ReasonInvalid {
			t.Errorf("hello with a key of the invite: %v, %v", ok, err)
		}
	}
	if s.member != nil {
		t.Fatal("a refused hello committed the invite")
	}

	// Committed: the invite is used, and only the node that joined confirms.
	commitForTest(t, s, home)
	if ok, err := ask(helloWith("laptop", other)); ok || refused(err) != pairing.ReasonUsed {
		t.Errorf("hello while committed: %v, %v", ok, err)
	}
	if ok, err := ask(confirmWith(other)); ok || refused(err) != pairing.ReasonInvalid {
		t.Errorf("confirm with another key: %v, %v", ok, err)
	}
	if s.member == nil || s.timer == nil {
		t.Fatal("a wrong confirmation ended the wait for the right one")
	}
	if ok, err := ask(confirmWith(home)); !ok || err != nil {
		t.Errorf("confirm of the node that joined: %v, %v", ok, err)
	}
}

// The confirmation deadline and a confirmation arrive together: what was
// already read is served before the undo, and the confirmation counts.
func TestInviteConfirmAtDeadline(t *testing.T) {
	s := testSession(t)
	home, other := testPublicKey(t), testPublicKey(t)
	commitForTest(t, s, home)
	srv := &pairServer{requests: make(chan inbound, 2), conns: map[net.Conn]struct{}{}}
	if ok, err := s.servePending(srv); ok || err != nil {
		t.Fatalf("nothing pending: %v, %v", ok, err)
	}
	wrongIn, wrong := pending(t, confirmWith(other))
	rightIn, right := pending(t, confirmWith(home))
	srv.requests <- wrongIn
	srv.requests <- rightIn
	if ok, err := s.servePending(srv); !ok || err != nil {
		t.Fatalf("servePending: %v, %v; want the confirmation", ok, err)
	}
	if err := <-wrong; refused(err) != pairing.ReasonInvalid {
		t.Errorf("confirm with another key: %v", err)
	}
	if err := <-right; err != nil {
		t.Errorf("confirm of the node that joined: %v", err)
	}
}

// Ctrl+C, SIGTERM and the hang-up of the terminal end the waiting phases of
// invite and join; a SIGHUP ignored at start, as under nohup, stays ignored.
func TestInterruptibleHangUp(t *testing.T) {
	if signal.Ignored(syscall.SIGHUP) {
		t.Skip("SIGHUP is ignored where the test runs")
	}
	ctx, stop := interruptible(context.Background())
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP did not end the wait")
	}
	stop()

	signal.Ignore(syscall.SIGHUP)
	defer signal.Reset(syscall.SIGHUP)
	ctx, stop = interruptible(context.Background())
	defer stop()
	if !signal.Ignored(syscall.SIGHUP) {
		t.Fatal("waiting stopped ignoring SIGHUP")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatal("an ignored SIGHUP ended the wait")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestOpenInviteIsVisible(t *testing.T) {
	vps, _, _ := newPair(t)
	inv := startInvite(t, vps)
	vps2 := vps.sibling()

	out := vps2.expect(0, "status")
	if !strings.Contains(out, "Invite open until") || strings.Contains(out, "Drift") {
		t.Errorf("status:\n%s", out)
	}
	// The table carries the invite's temporary rules: said so, not flagged.
	if !strings.Contains(out, "table inet meshly  present, with the open invite's temporary rules\n") || strings.Contains(out, "OUTDATED") {
		t.Errorf("status firewall line:\n%s", out)
	}
	var st struct {
		Invite *struct {
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"invite"`
		Firewall struct {
			MatchesConfig bool `json:"matches_config"`
		} `json:"firewall"`
		Drift []string `json:"drift"`
	}
	js := vps2.expect(0, "status", "--json")
	if err := json.Unmarshal([]byte(js), &st); err != nil || st.Invite == nil || len(st.Drift) != 0 {
		t.Errorf("status --json: %v\n%s", err, js)
	}
	if st.Firewall.MatchesConfig {
		t.Errorf("status --json: matches_config must stay literal (false) while the invite's rules are in the table:\n%s", js)
	}
	if strings.Contains(js+out, inv.code) {
		t.Error("the invite code is shown")
	}
	_, doc, _ := vps2.run("doctor")
	if strings.Contains(doc, "✗") || strings.Contains(doc, " drift  ") || !strings.Contains(doc, "an invite is open until") {
		t.Errorf("doctor:\n%s", doc)
	}
	for _, line := range strings.Split(doc, "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "!" && strings.Contains(f[1], "firewall") {
			t.Errorf("doctor warns about the firewall while the invite is open:\n%s", doc)
		}
	}
	if out := vps2.expect(ExitBusy, "allow", "22/tcp", "from", "home"); !strings.Contains(out, "meshly invite is waiting") {
		t.Errorf("allow: %s", out)
	}
	// The check timer leaves a running invite alone, marker included.
	vps2.must("service", "check")
	if _, err := vps2.app.Paths.LoadInviteMarker(); err != nil {
		t.Errorf("invite marker of the running invite: %v", err)
	}

	inv.cancel()
	inv.wait()
	if out := vps2.expect(0, "status"); strings.Contains(out, "Invite open") {
		t.Errorf("status after cancel:\n%s", out)
	}
}

// An invite killed with SIGKILL leaves its temporary state, its marker and
// an "opened" record without a "closed" one. The next command that takes
// the lock (the check timer at the latest) closes it: marker removed, the
// end journaled, the temporary state reconciled away.
func TestLeftoverInviteClosed(t *testing.T) {
	vps, _, _ := newPair(t)
	for _, cmd := range [][]string{{"service", "check"}, {"start"}} {
		t.Run(strings.Join(cmd, " "), func(t *testing.T) {
			vps.t = t
			cfg := vps.config()
			code, err := pairing.NewCode(cfg.Self.Endpoint, cfg.Self.WGPublicKey, cfg.Network.CIDR, vps.now.Add(pairing.DefaultTTL))
			if err != nil {
				t.Fatal(err)
			}
			sec, err := code.Secrets()
			if err != nil {
				t.Fatal(err)
			}
			if err := vps.app.applyOverlay(context.Background(), cfg, inviterOverlay(code, sec, true)); err != nil {
				t.Fatal(err)
			}
			if err := vps.app.Paths.SaveInviteMarker(store.InviteMarker{ExpiresAt: code.ExpiresAt}); err != nil {
				t.Fatal(err)
			}
			vps.app.audit("invite", "", "opened, expires "+code.ExpiresAt.Format(time.RFC3339))
			if len(vps.drift()) == 0 {
				t.Fatal("no temporary state to clean up")
			}

			before := interrupted(t, vps)
			vps.must(cmd...)
			if d := vps.drift(); len(d) != 0 {
				t.Errorf("drift: %v", d)
			}
			if d := vps.device(); len(d.Peers) != 0 {
				t.Errorf("WireGuard peers left: %+v", d.Peers)
			}
			if strings.Contains(vps.lastScript(), "tcp . 51820") {
				t.Error("the pairing port is still allowed")
			}
			if _, err := vps.app.Paths.LoadInviteMarker(); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("invite marker: %v", err)
			}
			if n := interrupted(t, vps); n != before+1 {
				t.Errorf("%d new \"closed: interrupted\" records, want 1", n-before)
			}
			if out := vps.must("status"); strings.Contains(out, "Invite open") {
				t.Errorf("status:\n%s", out)
			}
		})
	}
}

// interrupted counts the journal records of invites closed as interrupted.
func interrupted(t *testing.T, n *testNode) int {
	t.Helper()
	c := 0
	for _, r := range journalRecords(t, n) {
		if r.Event == journal.EventAudit && r.Op == "invite" && r.Detail == "closed: interrupted" {
			c++
		}
	}
	return c
}
