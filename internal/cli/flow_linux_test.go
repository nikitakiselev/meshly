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
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
		Pairing:  pairing.NewMemory().View(nil),
		Hostname: func() (string, error) { return "testhost", nil },
	}
	n.app.Engine = &engine.Engine{Links: n.k.LinkOps(), WG: n.k.WGOps(), FW: n.k.NFT(), Paths: paths, LoadKeys: paths.LoadKeys, Now: clock,
		Progress: func(s string) { n.app.printf("  %s\n", s) }}
	return n
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

// newPair returns two nodes on one in-memory pairing network: vps,
// initialized with a public endpoint, and an empty home. Dials from home
// pass only through a working tunnel (see tunnelUp).
func newPair(t *testing.T) (vps, home *testNode, mem *pairing.Memory) {
	t.Helper()
	vps, home = newTestNode(t, start), newTestNode(t, start)
	mem = pairing.NewMemory()
	vps.app.Pairing = mem.View(nil)
	home.app.Pairing = mem.View(tunnelUp(vps, home))
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

// inviteRun is a `meshly invite` running in the background.
type inviteRun struct {
	t       *testing.T
	n       *testNode
	code    string       // the first line of stdout
	stdout  bytes.Buffer // stdout after the code line
	stderr  syncBuffer
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
	n.app.Stdout, n.app.Stderr = pw, &r.stderr
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
		{nil, nil, "none listen 51820", "no public IPv4 address"},
		{append(public, la("198.51.100.20", "eth1")), nil, "none listen 51820", "198.51.100.20 on eth1, 203.0.113.10 on eth0"},
		{public, []string{"--endpoint", "none"}, "none listen 51820", "endpoint:     none (the joining node"},
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
	home.app.Pairing = mem.View(func(netip.AddrPort) error { return errors.New("udp blocked") })
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

	home.app.Pairing = mem.View(tunnelUp(vps, home))
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
	home.app.Pairing = mem.View(func(to netip.AddrPort) error {
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

func TestInviteCancelAndExpiry(t *testing.T) {
	vps, _, _ := newPair(t)
	closed := func(detail string) {
		t.Helper()
		if d := vps.drift(); len(d) != 0 {
			t.Errorf("drift after the invite: %v", d)
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
		rs := journalRecords(t, vps)
		if last := rs[len(rs)-1]; last.Event != journal.EventAudit || last.Op != "invite" || last.Detail != detail {
			t.Errorf("last journal record %+v, want audit %q", last, detail)
		}
	}

	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	vps.armed(tempPub)
	inv.cancel()
	if code, out := inv.wait(); code != ExitDeclined || !strings.Contains(out, "cancelled") {
		t.Errorf("cancelled invite: exit %d\n%s", code, out)
	}
	closed("closed: cancelled")
	if vps.k.PresharedKey(tempPub) != (wgtypes.Key{}) {
		t.Error("the preshared key is left")
	}

	inv = startInvite(t, vps, "--ttl", "5m")
	inv.expire()
	if code, out := inv.wait(); code != ExitUnreachable || !strings.Contains(out, "expired") {
		t.Errorf("expired invite: exit %d\n%s", code, out)
	}
	closed("closed: expired")
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

var shortTimeouts = pairing.Timeouts{Connect: time.Second, Exchange: time.Second, Confirm: 400 * time.Millisecond}

func TestConfirmFailureRollsBackBoth(t *testing.T) {
	vps, home, mem := newPair(t)
	vps.app.PairTimeouts, home.app.PairTimeouts = shortTimeouts, shortTimeouts
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	var blocked atomic.Bool
	blocked.Store(true)
	home.app.Pairing = mem.View(blockReal(vps, home, tempPub, &blocked, nil))
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
	if code, out, errOut := joinWith(home, inv.code, "--name", "home"); code != 0 {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
}

// Review Focus 5: Ctrl+C on home while it waits for the confirmation.
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
	var blocked atomic.Bool
	blocked.Store(true)
	home.app.Pairing = mem.View(blockReal(vps, home, tempPub, &blocked, func() { interrupt() }))
	code, out, errOut := joinWith(home, inv.code, "--name", "home")
	if code != ExitDeclined {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	home.untouched()
	inv.waitFor(`Node "home" did not confirm`)
	inv.waitFor("The code stays valid until")
	vps.armed(tempPub)

	blocked.Store(false)
	home.app.WaitContext = nil
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
	home.app.Pairing = mem.View(blockReal(vps, home, tempPub, &blocked, func() {
		// Only this goroutine uses home's fake kernel now.
		for i := range home.k.Devs["meshly0"].Peers {
			home.k.Devs["meshly0"].Peers[i].LastHandshake = time.Now()
		}
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
