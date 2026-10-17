//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/engine/enginetest"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/lock"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/preflight"
	"github.com/nikitakiselev/meshly/internal/store"
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
	for _, f := range []string{"wireguard.key", "identity.key"} {
		b, err := os.ReadFile(filepath.Join(n.app.Paths.KeysDir, f))
		if err == nil {
			s = append(s, strings.TrimSpace(string(b)))
		}
	}
	return s
}

var fingerprintRe = regexp.MustCompile(`[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}`)

func pair(t *testing.T) (vps, home *testNode, dir string) {
	t.Helper()
	start := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	vps, home = newTestNode(t, start), newTestNode(t, start)
	dir = t.TempDir()
	out := vps.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820")
	vpsFP := fingerprintRe.FindString(out)
	vps.must("invite", "--out", filepath.Join(dir, "home.invite"))
	out = home.must("join", filepath.Join(dir, "home.invite"), "--name", "home", "--expect-fingerprint", vpsFP, "--out", filepath.Join(dir, "home.request"))
	homeFP := fingerprintRe.FindString(out[strings.Index(out, "your fingerprint"):])
	vps.now = vps.now.Add(time.Minute)
	vps.must("approve", filepath.Join(dir, "home.request"), "--expect-fingerprint", homeFP, "--out", filepath.Join(dir, "home.accept"))
	home.now = home.now.Add(2 * time.Minute)
	home.must("activate", filepath.Join(dir, "home.accept"))
	return vps, home, dir
}

func TestFlowAndSecrets(t *testing.T) {
	vps, home, dir := pair(t)

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

	// Never a secret in any output, nor in the files meant to be copied or
	// the journal.
	all := vps.output.String() + home.output.String()
	for _, f := range []string{"home.invite", "home.request", "home.accept"} {
		all += readFile(t, filepath.Join(dir, f))
	}
	all += readFile(t, vps.app.Paths.JournalFile()) + readFile(t, vps.app.Paths.ConfigFile())
	for _, n := range []*testNode{vps, home} {
		for _, s := range n.secrets() {
			if len(s) < 40 {
				t.Fatalf("unexpected key file format: %d bytes", len(s))
			}
			if strings.Contains(all, s) {
				t.Fatal("a private key appears in output, a bootstrap file, the journal or the config")
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
	n.expect(ExitUsage, "join", "home.invite", "--name", "home", "--listen-port", "70000")
	n.expect(ExitUsage, "join", "home.invite", "--name", "home", "--listen-port", "-1")
	n.expect(ExitNotInit, "allow", "22/tcp", "from", "home")
	n.expect(ExitNotInit, "invite")
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

func TestInvalidBootstrapFiles(t *testing.T) {
	vps, home, dir := pair(t)
	_ = home
	// A request replayed after approval with a different invite state, a
	// garbage file and a file of the wrong type are rejected with exit 4.
	bad := filepath.Join(dir, "garbage")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	vps.expect(ExitInvalidFile, "approve", bad, "--expect-fingerprint", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
	vps.expect(ExitInvalidFile, "approve", filepath.Join(dir, "home.invite"), "--expect-fingerprint", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
	other := newTestNode(t, vps.now)
	other.expect(ExitConflict, "activate", filepath.Join(dir, "home.accept")) // no pending join here
	other.expect(ExitInvalidFile, "join", bad, "--name", "x", "--expect-fingerprint", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
	// The invite is one-time.
	other.now = other.now.Add(time.Minute)
	out := other.must("join", filepath.Join(dir, "home.invite"), "--name", "other", "--expect-fingerprint",
		fingerprintRe.FindString(vps.must("status")), "--out", filepath.Join(dir, "other.request"))
	_ = out
	msg := vps.expect(ExitInvalidFile, "approve", filepath.Join(dir, "other.request"), "--expect-fingerprint",
		fingerprintRe.FindString(out[strings.Index(out, "your fingerprint"):]))
	if !strings.Contains(msg, "one-time") {
		t.Fatalf("reuse message: %s", msg)
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

// Under sudo the bootstrap files belong to the invoking user, so they can
// copy them to the other node without root; the invite stays private.
func TestOutputsBelongToSudoUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another user needs root")
	}
	t.Setenv("SUDO_UID", "4242")
	t.Setenv("SUDO_GID", "4343")
	_, _, dir := pair(t)
	for f, mode := range map[string]os.FileMode{"home.invite": 0o600, "home.request": 0o644, "home.accept": 0o644} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		sys := st.Sys().(*syscall.Stat_t)
		if sys.Uid != 4242 || sys.Gid != 4343 || st.Mode().Perm() != mode {
			t.Errorf("%s: owner %d:%d mode %v, want 4242:4343 %v", f, sys.Uid, sys.Gid, st.Mode().Perm(), mode)
		}
	}
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

	// join looks for an address only when the inviter has none.
	dir := t.TempDir()
	join := func(vpsRoutes, homeRoutes []model.LinkAddr, args ...string) (*testNode, int, string) {
		t.Helper()
		vps := node(vpsRoutes)
		fp := fingerprintRe.FindString(vps.must("init", "homelab", "--name", "vps"))
		inv := filepath.Join(dir, "home.invite")
		vps.must("invite", "--out", inv, "--force")
		home := node(homeRoutes)
		code, out, errOut := home.run(append([]string{"join", inv, "--name", "home", "--expect-fingerprint", fp, "--out", filepath.Join(dir, "home.request"), "--force"}, args...)...)
		return home, code, out + errOut
	}
	pending := func(n *testNode) string {
		t.Helper()
		bs, err := n.app.Paths.LoadBootstrap()
		if err != nil || bs.Pending == nil {
			t.Fatalf("no pending join: %v", err)
		}
		return endpointArg(bs.Pending.Endpoint)
	}
	homePublic := []model.LinkAddr{la("198.51.100.20", "eth0")}
	if home, code, out := join(public, homePublic); code != 0 || pending(home) != "none" {
		t.Errorf("join to a vps with an endpoint advertised %s (exit %d):\n%s", pending(home), code, out)
	}
	if home, code, out := join(public, homePublic, "--endpoint", "auto"); code != 0 || pending(home) != "198.51.100.20:51820" {
		t.Errorf("join --endpoint auto: exit %d\n%s", code, out)
	}
	if home, code, out := join(private, homePublic); code != 0 || pending(home) != "198.51.100.20:51820" || !strings.Contains(out, "your endpoint:    198.51.100.20:51820, detected on eth0") {
		t.Errorf("join to a vps without an endpoint: exit %d\n%s", code, out)
	}
	if _, code, out := join(private, private); code != ExitUsage || !strings.Contains(out, "no public IPv4 address") {
		t.Errorf("join with no endpoint on either side: exit %d\n%s", code, out)
	}
	if _, code, out := join(private, homePublic, "--endpoint", "none"); code != ExitUsage || !strings.Contains(out, "needs one: --endpoint IP") {
		t.Errorf("join --endpoint none to a vps without an endpoint: exit %d\n%s", code, out)
	}
}

// meshly set peer-endpoint keeps the current port for a bare IP.
func TestSetPeerEndpoint(t *testing.T) {
	_, home, _ := pair(t)
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
