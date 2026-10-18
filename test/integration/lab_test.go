//go:build integration

// Package integration runs meshly against real kernels: every node is a
// privileged Docker container with its own network namespace, so real
// WireGuard packets cross a real NAT and real nftables rules decide. The
// developer's host network stack and firewall are never touched: the
// containers sit on internal Docker networks and all changes happen inside
// their namespaces.
//
//	make integration                        # all tests
//	MESHLY_IT_DISTROS=deb12 make integration
//	MESHLY_IT_KEEP=1 ...                    # keep containers of failed tests
//
// Topology (newLab):
//
//	     wan 198.51.100.0/24 (the "internet")
//	vps .10      attacker .66      natgw .2
//	                                 | masquerade, stateful
//	     lan 192.168.77.0/24 (home LAN behind NAT)
//	                    home .10   lanhost .20
package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const label = "meshly-it=1"

var (
	workDir  string
	goarch   string
	binPath  string // fault-injection build of the current tree
	distros  = []string{"deb12", "u2404"}
	images   = map[string]string{}
	buildMu  sync.Mutex
	releases = map[string]string{} // version -> binary path (signed test releases)
	testKey  ed25519.PrivateKey
)

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "integration setup:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func setup() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is required: %w", err)
	}
	_, file, _, _ := runtime.Caller(0)
	here := filepath.Dir(file)
	workDir = filepath.Join(here, ".work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return err
	}
	if d := os.Getenv("MESHLY_IT_DISTROS"); d != "" {
		distros = strings.Split(d, ",")
	}
	out, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		return fmt.Errorf("docker info: %w", err)
	}
	switch strings.TrimSpace(string(out)) {
	case "aarch64", "arm64":
		goarch = "arm64"
	case "x86_64", "amd64":
		goarch = "amd64"
	default:
		return fmt.Errorf("unsupported docker architecture %q", out)
	}
	cleanupStale()
	_, testKey, _ = ed25519.GenerateKey(rand.Reader)
	binPath = filepath.Join(workDir, "meshly")
	if err := buildBinary(binPath, "0.0.1", nil); err != nil {
		return err
	}
	if err := buildTool("fileserver"); err != nil {
		return err
	}
	for _, d := range append([]string{"systemd-deb12"}, distros...) {
		if err := buildImage(here, d); err != nil {
			return err
		}
	}
	return nil
}

func cleanupStale() {
	out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label="+label).Output()
	if ids := strings.Fields(string(out)); len(ids) > 0 {
		_ = exec.Command("docker", append([]string{"rm", "-f"}, ids...)...).Run()
	}
	out, _ = exec.Command("docker", "network", "ls", "-q", "--filter", "label="+label).Output()
	for _, id := range strings.Fields(string(out)) {
		_ = exec.Command("docker", "network", "rm", id).Run()
	}
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// buildBinary builds meshly with fault injection and the test release key.
func buildBinary(out, version string, extraTags []string) error {
	pub := testKey.Public().(ed25519.PublicKey)
	ld := fmt.Sprintf("-X github.com/nikitakiselev/meshly/internal/version.Version=%s -X github.com/nikitakiselev/meshly/internal/version.Commit=it -X github.com/nikitakiselev/meshly/internal/upgrade.ReleaseKey=%s",
		version, base64.StdEncoding.EncodeToString(pub))
	tags := append([]string{"meshly_faultinject"}, extraTags...)
	cmd := exec.Command("go", "build", "-tags", strings.Join(tags, ","), "-ldflags", ld, "-o", out, "./cmd/meshly")
	cmd.Dir = repoRoot()
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build meshly: %v\n%s", err, b)
	}
	return nil
}

func buildTool(name string) error {
	cmd := exec.Command("go", "build", "-o", filepath.Join(workDir, name), "./test/integration/tools/"+name)
	cmd.Dir = repoRoot()
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %v\n%s", name, err, b)
	}
	return nil
}

func buildImage(here, d string) error {
	base := map[string]string{"deb12": "debian:12", "u2404": "ubuntu:24.04"}
	file, flavor := "node.Dockerfile", d
	if strings.HasPrefix(d, "systemd-") {
		file, flavor = "systemd.Dockerfile", strings.TrimPrefix(d, "systemd-")
	}
	if base[flavor] == "" {
		return fmt.Errorf("unknown distro %q", d)
	}
	tag := "meshly-it-" + d
	images[d] = tag
	cmd := exec.Command("docker", "build", "-q", "-t", tag, "--build-arg", "BASE="+base[flavor], "-f", filepath.Join(here, "images", file), filepath.Join(here, "images"))
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker build %s: %v\n%s", tag, err, b)
	}
	return nil
}

// signedRelease builds a test release of version and returns the directory
// holding SHA256SUMS, SHA256SUMS.sig and the binary, laid out like GitHub
// release downloads (<dir>/download/v<ver>/... and <dir>/latest/download/...).
func signedRelease(t *testing.T, root, version string, latest bool) {
	t.Helper()
	buildMu.Lock()
	defer buildMu.Unlock()
	bin, ok := releases[version]
	if !ok {
		bin = filepath.Join(workDir, "meshly-"+version)
		if err := buildBinary(bin, version, nil); err != nil {
			t.Fatal(err)
		}
		releases[version] = bin
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	asset := fmt.Sprintf("meshly-%s-linux-%s", version, goarch)
	sum := sha256hex(b)
	sums := []byte(fmt.Sprintf("%s  %s\n", sum, asset))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(testKey, append([]byte("meshly-release/1\x00"), sums...)))
	dirs := []string{filepath.Join(root, "download", "v"+version)}
	if latest {
		dirs = append(dirs, filepath.Join(root, "latest", "download"))
	}
	for _, d := range dirs {
		must(t, os.MkdirAll(d, 0o755))
		must(t, os.WriteFile(filepath.Join(d, "SHA256SUMS"), sums, 0o644))
		must(t, os.WriteFile(filepath.Join(d, "SHA256SUMS.sig"), []byte(sig+"\n"), 0o644))
		must(t, os.WriteFile(filepath.Join(d, asset), b, 0o755))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- lab

type Lab struct {
	t      *testing.T
	id     string
	image  string
	nets   []string
	nodes  []*Node
	Distro string
}

type Node struct {
	lab       *Lab
	Name      string
	Container string
	IP        string // primary address
}

type Result struct {
	Out, Err string
	Code     int
}

func (r Result) String() string {
	return fmt.Sprintf("exit=%d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Out, r.Err)
}

func docker(args ...string) Result {
	cmd := exec.Command("docker", args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return Result{Out: o.String(), Err: e.String(), Code: code}
}

func (l *Lab) mustDocker(args ...string) Result {
	l.t.Helper()
	r := docker(args...)
	if r.Code != 0 {
		l.t.Fatalf("docker %s: %s", strings.Join(args, " "), r)
	}
	return r
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// newLab creates the NAT topology (wan 198.51.100.0/24, lan 192.168.77.0/24).
// Labs run one at a time; leftovers from an aborted run are removed by label.
func newLab(t *testing.T, distro string) *Lab { return newLabWith(t, distro, false) }

// newSystemdLab runs vps and home with systemd as PID 1.
func newSystemdLab(t *testing.T) *Lab { return newLabWith(t, distros[0], true) }

func newLabWith(t *testing.T, distro string, withSystemd bool) *Lab {
	t.Helper()
	l := &Lab{t: t, id: randHex(3), image: images[distro], Distro: distro}
	t.Cleanup(l.destroy)
	wan := l.network("wan", "198.51.100.0/24")
	lan := l.network("lan", "192.168.77.0/24")
	server := func(name, network, ip, gw string) {
		if !withSystemd {
			l.node(name, network, ip, gw)
			return
		}
		n := l.nodeImage(name, network, ip, "", images["systemd-deb12"], nil)
		n.WaitBoot()
		if gw != "" {
			n.MustSh("echo " + gw + " > /etc/it-gateway && systemctl start it-route.service")
		}
	}
	server("vps", wan, "198.51.100.10", "")
	gw := l.node("natgw", wan, "198.51.100.2", "")
	l.mustDocker("network", "connect", "--ip", "192.168.77.2", lan, gw.Container)
	server("home", lan, "192.168.77.10", "192.168.77.2")
	l.node("lanhost", lan, "192.168.77.20", "192.168.77.2")
	l.node("attacker", wan, "198.51.100.66", "")
	gw.MustSh(`sysctl -qw net.ipv4.ip_forward=1
W=$(ip -o -4 addr | awk '/198\.51\.100\.2\//{print $2}')
nft -f - <<EOF
table ip nat {
	chain post { type nat hook postrouting priority 100; oifname "$W" masquerade; }
}
table ip filter {
	chain forward_nat {
		type filter hook forward priority 0; policy drop;
		ct state established,related accept
		iifname != "$W" accept
	}
}
EOF`)
	return l
}

func (l *Lab) network(name, subnet string) string {
	n := "meshly-it-" + l.id + "-" + name
	l.mustDocker("network", "create", "--internal", "--label", label, "--subnet", subnet, n)
	l.nets = append(l.nets, n)
	return n
}

func (l *Lab) node(name, network, ip, gw string) *Node {
	return l.nodeImage(name, network, ip, gw, l.image, nil)
}

func (l *Lab) nodeImage(name, network, ip, gw, image string, extra []string) *Node {
	l.t.Helper()
	c := "meshly-it-" + l.id + "-" + name
	args := []string{"run", "-d", "--name", c, "--hostname", name, "--label", label, "--privileged",
		"--network", network, "--ip", ip, "-v", workDir + ":/opt/it:ro"}
	args = append(args, extra...)
	args = append(args, image)
	l.mustDocker(args...)
	n := &Node{lab: l, Name: name, Container: c, IP: ip}
	l.nodes = append(l.nodes, n)
	n.MustSh("install -m 0755 /opt/it/meshly /usr/local/bin/meshly")
	if gw != "" {
		n.MustSh("ip route replace default via " + gw)
	}
	return n
}

// Run runs a subtest whose failures (including those raised by node
// helpers) belong to the subtest.
func (l *Lab) Run(name string, f func(t *testing.T)) bool {
	parent := l.t
	return parent.Run(name, func(t *testing.T) {
		l.t = t
		defer func() { l.t = parent }()
		f(t)
	})
}

func (l *Lab) Node(name string) *Node {
	for _, n := range l.nodes {
		if n.Name == name {
			return n
		}
	}
	l.t.Fatalf("no node %s", name)
	return nil
}

func (l *Lab) destroy() {
	if l.t.Failed() && os.Getenv("MESHLY_IT_KEEP") != "" {
		l.t.Logf("keeping containers of lab %s", l.id)
		return
	}
	for _, n := range l.nodes {
		docker("rm", "-f", n.Container)
	}
	for _, n := range l.nets {
		docker("network", "rm", n)
	}
}

// ---------------------------------------------------------------- node

// WaitBoot waits until systemd finished booting the node.
func (n *Node) WaitBoot() {
	n.lab.t.Helper()
	for i := 0; i < 200; i++ {
		st := strings.TrimSpace(n.Sh("systemctl is-system-running 2>/dev/null").Out)
		if st == "running" || st == "degraded" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	n.lab.t.Fatalf("%s: systemd did not finish booting: %s", n.Name, n.Sh("systemctl --failed; systemctl list-jobs").Out)
}

// Reboot restarts the container: a fresh network namespace (no interface,
// no nftables tables) and a fresh systemd boot, with the disk kept.
func (n *Node) Reboot() {
	n.lab.t.Helper()
	n.lab.mustDocker("restart", "-t", "10", n.Container)
	n.WaitBoot()
}

func (n *Node) exec(env []string, stdin string, argv ...string) Result {
	args := []string{"exec", "-i"}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, n.Container)
	args = append(args, argv...)
	cmd := exec.Command("docker", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	return Result{Out: o.String(), Err: e.String(), Code: code}
}

// Sh runs a shell snippet (test code only; meshly itself never uses a shell).
func (n *Node) Sh(script string) Result { return n.exec(nil, "", "sh", "-c", script) }

func (n *Node) MustSh(script string) string {
	n.lab.t.Helper()
	r := n.Sh(script)
	if r.Code != 0 {
		n.lab.t.Fatalf("%s: sh %q: %s", n.Name, script, r)
	}
	return r.Out
}

// Meshly runs the meshly CLI with optional KEY=VALUE env entries first.
func (n *Node) Meshly(args ...string) Result {
	var env []string
	for len(args) > 0 && strings.Contains(args[0], "=") && !strings.HasPrefix(args[0], "-") {
		env = append(env, args[0])
		args = args[1:]
	}
	return n.exec(env, "", append([]string{"meshly"}, args...)...)
}

func (n *Node) MustMeshly(args ...string) Result {
	n.lab.t.Helper()
	r := n.Meshly(args...)
	if r.Code != 0 {
		n.lab.t.Fatalf("%s: meshly %s: %s", n.Name, strings.Join(args, " "), r)
	}
	return r
}

func (n *Node) ExpectCode(code int, args ...string) Result {
	n.lab.t.Helper()
	r := n.Meshly(args...)
	if r.Code != code {
		n.lab.t.Fatalf("%s: meshly %s: want exit %d, got %s", n.Name, strings.Join(args, " "), code, r)
	}
	return r
}

func (n *Node) ReadFile(path string) []byte {
	n.lab.t.Helper()
	r := n.exec(nil, "", "cat", path)
	if r.Code != 0 {
		n.lab.t.Fatalf("%s: cat %s: %s", n.Name, path, r)
	}
	return []byte(r.Out)
}

func (n *Node) WriteFile(path string, data []byte) {
	n.lab.t.Helper()
	r := n.exec(nil, string(data), "sh", "-c", `umask 077; cat > "$0"`, path)
	if r.Code != 0 {
		n.lab.t.Fatalf("%s: write %s: %s", n.Name, path, r)
	}
}

// Listen starts a TCP or UDP server on port that answers with a token and
// logs every connection to /tmp/hits-<proto>-<port>. It binds 0.0.0.0, so
// an accidentally opened public path would be detected too.
func (n *Node) Listen(proto string, port int) {
	n.lab.t.Helper()
	n.MustSh(fmt.Sprintf("nohup /opt/it/fileserver -%s %d -token %s-%s-%d >/dev/null 2>&1 &", proto, port, n.Name, proto, port))
	for i := 0; i < 50; i++ {
		if n.Sh(fmt.Sprintf("ss -Hln%s 'sport = :%d' | grep -q .", map[string]string{"tcp": "t", "udp": "u"}[proto], port)).Code == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	n.lab.t.Fatalf("%s: listener %s/%d did not start", n.Name, proto, port)
}

// Probe connects to addr:port and returns whether the server's token came
// back.
func (n *Node) Probe(proto, addr string, port int) bool {
	r := n.Sh(fmt.Sprintf("/opt/it/fileserver -probe -%s-dial %s:%d -timeout 2s", proto, addr, port))
	return r.Code == 0 && strings.Contains(r.Out, fmt.Sprintf("-%s-%d", proto, port))
}

func (n *Node) Ping(addr string) bool {
	return n.Sh("ping -c1 -W2 "+addr).Code == 0
}

// ---------------------------------------------------------------- meshly helpers

// Invite starts `meshly invite args...` in the background on n (stdout
// /root/invite.out, stderr /root/invite.err, exit status /root/invite.exit)
// and returns the code within 10s. The wrapper's own command line does not
// contain "meshly invite", so `pkill -f 'meshly invite'` hits meshly only.
func (n *Node) Invite(args ...string) string {
	t := n.lab.t
	t.Helper()
	n.WriteFile("/root/invite.sh", []byte(`meshly invite "$@" </dev/null >/root/invite.out 2>/root/invite.err; echo $? >/root/invite.exit`+"\n"))
	n.MustSh("rm -f /root/invite.out /root/invite.err /root/invite.exit && nohup sh /root/invite.sh " + strings.Join(args, " ") + " </dev/null >/dev/null 2>&1 &")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if line, _, ok := strings.Cut(n.Sh("cat /root/invite.out 2>/dev/null").Out, "\n"); ok {
			return strings.TrimSpace(line)
		}
		if n.Sh("test -e /root/invite.exit").Code == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: meshly invite %s printed no code:\n%s", n.Name, strings.Join(args, " "), n.Sh("cat /root/invite.exit /root/invite.out /root/invite.err 2>&1").Out)
	return ""
}

// InviteExit waits for the background invite and returns its exit status
// and stderr.
func (n *Node) InviteExit(timeout time.Duration) (int, string) {
	t := n.lab.t
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if r := n.Sh("cat /root/invite.exit 2>/dev/null"); r.Code == 0 && strings.HasSuffix(r.Out, "\n") {
			code, err := strconv.Atoi(strings.TrimSpace(r.Out))
			if err != nil {
				t.Fatalf("%s: invite exit status %q", n.Name, r.Out)
			}
			return code, n.Sh("cat /root/invite.err").Out
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: meshly invite still running after %s:\n%s", n.Name, timeout, n.Sh("cat /root/invite.out /root/invite.err").Out)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Join runs `meshly join args...` with code+"\n" on stdin.
func (n *Node) Join(code string, args ...string) Result { return n.JoinEnv(nil, code, args...) }

// JoinEnv is Join with KEY=VALUE environment entries, e.g. MESHLY_FAULT.
func (n *Node) JoinEnv(env []string, code string, args ...string) Result {
	return n.exec(env, code+"\n", append([]string{"meshly", "join"}, args...)...)
}

// Pair runs the documented two-server setup (init, invite, join) and
// returns once the WireGuard handshake is established. The code stays in
// the vps's /root/invite.out.
func (l *Lab) Pair() (vps, home *Node) {
	t := l.t
	t.Helper()
	vps, home = l.Node("vps"), l.Node("home")
	vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	code := vps.Invite()
	if r := home.Join(code, "--name", "home"); r.Code != 0 {
		t.Fatalf("home: meshly join: %s\ninvite stderr so far:\n%s", r, vps.Sh("cat /root/invite.err").Out)
	}
	if c, inv := vps.InviteExit(30 * time.Second); c != 0 {
		t.Fatalf("vps: meshly invite: exit %d\n%s", c, inv)
	}
	l.WaitHandshake(home, 20*time.Second)
	return vps, home
}

func (l *Lab) WaitHandshake(n *Node, timeout time.Duration) {
	l.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r := n.Sh("wg show meshly0 latest-handshakes")
		f := strings.Fields(r.Out)
		if len(f) == 2 && f[1] != "0" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	l.t.Fatalf("%s: no WireGuard handshake within %s", n.Name, timeout)
}

// KernelSnapshot captures the meshly-relevant kernel state for
// idempotency comparisons (counters and handles removed).
func (n *Node) KernelSnapshot() string {
	return n.MustSh(`{ nft list table inet meshly 2>/dev/null | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'; ip -d link show meshly0 2>/dev/null | grep -v -E 'link/none|^ +(RX|TX)'; ip -4 addr show dev meshly0 2>/dev/null | grep inet; ip route show proto 109; wg show meshly0 allowed-ips 2>/dev/null; wg show meshly0 endpoints 2>/dev/null | cut -f1; } | sed -E 's/valid_lft.*//'`)
}

// Foreign captures state meshly must not touch: everything but the meshly
// table and meshly's rule in the iptables chains.
func (n *Node) Foreign() string {
	return n.MustSh(`nft list ruleset | awk '/^table inet meshly/{skip=1} /^table/{if($0!~/inet meshly/)skip=0} !skip' | grep -v 'meshly:v1 integration' | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'; ip route show table main | grep -v 'proto 109'; ip -br link | grep -v meshly0 | awk '{print $1, $2}'`)
}

// IptablesFirst reports whether meshly's rule is the first rule of the
// INPUT and OUTPUT chains, for IPv4 and IPv6.
func (n *Node) IptablesFirst() bool {
	return n.iptablesFirst("iptables -S INPUT", "iptables -S OUTPUT", "ip6tables -S INPUT", "ip6tables -S OUTPUT")
}

// IptablesFirst4 is IptablesFirst for the IPv4 INPUT chain only.
func (n *Node) IptablesFirst4() bool { return n.iptablesFirst("iptables -S INPUT") }

func (n *Node) iptablesFirst(cmds ...string) bool {
	for _, c := range cmds {
		lines := strings.Split(n.Sh(c).Out, "\n")
		if len(lines) < 2 || lines[1] != `-A `+strings.Fields(c)[2]+` -m mark --mark 0x10000000/0x10000000 -m comment --comment "meshly:v1 integration" -j ACCEPT` {
			return false
		}
	}
	return true
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
