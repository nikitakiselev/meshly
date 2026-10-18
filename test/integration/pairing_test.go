//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nikitakiselev/meshly/internal/pairing"
)

// inviteCode returns the code the last background invite on n printed.
func inviteCode(n *Node) string {
	line, _, _ := strings.Cut(string(n.ReadFile("/root/invite.out")), "\n")
	return strings.TrimSpace(line)
}

// codeSecrets returns code and the temporary private key and preshared key
// derived from it (base64), none of which may show up anywhere.
func codeSecrets(t *testing.T, code string) []string {
	t.Helper()
	c, err := pairing.ParseCode(code, time.Now())
	must(t, err)
	sec, err := c.Secrets()
	must(t, err)
	return []string{code, sec.PrivateKey.String(), sec.PresharedKey.String()}
}

// noMeshly asserts that nothing of meshly exists on n: no interface, no
// firewall table, no configuration and no keys.
func noMeshly(t *testing.T, n *Node) {
	t.Helper()
	switch {
	case n.Sh("ip link show meshly0").Code == 0:
		t.Fatalf("%s: meshly0 exists", n.Name)
	case n.Sh("nft list table inet meshly").Code == 0:
		t.Fatalf("%s: table inet meshly exists", n.Name)
	case n.Sh("test -e /etc/meshly/meshly.json").Code == 0:
		t.Fatalf("%s: a configuration was saved", n.Name)
	case n.Sh("test -e /etc/meshly/keys/wireguard.key").Code == 0:
		t.Fatalf("%s: a WireGuard key was left behind", n.Name)
	}
}

// interrupt sends sig to the running `meshly invite` on n (argv, no
// shell: a shell's own command line would match the pattern too).
func interrupt(t *testing.T, n *Node, sig string) {
	t.Helper()
	if r := n.exec(nil, "", "pkill", "-"+sig, "-f", "meshly invite"); r.Code != 0 {
		t.Fatalf("%s: pkill -%s: %s", n.Name, sig, r)
	}
}

// inviteClosed asserts that nothing of an invite is left on the vps: no
// temporary peer, no drift, no marker and the kernel state of before.
func inviteClosed(t *testing.T, vps *Node, before string) {
	t.Helper()
	if out := strings.TrimSpace(vps.MustSh("wg show meshly0 peers")); out != "" {
		t.Fatalf("peer left after the invite: %q", out)
	}
	if s := status(t, vps); len(s.Drift) != 0 {
		t.Fatalf("drift after the invite: %v", s.Drift)
	}
	if vps.Sh("test -e /run/meshly/invite.json").Code == 0 {
		t.Fatal("/run/meshly/invite.json left after the invite")
	}
	if after := vps.KernelSnapshot(); after != before {
		t.Fatalf("kernel state differs after the invite:\n--- before\n%s\n--- after\n%s", before, after)
	}
}

// One invite, one join: the nodes pair; neither the code nor a private
// key shows up anywhere.
func TestPairing(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	code := inviteCode(vps)
	if inv := string(vps.ReadFile("/root/invite.out")) + string(vps.ReadFile("/root/invite.err")); !strings.Contains(inv, `Node "home" (10.100.0.2) joined`) {
		t.Fatalf("invite does not report the join:\n%s", inv)
	}
	homePub := strings.TrimSpace(home.MustSh("wg show meshly0 public-key"))
	if peers := strings.TrimSpace(vps.MustSh("wg show meshly0 peers")); peers != homePub {
		t.Fatalf("vps peers %q, want only home's key %q", peers, homePub)
	}
	for _, n := range []*Node{vps, home} {
		if s := status(t, n); len(s.Drift) != 0 {
			t.Fatalf("%s: drift after pairing: %v", n.Name, s.Drift)
		}
	}

	// The code and the keys derived from it are never journaled.
	secrets := codeSecrets(t, code)
	for _, n := range []*Node{vps, home} {
		for _, out := range []string{n.MustSh("cat /var/lib/meshly/journal.jsonl"), n.MustMeshly("logs", "--json", "-n", "1000").Out} {
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Fatalf("%s: the invite code or a key derived from it is in the journal", n.Name)
				}
			}
		}
	}

	// A second invite, on a node that has not paired yet: the code is not
	// in any process's arguments, nor in status or doctor.
	lanhost := l.Node("lanhost")
	lanhost.MustMeshly("init", "lab2", "--name", "lanhost", "--endpoint", "192.168.77.20:51820")
	code2 := lanhost.Invite()
	ps := lanhost.MustSh("ps -eo args")
	if !strings.Contains(ps, "meshly invite") {
		t.Fatalf("invite not running:\n%s", ps)
	}
	st := lanhost.MustMeshly("status", "--json").Out
	if !strings.Contains(st, `"invite"`) {
		t.Fatalf("status --json does not show the open invite:\n%s", st)
	}
	// The temporary rules are the invite's, not an alarm.
	text := lanhost.MustMeshly("status").Out
	if !strings.Contains(text, "present, with the open invite's temporary rules") || strings.Contains(text, "OUTDATED") {
		t.Fatalf("status while the invite is open:\n%s", text)
	}
	doc := lanhost.Meshly("doctor").Out
	for _, line := range strings.Split(doc, "\n") {
		if f := strings.Fields(line); len(f) > 1 && (f[0] == "!" || f[0] == "✗") && (strings.Contains(f[1], "firewall") || f[1] == "drift") {
			t.Fatalf("doctor flags the invite's temporary state:\n%s", doc)
		}
	}
	secrets2 := codeSecrets(t, code2)
	for _, out := range []string{ps, st, text, doc, lanhost.Meshly("doctor", "--json").Out, lanhost.MustMeshly("logs", "--json", "-n", "1000").Out} {
		for _, s := range secrets2 {
			if strings.Contains(out, s) {
				t.Fatalf("the invite code or a key derived from it is in ps, status, doctor or logs:\n%s", out)
			}
		}
	}
	interrupt(t, lanhost, "INT")
	if c, inv := lanhost.InviteExit(30 * time.Second); c != 10 {
		t.Fatalf("cancelled invite: exit %d\n%s", c, inv)
	}

	// Keys: private to root, never in output or in files meant to be read.
	for _, n := range []*Node{vps, home} {
		if perm := strings.TrimSpace(n.MustSh("stat -c %a /etc/meshly/keys /etc/meshly/keys/wireguard.key | tr '\\n' ' '")); perm != "700 600" {
			t.Fatalf("%s: key permissions: %s", n.Name, perm)
		}
		priv := strings.TrimSpace(n.MustSh("cat /etc/meshly/keys/wireguard.key"))
		if priv == "" {
			t.Fatalf("%s: empty key file", n.Name)
		}
		for _, out := range []string{
			n.MustMeshly("status", "--json").Out, n.MustMeshly("status").Out,
			n.Meshly("doctor", "--json").Out, n.Meshly("doctor").Out, n.MustMeshly("logs", "--json", "-n", "1000").Out,
			n.MustSh("cat /etc/meshly/meshly.json /var/lib/meshly/*.json* /var/lib/meshly/history/* 2>/dev/null; true"),
			n.MustSh("ps -eo args"),
		} {
			if strings.Contains(out, priv) {
				t.Fatalf("%s: the private key appears in output or a readable file", n.Name)
			}
		}
	}
}

// Damaged, used and expired codes are refused; nothing changes on the
// joining node.
func TestPairingRefusals(t *testing.T) {
	l := newLab(t, distros[0])
	home, lanhost := l.Node("home"), l.Node("lanhost")
	if r := home.Join("garbage"); r.Code != 4 {
		t.Fatalf("damaged code: want exit 4: %s", r)
	}
	noMeshly(t, home)

	vps, home := l.Pair()
	code := inviteCode(vps)
	// Never as an argument: it would be in the process list and the shell
	// history.
	if r := home.Meshly("join", code); r.Code != 2 {
		t.Fatalf("code as an argument: want exit 2: %s", r)
	}
	// The invite is closed after the join: WireGuard drops the second
	// node's handshake, so it cannot tell "used" from "unreachable".
	start := time.Now()
	r := lanhost.Join(code)
	if took := time.Since(start); r.Code != 13 || took > 45*time.Second {
		t.Fatalf("used code: want exit 13 within 45s, got after %s: %s", took.Round(time.Second), r)
	}
	noMeshly(t, lanhost)

	if os.Getenv("MESHLY_IT_SHORT") != "" {
		t.Log("MESHLY_IT_SHORT set: expiry not tested")
		return
	}
	vps.MustMeshly("revoke", "home", "--yes")
	home.MustMeshly("reset", "--yes")
	before := vps.KernelSnapshot()
	code = vps.Invite("--ttl", "1m")
	time.Sleep(65 * time.Second)
	if c, inv := vps.InviteExit(10 * time.Second); c != 13 || !strings.Contains(inv, "expired") {
		t.Fatalf("expired invite: want exit 13 \"expired\", got %d:\n%s", c, inv)
	}
	inviteClosed(t, vps, before)
	// Seconds past its expiry the code is still within the joining node's
	// allowance for clock skew (pairing.ClockSkew), so the join goes out and
	// finds the invite closed.
	r = home.Join(code)
	if r.Code != 13 || !strings.Contains(r.Err, "did not answer") {
		t.Fatalf("code of a closed invite: want exit 13 \"did not answer\": %s", r)
	}
	noMeshly(t, home)
	// Past the allowance the joining node refuses the code itself. The
	// container clock cannot be moved forward, so the same code is encoded
	// again with its expiry moved back by ClockSkew.
	c, err := pairing.ParseCode(code, time.Now())
	must(t, err)
	c.ExpiresAt = c.ExpiresAt.Add(-pairing.ClockSkew)
	r = home.Join(c.String())
	if r.Code != 4 || !strings.Contains(r.Err, "expired") {
		t.Fatalf("expired code: want exit 4 \"expired\": %s", r)
	}
	noMeshly(t, home)
}

// sockets lists the listening TCP and UDP sockets of n as "proto addr:port".
func sockets(n *Node) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(n.MustSh("ss -Htuln")), "\n") {
		if f := strings.Fields(line); len(f) >= 5 {
			out = append(out, f[0]+" "+f[4])
		}
	}
	slices.Sort(out)
	return out
}

// While an invite waits, the vps exposes nothing new: the only new socket
// is the pairing listener on the VPN address, out of reach from outside.
func TestPairingNothingExposed(t *testing.T) {
	l := newLab(t, distros[0])
	vps, attacker := l.Node("vps"), l.Node("attacker")
	vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	vps.Listen("tcp", 8080) // a public service: the connect check itself works
	before := sockets(vps)
	vps.Invite()
	var added []string
	for _, s := range sockets(vps) {
		if !slices.Contains(before, s) {
			added = append(added, s)
		}
	}
	if !slices.Equal(added, []string{"tcp 10.100.0.1:51820"}) {
		t.Fatalf("new sockets during the invite: %v\nbefore: %v", added, before)
	}
	connect := func(addr string) bool {
		return attacker.Sh("/opt/it/fileserver -connect -tcp-dial "+addr+" -timeout 2s").Code == 0
	}
	if !connect("198.51.100.10:8080") {
		t.Fatal("baseline: the attacker cannot connect to a public service")
	}
	if connect("198.51.100.10:51820") {
		t.Fatal("the pairing port is reachable on the public address")
	}
	// Off the tunnel, with a route to the VPN address through the vps: the
	// SYN reaches the vps and meshly's guard drops it.
	attacker.MustSh("ip route add 10.100.0.0/24 via 198.51.100.10")
	drops := guardDrops(t, vps)
	if connect("10.100.0.1:51820") {
		t.Fatal("the pairing port is reachable from outside the tunnel via a route to the VPN address")
	}
	if after := guardDrops(t, vps); after <= drops {
		t.Fatalf("the probe never reached the vps's guard (%d -> %d drops), so its failure proves nothing", drops, after)
	}
	// Control through the same route: an address of the vps that the guard
	// does not cover is reachable, so the guard alone keeps the pairing port
	// closed; and the pairing listener does not answer on that address.
	vps.MustSh("ip link add itdummy type dummy && ip addr add 10.100.0.200/32 dev itdummy && ip link set itdummy up")
	if !connect("10.100.0.200:8080") {
		t.Fatal("control: the route through the vps does not deliver to its local addresses")
	}
	if connect("10.100.0.200:51820") {
		t.Fatal("the pairing listener answers on another address of the vps")
	}
	vps.MustSh("ip link del itdummy")
	for _, s := range sockets(vps) {
		if strings.HasPrefix(s, "udp ") && !slices.Contains(before, s) {
			t.Fatalf("new UDP socket during the invite: %s", s)
		}
	}
	interrupt(t, vps, "INT")
	if c, inv := vps.InviteExit(30 * time.Second); c != 10 {
		t.Fatalf("cancelled invite: exit %d\n%s", c, inv)
	}
}

var guardRe = regexp.MustCompile(`counter packets (\d+) bytes \d+ drop comment "vpn address reachable only through the vpn"`)

// guardDrops returns the packets meshly's guard dropped because they came
// for the VPN address from outside the tunnel.
func guardDrops(t *testing.T, n *Node) int {
	t.Helper()
	out := n.MustSh("nft list chain inet meshly guard_pre")
	m := guardRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("%s: no guard counter in:\n%s", n.Name, out)
	}
	v, err := strconv.Atoi(m[1])
	must(t, err)
	return v
}

// UDP to the WireGuard port is blocked: join says so, changes nothing and
// the same code works once the path is open.
func TestPairingUDPBlocked(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home, gw := l.Node("vps"), l.Node("home"), l.Node("natgw")
	vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	code := vps.Invite()
	gw.MustSh("nft insert rule ip filter forward_nat udp dport 51820 drop")
	start := time.Now()
	r := home.Join(code)
	took := time.Since(start)
	if r.Code != 13 || took > 45*time.Second {
		t.Fatalf("blocked UDP: want exit 13 within 45s, got after %s: %s", took.Round(time.Second), r)
	}
	for _, want := range []string{"did not answer", "UDP port 51820", "Nothing was changed on this node."} {
		if !strings.Contains(r.Err, want) {
			t.Fatalf("blocked UDP: stderr misses %q: %s", want, r)
		}
	}
	noMeshly(t, home)
	gw.MustSh(`nft delete rule ip filter forward_nat handle $(nft -a list chain ip filter forward_nat | awk '/udp dport 51820 drop/{print $NF}')`)
	if r := home.Join(code); r.Code != 0 {
		t.Fatalf("join after unblocking: %s\ninvite stderr:\n%s", r, vps.Sh("cat /root/invite.err").Out)
	}
	if c, inv := vps.InviteExit(30 * time.Second); c != 0 {
		t.Fatalf("invite: exit %d\n%s", c, inv)
	}
	l.WaitHandshake(home, 20*time.Second)
}

// Ctrl+C removes the invite's temporary state at once; after kill -9 the
// check (meshly-check.timer) removes it.
func TestPairingCleanup(t *testing.T) {
	l := newLab(t, distros[0])
	vps := l.Node("vps")
	vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	before := vps.KernelSnapshot()

	vps.Invite()
	if out := strings.TrimSpace(vps.MustSh("wg show meshly0 peers")); out == "" {
		t.Fatal("no temporary peer while the invite waits")
	}
	interrupt(t, vps, "INT")
	if c, inv := vps.InviteExit(30 * time.Second); c != 10 {
		t.Fatalf("Ctrl+C: want exit 10, got %d:\n%s", c, inv)
	}
	inviteClosed(t, vps, before)

	vps.Invite()
	interrupt(t, vps, "KILL")
	if c, _ := vps.InviteExit(10 * time.Second); c != 137 {
		t.Fatalf("kill -9: exit %d", c)
	}
	if out := strings.TrimSpace(vps.MustSh("wg show meshly0 peers")); out == "" {
		t.Fatal("kill -9: the temporary peer is already gone (nothing for the check to do)")
	}
	if vps.Sh("test -e /run/meshly/invite.json").Code != 0 {
		t.Fatal("kill -9: no marker left (nothing for the check to close)")
	}
	vps.MustMeshly("service", "check")
	if out := strings.TrimSpace(vps.MustSh("wg show meshly0 peers")); out != "" {
		t.Fatalf("temporary peer left after the check: %q", out)
	}
	if vps.Sh("test -e /run/meshly/invite.json").Code == 0 {
		t.Fatal("/run/meshly/invite.json left after the check")
	}
	type record struct{ Event, Op, Detail string }
	var logs struct{ Records []record }
	must(t, json.Unmarshal([]byte(vps.MustMeshly("logs", "--json", "-n", "1000").Out), &logs))
	if !slices.Contains(logs.Records, record{"audit", "invite", "closed: interrupted"}) {
		t.Fatalf("the killed invite is not journaled as closed:\n%s", vps.MustMeshly("logs").Out)
	}
	if s := status(t, vps); len(s.Drift) != 0 {
		t.Fatalf("drift after the check: %v", s.Drift)
	}
	if after := vps.KernelSnapshot(); after != before {
		t.Fatalf("kernel state differs after the check:\n--- before\n%s\n--- after\n%s", before, after)
	}
}

// Without --endpoint, init finds the public address on the interface with
// the default route; a node behind NAT advertises none.
func TestEndpointDetected(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Node("vps"), l.Node("home")
	endpoint := func(n *Node) string {
		t.Helper()
		var s struct {
			Config struct {
				Endpoint string `json:"endpoint"`
			} `json:"config"`
		}
		r := n.MustMeshly("status", "--json")
		if err := json.Unmarshal([]byte(r.Out), &s); err != nil {
			t.Fatalf("status --json: %v\n%s", err, r.Out)
		}
		return s.Config.Endpoint
	}
	// The lab's wan is an internal Docker network without a gateway; give
	// the vps the default route a real server has.
	vps.MustSh("ip route replace default via 198.51.100.2")
	r := vps.MustMeshly("init", "homelab", "--name", "vps")
	if !strings.Contains(r.Out, "198.51.100.10:51820, detected on eth0") || endpoint(vps) != "198.51.100.10:51820" {
		t.Fatalf("vps endpoint %q, init output:\n%s", endpoint(vps), r.Out)
	}
	r = home.MustMeshly("init", "homelab", "--name", "home")
	if !strings.Contains(r.Out, "no public IPv4 address") || endpoint(home) != "" {
		t.Fatalf("home endpoint %q, init output:\n%s", endpoint(home), r.Out)
	}
}
