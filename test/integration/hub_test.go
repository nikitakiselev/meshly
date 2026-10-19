//go:build integration

package integration

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A third node joins through the vps while home stays connected: office,
// behind the same NAT as home. Each node reaches on the vps only what the vps
// allows it, the nodes that joined cannot reach each other, not even when
// root on one of them sends packets for the other through the vps, and
// revoking one node leaves the other connected.
func TestHubAndSpokes(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	office := l.Node("lanhost")
	vps.Listen("tcp", 9100)
	vps.Listen("tcp", 9108)
	vps.MustMeshly("allow", "9100/tcp", "from", "home")
	if !home.Probe("tcp", "10.100.0.1", 9100) {
		t.Fatal("baseline: home does not reach 9100/tcp on the vps")
	}

	code := vps.Invite()
	if !home.Probe("tcp", "10.100.0.1", 9100) {
		t.Fatal("home lost 9100/tcp on the vps while the invite waits")
	}
	if r := office.Join(code, "--name", "office"); r.Code != 0 || !strings.Contains(r.Out, `Joined network "homelab" as "office" (10.100.0.3).`) {
		t.Fatalf("office: meshly join: %s\ninvite stderr so far:\n%s", r, vps.Sh("cat /root/invite.err").Out)
	}
	if c, inv := vps.InviteExit(30 * time.Second); c != 0 {
		t.Fatalf("vps: meshly invite: exit %d\n%s", c, inv)
	}
	l.WaitHandshake(office, 20*time.Second)
	vps.MustMeshly("allow", "9108/tcp", "from", "office")

	// Rules are per peer.
	for _, c := range []struct {
		from *Node
		port int
		want bool
	}{{home, 9100, true}, {home, 9108, false}, {office, 9108, true}, {office, 9100, false}} {
		if got := c.from.Probe("tcp", "10.100.0.1", c.port); got != c.want {
			t.Errorf("%s reaches %d/tcp on the vps: %v, want %v", c.from.Name, c.port, got, c.want)
		}
	}
	if r := vps.MustMeshly("nodes"); !strings.Contains(r.Out, "home ") || !strings.Contains(r.Out, "office ") ||
		strings.Count(r.Out, "online, last seen") != 2 {
		t.Fatalf("meshly nodes on the vps does not show home and office online:\n%s", r.Out)
	}

	// The nodes that joined know only the vps. A packet for the other one
	// goes into the tunnel interface, where meshly drops it, and never out
	// through the LAN unencrypted.
	home.Listen("tcp", 7000)
	office.Listen("tcp", 7000)
	notPeer := notPeerDrops(t, office)
	if home.Probe("tcp", "10.100.0.3", 7000) || office.Probe("tcp", "10.100.0.2", 7000) {
		t.Fatal("the nodes that joined reach each other")
	}
	if after := notPeerDrops(t, office); after <= notPeer {
		t.Fatalf("office's packets for home did not go into meshly0 (%d -> %d drops)", notPeer, after)
	}
	// Root on home makes the tunnel to the vps carry packets for office, and
	// the vps forwards IPv4: the vps drops them before routing.
	vpsKey := strings.TrimSpace(vps.MustSh("wg show meshly0 public-key"))
	home.MustSh(fmt.Sprintf(`nft add element inet meshly peers { 10.100.0.3 }
wg set meshly0 peer %s allowed-ips 10.100.0.1/32,10.100.0.3/32
ip route replace 10.100.0.3/32 dev meshly0 src 10.100.0.2`, vpsKey))
	vps.MustSh("sysctl -qw net.ipv4.ip_forward=1")
	before := drops(t, vps, "from_vpn", "only the local vpn address")
	if home.Probe("tcp", "10.100.0.3", 7000) {
		t.Fatal("home reaches office through the vps")
	}
	if after := drops(t, vps, "from_vpn", "only the local vpn address"); after <= before {
		t.Fatalf("home's packets for office never reached the vps's guard (%d -> %d drops), so the failed probe proves nothing", before, after)
	}
	if hits := office.Sh("cat /tmp/hits-tcp-7000 2>/dev/null").Out; hits != "" {
		t.Fatalf("office got connections:\n%s", hits)
	}
	home.MustMeshly("start") // repair what root changed

	// Revoking office closes its access and leaves home connected.
	vps.MustMeshly("revoke", "office", "--yes")
	if office.Probe("tcp", "10.100.0.1", 9108) {
		t.Error("office reaches 9108/tcp on the vps after the revoke")
	}
	if !home.Probe("tcp", "10.100.0.1", 9100) {
		t.Error("home lost 9100/tcp on the vps when office was revoked")
	}
}

// notPeerDrops returns the packets n dropped on their way into the tunnel
// because their destination is not a peer.
func notPeerDrops(t *testing.T, n *Node) int {
	t.Helper()
	out := n.MustSh("nft list chain inet meshly to_vpn")
	m := regexp.MustCompile(`ip daddr != @peers counter packets (\d+) bytes \d+ drop`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("%s: no counter for destinations that are not peers in:\n%s", n.Name, out)
	}
	v, err := strconv.Atoi(m[1])
	must(t, err)
	return v
}
