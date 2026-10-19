//go:build linux

package cli

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/nikitakiselev/meshly/internal/diag"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/pairing"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// officeVPN is the address of the third node: the first one free after vps
// and home.
var officeVPN = netip.MustParseAddr("10.100.0.3")

// trio returns vps with the peers home and office, each joined through an
// invite on vps.
func trio(t *testing.T) (vps, home, office *testNode, mem *pairing.Memory) {
	t.Helper()
	vps, home, mem = newPair(t)
	join(t, vps, home, "home")
	office = newTestNode(t, start)
	office.app.Pairing = mem.View(officeVPN, tunnelUp(vps, office))
	join(t, vps, office, "office")
	return vps, home, office, mem
}

// join adds n to the network of vps as name, through an invite on vps.
func join(t *testing.T, vps, n *testNode, name string) {
	t.Helper()
	inv := startInvite(t, vps)
	if code, out, errOut := joinWith(n, inv.code, "--name", name); code != 0 {
		t.Fatalf("%s: meshly join: exit %d\n%s%s", name, code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("meshly invite for %s: exit %d\n%s", name, code, out)
	}
}

// deviceKeys returns the public keys of the WireGuard peers of n, sorted.
func deviceKeys(n *testNode) []string {
	var keys []string
	for _, p := range n.device().Peers {
		keys = append(keys, p.PublicKey)
	}
	slices.Sort(keys)
	return keys
}

func sortedKeys(keys ...string) []string {
	slices.Sort(keys)
	return keys
}

// A node with a peer invites one more: the new node gets the next free
// address and knows only the inviting node; the peer that was there keeps
// working all along.
func TestInviteAddsNode(t *testing.T) {
	vps, home, mem := newPair(t)
	join(t, vps, home, "home")
	homeKey := home.config().Self.WGPublicKey
	office := newTestNode(t, start)
	office.app.Pairing = mem.View(officeVPN, tunnelUp(vps, office))

	inv := startInvite(t, vps)
	c, err := pairing.ParseCode(inv.code, start)
	if err != nil {
		t.Fatal(err)
	}
	if _, joiner := c.Addresses(); joiner != officeVPN {
		t.Fatalf("the code gives the joining node %s, want %s", joiner, officeVPN)
	}
	tempPub, _ := tempKeys(t, inv.code)
	if got := deviceKeys(vps); !slices.Equal(got, sortedKeys(homeKey, tempPub)) {
		t.Errorf("vps WireGuard peers while the invite waits: %v, want home and the temporary peer", got)
	}

	code, out, errOut := joinWith(office, inv.code, "--name", "office")
	if code != 0 || !strings.Contains(out, `Joined network "homelab" as "office" (10.100.0.3).`) ||
		!strings.Contains(out, "peer:  vps 10.100.0.1 via 203.0.113.10:51820") {
		t.Fatalf("join: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 || !strings.Contains(inv.stdout.String(), `Node "office" (10.100.0.3) joined. The invite is closed.`) {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}

	vcfg, ocfg := vps.config(), office.config()
	officeKey := ocfg.Self.WGPublicKey
	want := []model.Peer{
		{Name: "home", Address: homeVPN, WGPublicKey: homeKey},
		{Name: "office", Address: officeVPN, WGPublicKey: officeKey},
	}
	if len(vcfg.Peers) != len(want) {
		t.Fatalf("vps peers: %s, want home and office", peerNames(vcfg))
	}
	for i, w := range want {
		if p := vcfg.Peers[i]; p.Name != w.Name || p.Address != w.Address || p.WGPublicKey != w.WGPublicKey {
			t.Errorf("vps peers[%d] = %s %s %s, want %s %s %s", i, p.Name, p.Address, p.WGPublicKey, w.Name, w.Address, w.WGPublicKey)
		}
	}
	if len(ocfg.Peers) != 1 || ocfg.Peers[0].Name != "vps" || ocfg.Self.Address != officeVPN || ocfg.Network.ID != vcfg.Network.ID {
		t.Errorf("office: self %s, peers %s, network %s; want 10.100.0.3 with only vps in %s", ocfg.Self.Address, peerNames(ocfg), ocfg.Network.ID, vcfg.Network.ID)
	}
	if hcfg := home.config(); len(hcfg.Peers) != 1 || hcfg.Peers[0].Name != "vps" {
		t.Errorf("home peers: %s, want only vps", peerNames(hcfg))
	}
	if got := deviceKeys(vps); !slices.Equal(got, sortedKeys(homeKey, officeKey)) {
		t.Errorf("vps WireGuard peers %v, want home and office", got)
	}
	if got := deviceKeys(office); !slices.Equal(got, []string{vcfg.Self.WGPublicKey}) {
		t.Errorf("office WireGuard peers %v, want only vps", got)
	}
	for _, k := range []string{tempPub, homeKey, officeKey} {
		if vps.k.PresharedKey(k) != (wgtypes.Key{}) {
			t.Error("a preshared key is left on vps")
		}
	}
	for _, n := range []*testNode{vps, home, office} {
		if d := n.drift(); len(d) != 0 {
			t.Errorf("drift: %v", d)
		}
	}
	nodes := func(n *testNode) []string {
		var ns diag.Nodes
		if err := json.Unmarshal([]byte(n.must("nodes", "--json")), &ns); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, x := range ns.Nodes {
			names = append(names, x.Name+" "+x.VPNAddress)
		}
		return names
	}
	if got := nodes(vps); !slices.Equal(got, []string{"vps 10.100.0.1", "home 10.100.0.2", "office 10.100.0.3"}) {
		t.Errorf("nodes on vps: %v", got)
	}
	if got := nodes(office); !slices.Equal(got, []string{"office 10.100.0.3", "vps 10.100.0.1"}) {
		t.Errorf("nodes on office: %v", got)
	}
}

// Rules are per peer: what one peer may use, another may not.
func TestRulesPerPeer(t *testing.T) {
	vps, _, _, _ := trio(t)
	vps.must("allow", "9108/tcp", "from", "office")
	script := vps.lastScript()
	if !strings.Contains(script, "10.100.0.3 . tcp . 9108") || strings.Contains(script, "10.100.0.2 . tcp . 9108") {
		t.Errorf("allow 9108/tcp from office:\n%s", script)
	}
	if !strings.Contains(script, "elements = { 10.100.0.2, 10.100.0.3 }") {
		t.Errorf("the peers set lacks home or office:\n%s", script)
	}
	if out := vps.must("rules"); !strings.Contains(out, "allow 9108/tcp from office") || strings.Contains(out, "from home") {
		t.Errorf("rules:\n%s", out)
	}
}

// Revoking one node leaves the others connected, and its address goes to
// the next node that joins.
func TestRevokeOneOfSeveral(t *testing.T) {
	vps, home, _, _ := trio(t)
	vps.must("allow", "22/tcp", "from", "home")
	vps.must("allow", "9108/tcp", "from", "office")
	vps.must("revoke", "office", "--yes")
	cfg := vps.config()
	if len(cfg.Peers) != 1 || cfg.Peers[0].Name != "home" || len(cfg.Rules) != 1 || cfg.Rules[0].Peer != "home" {
		t.Errorf("vps after revoking office: peers %s, rules %v", peerNames(cfg), cfg.Rules)
	}
	if got := deviceKeys(vps); !slices.Equal(got, []string{home.config().Self.WGPublicKey}) {
		t.Errorf("vps WireGuard peers %v, want only home", got)
	}
	if d := vps.drift(); len(d) != 0 {
		t.Errorf("drift: %v", d)
	}

	inv := startInvite(t, vps)
	c, err := pairing.ParseCode(inv.code, start)
	if err != nil {
		t.Fatal(err)
	}
	if _, joiner := c.Addresses(); joiner != officeVPN {
		t.Errorf("the next node gets %s, want the freed %s", joiner, officeVPN)
	}
}

// A joining node cannot take the name of a node that is already in the
// network; the invite waits on, and the existing node keeps its place.
func TestJoinNameOfAnotherNode(t *testing.T) {
	vps, home, mem := newPair(t)
	join(t, vps, home, "home")
	homeKey := home.config().Self.WGPublicKey
	office := newTestNode(t, start)
	office.app.Pairing = mem.View(officeVPN, tunnelUp(vps, office))
	inv := startInvite(t, vps)
	tempPub, _ := tempKeys(t, inv.code)
	code, out, errOut := joinWith(office, inv.code, "--name", "home")
	if code != ExitConflict || !strings.Contains(errOut, `the name "home" is already used`) || !strings.Contains(errOut, "meshly revoke home") {
		t.Fatalf("join --name home: exit %d\n%s%s", code, out, errOut)
	}
	office.untouched()
	if got := deviceKeys(vps); !slices.Equal(got, sortedKeys(homeKey, tempPub)) {
		t.Errorf("vps WireGuard peers %v, want home and the temporary peer", got)
	}
	if code, out, errOut := joinWith(office, inv.code, "--name", "office"); code != 0 {
		t.Fatalf("join --name office: exit %d\n%s%s", code, out, errOut)
	}
	if code, out := inv.wait(); code != 0 {
		t.Fatalf("invite: exit %d\n%s", code, out)
	}
}

// Only the node that created the network invites: a node that joined it
// points to that node, also after it revoked it.
func TestInviteOnlyOnFirstNode(t *testing.T) {
	_, home := pair(t)
	home.must("set", "endpoint", "198.51.100.20")
	if out := home.expect(ExitConflict, "invite"); !strings.Contains(out, "sudo meshly invite") || !strings.Contains(out, "on vps") {
		t.Errorf("invite on a node that joined:\n%s", out)
	}
	home.must("revoke", "vps", "--yes")
	if out := home.expect(ExitConflict, "invite"); !strings.Contains(out, "meshly reset") || !strings.Contains(out, "meshly init") {
		t.Errorf("invite on a node that joined and revoked the first node:\n%s", out)
	}
	if _, err := home.app.Paths.LoadInviteMarker(); err == nil {
		t.Error("a refused invite left a marker")
	}
}

// A network without a free address refuses the invite before printing a
// code.
func TestInviteNetworkFull(t *testing.T) {
	vps, home := newTestNode(t, start), newTestNode(t, start)
	mem := pairing.NewMemory()
	vps.app.Pairing = mem.View(netip.MustParseAddr("10.100.0.1"), nil)
	home.app.Pairing = mem.View(netip.MustParseAddr("10.100.0.2"), tunnelUp(vps, home))
	vps.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820", "--cidr", "10.100.0.0/30")
	join(t, vps, home, "home")
	if out := vps.expect(ExitConflict, "invite"); !strings.Contains(out, "no free address") || !strings.Contains(out, "10.100.0.0/30") {
		t.Errorf("invite in a full network:\n%s", out)
	}
	if _, err := vps.app.Paths.LoadInviteMarker(); err == nil {
		t.Error("a refused invite left a marker")
	}
}

// With several peers, a probe names the peer to probe.
func TestDoctorProbeNeedsPeer(t *testing.T) {
	vps, _, _, _ := trio(t)
	if out := vps.expect(ExitUsage, "doctor", "--probe", "22/tcp"); !strings.Contains(out, "--peer") || !strings.Contains(out, "home, office") {
		t.Errorf("doctor --probe without --peer:\n%s", out)
	}
}
