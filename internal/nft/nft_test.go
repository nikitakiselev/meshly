package nft

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nikitakiselev/meshly/internal/model"
)

var nftVersions = []string{"nft-1.0.6", "nft-1.0.9"}

func loadFixture(t testing.TB, version, name string) *Ruleset {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", version, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ParseRuleset(b)
	if err != nil {
		t.Fatalf("%s/%s: %v", version, name, err)
	}
	return rs
}

func testContext() Context {
	return Context{
		Interface: "meshly0", LocalVPN: netip.MustParseAddr("10.100.0.1"),
		Peers: []netip.Addr{netip.MustParseAddr("10.100.0.2")}, ListenPort: 51820, Mark: model.DefaultFirewallMark,
		LocalAddrs: []netip.Addr{netip.MustParseAddr("198.51.100.10")},
	}
}

func TestRenderDeterministicAndHashed(t *testing.T) {
	in := fixtureInput()
	a, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Render(in)
	if a != b {
		t.Fatal("rendering is not deterministic")
	}
	// Rule order in the input does not matter (sets are sorted).
	in2 := fixtureInput()
	slices.Reverse(in2.Allow)
	c, _ := Render(in2)
	if c.Hash != a.Hash {
		t.Fatal("hash depends on rule order")
	}
	// Any policy change changes the hash.
	for name, mutate := range map[string]func(*Input){
		"rule":   func(i *Input) { i.Allow = i.Allow[:1] },
		"peer":   func(i *Input) { i.Peers, i.Allow = nil, nil },
		"port":   func(i *Input) { i.ListenPort = 51821 },
		"mark":   func(i *Input) { i.Mark = 0x20000000 },
		"ifname": func(i *Input) { i.Interface = "wg7" },
	} {
		i := fixtureInput()
		mutate(&i)
		r, err := Render(i)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Hash == a.Hash {
			t.Fatalf("%s change does not change the hash", name)
		}
	}
	if !strings.Contains(a.Definition, MarkerPrefix+" net="+in.NetworkID+" hash="+a.Hash) {
		t.Fatal("ownership marker missing")
	}
	if !strings.HasPrefix(a.ApplyScript(), "table inet meshly\ndelete table inet meshly\n") {
		t.Fatal("apply script is not an atomic replace of the meshly table only")
	}
	for _, forbidden := range []string{"flush ruleset", "table ip ", "table inet filter", "delete table inet filter"} {
		if strings.Contains(a.ApplyScript(), forbidden) {
			t.Fatalf("apply script touches foreign objects: %q", forbidden)
		}
	}
}

func TestRenderPolicyShape(t *testing.T) {
	r, err := Render(fixtureInput())
	if err != nil {
		t.Fatal(err)
	}
	d := r.Definition
	for _, want := range []string{
		`counter drop comment "default deny"`,
		`iifname "meshly0" counter drop comment "no forwarding from the vpn"`,
		`oifname "meshly0" counter drop comment "no forwarding into the vpn"`,
		`ct status dnat counter drop`,
		`meta nfproto != ipv4 counter drop comment "no ipv6 inside the vpn"`,
		`10.100.0.2 . tcp . 22`,
		`10.100.0.2 . udp . 53`,
		`type filter hook prerouting priority -180`,
		`type filter hook forward priority -300`,
	} {
		if !strings.Contains(d, want) {
			t.Errorf("rendered table lacks %q", want)
		}
	}
	// Allow decisions are taken per packet from the sets (no "ct state
	// established accept" shortcut for inbound flows), so deny also cuts
	// existing connections.
	from := d[strings.Index(d, "chain from_vpn"):]
	from = from[:strings.Index(from, "}")]
	if strings.Contains(from, "ct state established accept") || strings.Contains(from, "ct state established,related accept") {
		t.Fatal("inbound chain accepts established flows without consulting the allow set")
	}
	// Lockdown: no peers and no rules.
	cfg := &model.Config{Network: model.Network{ID: fixtureInput().NetworkID, CIDR: fixtureInput().CIDR},
		Self:      model.Self{Address: fixtureInput().LocalAddr, ListenPort: 51820},
		Interface: model.Interface{Name: "meshly0"}, Firewall: model.Firewall{Mark: model.DefaultFirewallMark},
		Peers: []model.Peer{{Name: "home", Address: netip.MustParseAddr("10.100.0.2")}},
		Rules: []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 22}}}
	lock, err := Render(InputFromConfig(cfg, true))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(lock.Definition, "elements") {
		t.Fatalf("lockdown table admits peers or services:\n%s", lock.Definition)
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	for name, mutate := range map[string]func(*Input){
		"interface with quote": func(i *Input) { i.Interface = `x"; flush ruleset; "` },
		"network id":           func(i *Input) { i.NetworkID = "abc" },
		"two-bit mark":         func(i *Input) { i.Mark = 0x30000000 },
		"peer outside cidr":    func(i *Input) { i.Peers = []netip.Addr{netip.MustParseAddr("192.168.1.1")} },
		"ipv6 local":           func(i *Input) { i.LocalAddr = netip.MustParseAddr("fd00::1") },
	} {
		i := fixtureInput()
		mutate(&i)
		if _, err := Render(i); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The table as read back from real nft (1.0.6 lacks table comments in
// JSON, hence the marker rule) must be recognised as ours, with the hash of
// what was rendered, on both versions.
func TestMarkerRoundTripRealNft(t *testing.T) {
	r, _ := Render(fixtureInput())
	for _, v := range nftVersions {
		rs := loadFixture(t, v, "meshly")
		tab := rs.Table(TableFamily, TableName)
		if tab == nil {
			t.Fatalf("%s: table not found", v)
		}
		netID, hash, ok := tab.Marker()
		if !ok || netID != fixtureInput().NetworkID || hash != r.Hash {
			t.Fatalf("%s: marker (%q, %q, %v), want hash %s", v, netID, hash, ok, r.Hash)
		}
		if tab.ContentHash() == "" || tab.ContentHash() != loadFixture(t, v, "meshly").Table(TableFamily, TableName).ContentHash() {
			t.Fatalf("%s: content hash unstable", v)
		}
		a := Analyze(rs, testContext())
		if !a.OurTablePresent || !a.OurTableOwned || len(a.Chains) != 0 {
			t.Fatalf("%s: own table not recognised or analysed as foreign: %+v", v, a)
		}
	}
}

func TestAnalyzeFixtures(t *testing.T) {
	type want struct {
		chains     map[string]string // "family table chain" -> status
		docker     bool
		ufw        bool
		firewalld  bool
		flowtables int
		netdev     int
	}
	cases := map[string]want{
		"empty":               {},
		"drop-no-integration": {chains: map[string]string{"inet filter input": "needs-integration"}},
		"drop-integrated":     {chains: map[string]string{"inet filter input": "integrated", "inet filter output": "compatible"}},
		"misplaced":           {chains: map[string]string{"inet filter input": "misplaced-integration"}},
		// Conservative: a source-range drop could hit the peer's public
		// endpoint (WireGuard transport) and "udp dport 53 reject" an
		// allowed VPN service.
		"accept-compatible": {chains: map[string]string{"inet filter input": "needs-integration"}},
		"named-set-peer":    {chains: map[string]string{"inet filter input": "needs-integration"}},
		"docker":            {chains: map[string]string{"ip nat PREROUTING": "compatible", "ip nat POSTROUTING": "compatible"}, docker: true},
		"iptables-nft-drop": {chains: map[string]string{"ip filter INPUT": "unsupported"}},
		"ufw-chains":        {chains: map[string]string{"ip filter INPUT": "unsupported"}, ufw: true},
		"firewalld":         {firewalld: true},
		"flowtable-netdev":  {flowtables: 1, netdev: 1},
	}
	for _, v := range nftVersions {
		for name, w := range cases {
			t.Run(v+"/"+name, func(t *testing.T) {
				a := Analyze(loadFixture(t, v, name), testContext())
				got := map[string]string{}
				for _, c := range a.Chains {
					got[c.Family+" "+c.Table+" "+c.Chain] = c.Status
				}
				if len(got) != len(w.chains) {
					t.Fatalf("chains %v, want %v", got, w.chains)
				}
				for k, s := range w.chains {
					if got[k] != s {
						t.Fatalf("%s: status %q, want %q (all: %v)", k, got[k], s, got)
					}
				}
				if a.DockerDetected != w.docker || a.UFWChains != w.ufw || a.FirewalldTables != w.firewalld ||
					len(a.Flowtables) != w.flowtables || len(a.NetdevChains) != w.netdev {
					t.Fatalf("flags: %+v", a)
				}
			})
		}
	}
}

// A foreign table that imitates ours without the marker is not ours.
func TestForeignTableNamedMeshly(t *testing.T) {
	js := `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"meshly","handle":1}},
{"chain":{"family":"inet","table":"meshly","name":"guard_pre","handle":1,"type":"filter","hook":"prerouting","prio":-180,"policy":"accept"}},
{"rule":{"family":"inet","table":"meshly","chain":"guard_pre","handle":2,"expr":[{"accept":null}]}}]}`
	rs, err := ParseRuleset([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	a := Analyze(rs, testContext())
	if !a.OurTablePresent || a.OurTableOwned {
		t.Fatalf("foreign table taken as ours: %+v", a)
	}
}

func FuzzParseRuleset(f *testing.F) {
	for _, v := range nftVersions {
		files, _ := filepath.Glob(filepath.Join("testdata", v, "*.json"))
		for _, p := range files {
			b, _ := os.ReadFile(p)
			f.Add(b)
		}
	}
	f.Add([]byte(`{"nftables":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, err := ParseRuleset(b)
		if err != nil {
			return
		}
		// Analysis of any parsable ruleset must not panic.
		_ = Analyze(rs, testContext())
		if tab := rs.Table(TableFamily, TableName); tab != nil {
			_, _, _ = tab.Marker()
			_ = tab.ContentHash()
		}
	})
}
