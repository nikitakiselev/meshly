package nft

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nikitakiselev/meshly/internal/model"
)

var nftVersions = []string{"nft-1.0.6", "nft-1.0.9"}

// allVersions adds nft-1.1.3 (Debian 13, iptables 1.8.11), captured only
// with UFW and fail2ban (newerCaptures).
var allVersions = []string{"nft-1.0.6", "nft-1.0.9", "nft-1.1.3"}

var newerCaptures = map[string]bool{"ufw": true, "ufw-integrated": true, "fail2ban": true, "fail2ban-peer": true}

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
	// Nor the transport: the interface is gone in safe mode, and the mark
	// would let anything bound to the listen port pass the host firewall.
	if strings.Contains(lock.Definition, "wireguard transport") || strings.Contains(lock.Definition, "51820") {
		t.Fatalf("lockdown table marks the WireGuard transport:\n%s", lock.Definition)
	}
	if normal, _ := Render(InputFromConfig(cfg, false)); strings.Count(normal.Definition, "comment \"wireguard transport\"") != 2 {
		t.Fatalf("table does not mark the WireGuard transport:\n%s", normal.Definition)
	}
}

// chainBody returns the rules of chain name in a rendered definition.
func chainBody(t *testing.T, def, name string) string {
	t.Helper()
	i := strings.Index(def, "\tchain "+name+" {\n")
	if i < 0 {
		t.Fatalf("no chain %s in:\n%s", name, def)
	}
	body := def[i:]
	return body[:strings.Index(body, "\n\t}\n")+1]
}

var markerHash = regexp.MustCompile(`hash=[0-9a-f]+`)

// An exclusive service is reachable only from its peer through the
// interface: guard_in drops its port from anywhere else, loopback and DNAT
// included. Without exclusive entries the table renders as before
// (TestMarkerRoundTripRealNft holds that hash against real nft).
func TestRenderExclusive(t *testing.T) {
	const rule = `ip daddr 10.100.0.1 tcp dport 51820 iifname . ip saddr != { "meshly0" . 10.100.0.2 } counter drop comment "reachable only from its peer through the vpn"`
	home := netip.MustParseAddr("10.100.0.2")
	pair := AllowEntry{Peer: home, Proto: model.ProtoTCP, Port: 51820}
	in := fixtureInput()
	in.Allow = append(in.Allow, pair)
	allowOnly, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(allowOnly.Definition, "reachable only from its peer") {
		t.Fatalf("a plain allow entry is exclusive:\n%s", allowOnly.Definition)
	}
	in.Exclusive = []AllowEntry{pair}
	r, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if g := chainBody(t, r.Definition, "guard_in"); !strings.HasSuffix(g, "\t\t"+rule+"\n") {
		t.Fatalf("guard_in does not end with the exclusive rule:\n%s", g)
	}
	if n := strings.Count(r.Definition, "reachable only from its peer"); n != 1 {
		t.Fatalf("%d exclusive rules, want 1:\n%s", n, r.Definition)
	}
	if r.Hash == allowOnly.Hash {
		t.Fatal("the exclusive rule does not change the hash")
	}
	without := strings.Replace(r.Definition, "\t\t"+rule+"\n", "", 1)
	if markerHash.ReplaceAllString(without, "") != markerHash.ReplaceAllString(allowOnly.Definition, "") {
		t.Fatalf("the exclusive entry changes more than its rule:\n%s", r.Definition)
	}

	// Peers that share a port share its rule: each would drop the other.
	other := netip.MustParseAddr("10.100.0.3")
	in.Peers = append(in.Peers, other)
	in.Allow = append(in.Allow, AllowEntry{Peer: other, Proto: model.ProtoTCP, Port: 51820}, AllowEntry{Peer: other, Proto: model.ProtoUDP, Port: 53})
	in.Exclusive = []AllowEntry{in.Allow[len(in.Allow)-1], in.Allow[len(in.Allow)-2], pair}
	r, err = Render(in)
	if err != nil {
		t.Fatal(err)
	}
	g := chainBody(t, r.Definition, "guard_in")
	for _, want := range []string{
		`ip daddr 10.100.0.1 tcp dport 51820 iifname . ip saddr != { "meshly0" . 10.100.0.2, "meshly0" . 10.100.0.3 } counter drop`,
		`ip daddr 10.100.0.1 udp dport 53 iifname . ip saddr != { "meshly0" . 10.100.0.3 } counter drop`,
	} {
		if !strings.Contains(g, want) {
			t.Errorf("guard_in lacks %q:\n%s", want, g)
		}
	}
	if strings.Index(g, "tcp dport 51820") > strings.Index(g, "udp dport 53") {
		t.Errorf("exclusive rules are not sorted:\n%s", g)
	}

	for name, x := range map[string]AllowEntry{
		"not allowed": {Peer: home, Proto: model.ProtoTCP, Port: 8080},
		"ping":        {Peer: home, Proto: model.ProtoPing},
	} {
		in := fixtureInput()
		in.Exclusive = []AllowEntry{x}
		if _, err := Render(in); err == nil {
			t.Errorf("exclusive entry %s: accepted", name)
		}
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
		bans       map[string]string // "family table chain" -> "set addr,addr; ..."
		docker     bool
		ufw        bool
		fail2ban   bool
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
		// A named set of single addresses is a ban list: it may list the
		// peer, which is reported, but needs no integration.
		"named-set-peer": {chains: map[string]string{"inet filter input": "compatible"},
			bans: map[string]string{"inet filter input": "blocked 10.100.0.2"}},
		// fail2ban (sshd and recidive jails, IPv4 and IPv6 bans): only TCP,
		// and only banned addresses.
		"fail2ban": {chains: map[string]string{"inet f2b-table f2b-chain": "compatible"}, fail2ban: true},
		"fail2ban-peer": {chains: map[string]string{"inet f2b-table f2b-chain": "compatible"}, fail2ban: true,
			bans: map[string]string{"inet f2b-table f2b-chain": "addr-set-sshd 10.100.0.2"}},
		"docker": {chains: map[string]string{"ip nat PREROUTING": "compatible", "ip nat POSTROUTING": "compatible"}, docker: true},
		// iptables filter INPUT/OUTPUT: integrated by meshly itself.
		"iptables-nft-drop": {chains: map[string]string{"ip filter INPUT": "needs-integration"}},
		"ufw-chains":        {chains: map[string]string{"ip filter INPUT": "needs-integration"}, ufw: true},
		"ufw": {chains: map[string]string{"ip filter INPUT": "needs-integration", "ip filter OUTPUT": "compatible",
			"ip6 filter INPUT": "needs-integration", "ip6 filter OUTPUT": "needs-integration"}, ufw: true},
		"ufw-integrated": {chains: map[string]string{"ip filter INPUT": "integrated", "ip filter OUTPUT": "compatible",
			"ip6 filter INPUT": "integrated", "ip6 filter OUTPUT": "integrated"}, ufw: true},
		"firewalld":        {firewalld: true},
		"flowtable-netdev": {flowtables: 1, netdev: 1},
	}
	for _, v := range allVersions {
		for name, w := range cases {
			if !slices.Contains(nftVersions, v) && !newerCaptures[name] {
				continue
			}
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
				for _, c := range a.Chains {
					k := c.Family + " " + c.Table + " " + c.Chain
					if b := bansString(c.Bans); b != w.bans[k] {
						t.Fatalf("%s: bans %q, want %q", k, b, w.bans[k])
					}
				}
				for _, c := range a.Chains {
					if want := c.Table == "filter" && c.IptablesManaged; c.ByMeshly != want {
						t.Fatalf("%s %s %s: integrated by meshly %v, want %v", c.Family, c.Table, c.Chain, c.ByMeshly, want)
					}
				}
				if len(a.NeedsIntegration()) != 0 && strings.HasPrefix(name, "ufw") {
					t.Fatalf("the administrator is asked to integrate iptables chains: %+v", a.NeedsIntegration())
				}
				if a.DockerDetected != w.docker || a.UFWChains != w.ufw || a.Fail2ban != w.fail2ban || a.FirewalldTables != w.firewalld ||
					len(a.Flowtables) != w.flowtables || len(a.NetdevChains) != w.netdev {
					t.Fatalf("flags: %+v", a)
				}
			})
		}
	}
}

func bansString(bans []Ban) string {
	var out []string
	for _, b := range bans {
		var addrs []string
		for _, a := range b.Addrs {
			addrs = append(addrs, a.String())
		}
		out = append(out, b.Set+" "+strings.Join(addrs, ","))
	}
	return strings.Join(out, "; ")
}

// initContext is the context of init, invite and join: no peer yet.
func initContext() Context {
	c := testContext()
	c.Peers = nil
	c.Network = netip.MustParsePrefix("10.100.0.0/24")
	return c
}

// Until a peer is known, a ban list is checked against the VPN network.
func TestBanListsWithoutPeers(t *testing.T) {
	for _, v := range allVersions {
		a := Analyze(loadFixture(t, v, "fail2ban"), initContext())
		if len(a.Chains) != 1 || a.Chains[0].Status != "compatible" || len(a.Chains[0].Bans) != 0 {
			t.Fatalf("%s: fail2ban before pairing: %+v", v, a.Chains)
		}
		a = Analyze(loadFixture(t, v, "fail2ban-peer"), initContext())
		if c := a.Chains[0]; c.Status != "compatible" || bansString(c.Bans) != "addr-set-sshd 10.100.0.2" {
			t.Fatalf("%s: banned VPN address before pairing: %+v", v, c)
		}
	}
}

func TestBanLists(t *testing.T) {
	ruleset := func(elems, rule string) *Ruleset {
		t.Helper()
		js := `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"filter","handle":1}},` +
			`{"set":{"family":"inet","name":"s","table":"filter","type":"ipv4_addr","handle":2,"elem":[` + elems + `]}},` +
			`{"chain":{"family":"inet","table":"filter","name":"input","handle":3,"type":"filter","hook":"input","prio":0,"policy":"accept"}},` +
			`{"rule":{"family":"inet","table":"filter","chain":"input","handle":4,"expr":[` + rule + `,{"drop":null}]}}]}`
		rs, err := ParseRuleset([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
	saddr := func(op, right string) string {
		return `{"match":{"op":"` + op + `","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":` + right + `}}`
	}
	endpoint := testContext()
	endpoint.Endpoints = []netip.Addr{netip.MustParseAddr("203.0.113.20")}
	cases := []struct {
		name, elems, rule string
		ctx               Context
		status, bans      string
	}{
		{"banned endpoint", `"203.0.113.20","198.51.100.7"`, saddr("==", `"@s"`), endpoint, "compatible", "s 203.0.113.20"},
		{"endpoint not known", `"203.0.113.20","198.51.100.7"`, saddr("==", `"@s"`), testContext(), "compatible", ""},
		{"range outside the VPN", `{"prefix":{"addr":"192.0.2.0","len":24}}`, saddr("==", `"@s"`), initContext(), "compatible", ""},
		{"range over the VPN", `{"prefix":{"addr":"10.0.0.0","len":8}}`, saddr("==", `"@s"`), initContext(), "needs-integration", ""},
		{"range over the peer", `{"prefix":{"addr":"10.0.0.0","len":8}}`, saddr("==", `"@s"`), testContext(), "needs-integration", ""},
		{"interval over the VPN", `{"range":["10.100.0.100","10.100.1.5"]}`, saddr("==", `"@s"`), initContext(), "needs-integration", ""},
		{"allow list", `"198.51.100.7"`, saddr("!=", `"@s"`), testContext(), "needs-integration", ""},
		// An anonymous set is not a ban list: it may hold the peer's
		// endpoint (WireGuard transport).
		{"anonymous set", `"198.51.100.7"`, saddr("==", `{"set":["198.51.100.7"]}`), initContext(), "needs-integration", ""},
	}
	for _, c := range cases {
		a := Analyze(ruleset(c.elems, c.rule), c.ctx)
		if len(a.Chains) != 1 || a.Chains[0].Status != c.status || bansString(a.Chains[0].Bans) != c.bans {
			t.Errorf("%s: %+v, want %s with bans %q", c.name, a.Chains, c.status, c.bans)
		}
	}
}

// Meshly's rule in the iptables chains of a real UFW ruleset: inserted
// where missing, left alone where it is first.
func TestIptablesChainsRealUFW(t *testing.T) {
	mark := model.DefaultFirewallMark
	rule := `insert rule %s filter %s meta mark & 0x10000000 == 0x10000000 counter accept comment "meshly:v1 integration"` + "\n"
	for _, v := range allVersions {
		chains := loadFixture(t, v, "ufw").IptablesChains(mark)
		if got := IptablesNames(chains); got != "ip filter INPUT, ip filter OUTPUT, ip6 filter INPUT, ip6 filter OUTPUT" {
			t.Fatalf("%s: chains %s", v, got)
		}
		want := ""
		for _, c := range chains {
			if c.OK() || !c.Needed || len(c.Ours) != 0 {
				t.Fatalf("%s: %s observed as %+v", v, c, c)
			}
			want += fmt.Sprintf(rule, c.Family, c.Chain)
		}
		if got := IptablesScript(chains, mark); got != want {
			t.Fatalf("%s: script\n%s\nwant\n%s", v, got, want)
		}
		if got := IptablesRemoveScript(chains); got != "" {
			t.Fatalf("%s: nothing to remove, got %q", v, got)
		}

		chains = loadFixture(t, v, "ufw-integrated").IptablesChains(mark)
		for _, c := range chains {
			if !c.OK() || !c.First || len(c.Ours) != 1 {
				t.Fatalf("%s: %s observed as %+v", v, c, c)
			}
		}
		if got := IptablesScript(chains, mark); got != "" {
			t.Fatalf("%s: integrated chains changed: %q", v, got)
		}
		if got := IptablesRemoveScript(chains); strings.Count(got, "delete rule ") != 4 {
			t.Fatalf("%s: remove script %q", v, got)
		}
		// Another mark: the rule is replaced.
		other := loadFixture(t, v, "ufw-integrated").IptablesChains(0x20000000)
		if got := IptablesScript(other, 0x20000000); strings.Count(got, "delete rule ") != 4 || strings.Count(got, "insert rule ") != 4 {
			t.Fatalf("%s: rule with another mark kept: %q", v, got)
		}
	}
}

// The rule must be the only meshly rule and the first one; chains that
// cannot drop anything are left alone.
func TestIptablesChainStates(t *testing.T) {
	ours := func(h int) string {
		return fmt.Sprintf(`{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":%d,"comment":"meshly:v1 integration","expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},268435456]},"right":268435456}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}`, h)
	}
	foreign := `{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":5,"expr":[{"counter":{"packets":0,"bytes":0}},{"drop":null}]}}`
	head := `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"ip","name":"filter","handle":1}},` +
		`{"chain":{"family":"ip","table":"filter","name":"INPUT","handle":2,"type":"filter","hook":"input","prio":0,"policy":"%s"}}`
	cases := []struct {
		name, policy string
		rules        []string
		ok, needed   bool
		script       string
	}{
		{"empty accept chain", "accept", nil, true, false, ""},
		{"empty drop chain", "drop", nil, false, true, "insert"},
		{"foreign rule", "accept", []string{foreign}, false, true, "insert"},
		{"first", "drop", []string{ours(7), foreign}, true, true, ""},
		{"misplaced", "drop", []string{foreign, ours(7)}, false, true, "delete 7, insert"},
		{"duplicate", "drop", []string{ours(7), foreign, ours(8)}, false, true, "delete 7, delete 8, insert"},
		{"alone in an accept chain", "accept", []string{ours(7)}, true, true, ""},
	}
	for _, c := range cases {
		js := fmt.Sprintf(head, c.policy)
		for _, r := range c.rules {
			js += "," + r
		}
		rs, err := ParseRuleset([]byte(js + "]}"))
		if err != nil {
			t.Fatal(err)
		}
		chains := rs.IptablesChains(model.DefaultFirewallMark)
		if len(chains) != 1 || chains[0].OK() != c.ok || chains[0].Needed != c.needed {
			t.Fatalf("%s: %+v", c.name, chains)
		}
		var ops []string
		for _, l := range strings.Split(strings.TrimSpace(IptablesScript(chains, model.DefaultFirewallMark)), "\n") {
			switch {
			case strings.HasPrefix(l, "delete rule ip filter INPUT handle "):
				ops = append(ops, "delete "+strings.TrimPrefix(l, "delete rule ip filter INPUT handle "))
			case strings.HasPrefix(l, "insert rule ip filter INPUT "):
				ops = append(ops, "insert")
			case l != "":
				t.Fatalf("%s: unexpected statement %q", c.name, l)
			}
		}
		if got := strings.Join(ops, ", "); got != c.script {
			t.Fatalf("%s: script %q, want %q", c.name, got, c.script)
		}
	}
}

// Chains of other iptables tables and hooks are not integrated by meshly.
func TestIptablesOtherChainsUnsupported(t *testing.T) {
	js := `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"ip","name":"mangle","handle":1}},
{"chain":{"family":"ip","table":"mangle","name":"INPUT","handle":2,"type":"filter","hook":"input","prio":-150,"policy":"drop"}}]}`
	rs, err := ParseRuleset([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.IptablesChains(model.DefaultFirewallMark)) != 0 {
		t.Fatal("mangle chain taken for integration")
	}
	a := Analyze(rs, testContext())
	if len(a.Chains) != 1 || a.Chains[0].Status != "unsupported" || a.Chains[0].ByMeshly {
		t.Fatalf("mangle INPUT with policy drop: %+v", a.Chains)
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
