package nft

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Context describes the traffic Meshly needs to pass through foreign
// chains:
//
//   - class A: decrypted VPN traffic on the Meshly interface (IPv4 between
//     the local VPN address and the peers); on the forward hook, between
//     the Meshly interface and a Docker bridge;
//   - class B: WireGuard transport (UDP to/from the listen port on any
//     other interface); never forwarded.
type Context struct {
	Interface  string
	LocalVPN   netip.Addr
	Peers      []netip.Addr
	ListenPort uint16
	Mark       uint32
	// LocalAddrs are all addresses configured on the host (WireGuard
	// listens on every address).
	LocalAddrs []netip.Addr
	// Network is the VPN network. While no peer is known (init, invite,
	// join), a match on the remote address is checked against all of it:
	// the peers get their addresses from it.
	Network netip.Prefix
	// Endpoints are the known public addresses of the peers.
	Endpoints []netip.Addr
	// DockerBridges are the names of the node's Docker bridges. The
	// forward hook is analysed only while there is one.
	DockerBridges []string
}

// ChainFinding is the verdict for one foreign base chain.
type ChainFinding struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Hook     string `json:"hook"`
	Priority int    `json:"priority"`
	Policy   string `json:"policy"`
	// IptablesManaged: the table is owned by iptables-nft.
	IptablesManaged bool `json:"iptables_managed"`
	// ByMeshly: an iptables filter INPUT or OUTPUT chain (or ip filter
	// FORWARD), into which Meshly puts its integration rule itself (see IptablesChains).
	ByMeshly bool `json:"integrated_by_meshly,omitempty"`
	// Interfering lists handles of rules that may drop Meshly traffic
	// (directly or through jumps). Policy drop is reported separately.
	Interfering []int `json:"interfering_rules,omitempty"`
	// Bans lists rules that drop Meshly traffic only from peers listed in
	// a ban list (see Ban). They need no integration.
	Bans []Ban `json:"bans,omitempty"`
	// IntegrationHandle is the handle of the integration rule (0: none).
	IntegrationHandle int `json:"integration_rule,omitempty"`
	// Status: "compatible", "integrated", "needs-integration",
	// "misplaced-integration", "unsupported".
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Ban is a rule that drops the traffic of addresses listed in a named set
// with no range of VPN addresses: a ban list, as fail2ban, sshguard and
// CrowdSec keep. Bans hold also for Meshly traffic, so such a rule needs
// no integration; Addrs are the listed peer addresses (or, while no peer
// is known, VPN addresses) and peer endpoints whose traffic it drops.
type Ban struct {
	Rule  int          `json:"rule"`
	Set   string       `json:"set"`
	Addrs []netip.Addr `json:"addresses"`
}

// Fail2ban reports whether the set is one of fail2ban's.
func (b Ban) Fail2ban(table string) bool {
	return table == Fail2banTable || strings.HasPrefix(b.Set, "addr-set-") || strings.HasPrefix(b.Set, "addr6-set-")
}

// Fail2banTable is the table of fail2ban's nftables actions.
const Fail2banTable = "f2b-table"

// Analysis summarises a ruleset.
type Analysis struct {
	OurTablePresent bool           `json:"our_table_present"`
	OurTableOwned   bool           `json:"our_table_owned"`
	MarkerNetwork   string         `json:"marker_network,omitempty"`
	MarkerHash      string         `json:"marker_hash,omitempty"`
	Chains          []ChainFinding `json:"chains"`
	DockerDetected  bool           `json:"docker_detected"`
	DNATRules       int            `json:"dnat_rules"`
	IptablesTables  []string       `json:"iptables_nft_tables,omitempty"`
	UFWChains       bool           `json:"ufw_chains"`
	Fail2ban        bool           `json:"fail2ban"`
	FirewalldTables bool           `json:"firewalld_tables"`
	Flowtables      []string       `json:"flowtables_with_interface,omitempty"`
	NetdevChains    []string       `json:"netdev_chains,omitempty"`
	// DockerBridges are Context.DockerBridges.
	DockerBridges []string `json:"docker_bridges,omitempty"`
}

// NeedsIntegration reports chains that block Meshly until the
// administrator adds the integration rule. Forward chains are not
// among them (see Forward).
func (a *Analysis) NeedsIntegration() []ChainFinding {
	var out []ChainFinding
	for _, c := range a.Chains {
		if c.Hook != "forward" && !c.ByMeshly && (c.Status == "needs-integration" || c.Status == "misplaced-integration") {
			out = append(out, c)
		}
	}
	return out
}

// Unsupported reports chains that cannot be integrated, except forward
// chains (see Forward).
func (a *Analysis) Unsupported() []ChainFinding {
	var out []ChainFinding
	for _, c := range a.Chains {
		if c.Hook != "forward" && c.Status == "unsupported" {
			out = append(out, c)
		}
	}
	return out
}

// Forward reports forward chains, other than those Meshly integrates
// itself, that may drop the traffic of Docker containers through Meshly.
// They never block the tunnel between the hosts.
func (a *Analysis) Forward() []ChainFinding {
	var out []ChainFinding
	for _, c := range a.Chains {
		if c.Hook == "forward" && !c.ByMeshly && c.Status != "compatible" && c.Status != "integrated" {
			out = append(out, c)
		}
	}
	return out
}

// ByMeshly reports the iptables chains that may drop Meshly traffic, into
// which Meshly puts its integration rule itself.
func (a *Analysis) ByMeshly() []ChainFinding {
	var out []ChainFinding
	for _, c := range a.Chains {
		if c.ByMeshly && c.Status != "compatible" {
			out = append(out, c)
		}
	}
	return out
}

// HasFirewall reports whether any foreign chain but a forward one can drop
// Meshly traffic.
func (a *Analysis) HasFirewall() bool {
	for _, c := range a.Chains {
		if c.Hook != "forward" && c.Status != "compatible" {
			return true
		}
	}
	return false
}

var relevantHooks = map[string]bool{"prerouting": true, "input": true, "output": true, "postrouting": true}

var iptablesTables = map[string]bool{"filter": true, "nat": true, "mangle": true, "raw": true, "security": true}

func isIptablesTable(rs *Ruleset, family, table string) bool {
	if (family != "ip" && family != "ip6") || !iptablesTables[table] {
		return false
	}
	for _, c := range rs.Chains {
		if c.Family == family && c.Table == table && c.IsBase() && strings.ToUpper(c.Name) == c.Name {
			return true
		}
	}
	return false
}

// Analyze inspects a ruleset in the given context.
func Analyze(rs *Ruleset, ctx Context) *Analysis {
	a := &Analysis{DockerBridges: ctx.DockerBridges}
	if t := rs.Table(TableFamily, TableName); t != nil {
		a.OurTablePresent = true
		a.MarkerNetwork, a.MarkerHash, a.OurTableOwned = t.Marker()
	}
	seenIpt := map[string]bool{}
	for _, t := range rs.Tables {
		if isIptablesTable(rs, t.Family, t.Name) && !seenIpt[t.Family+" "+t.Name] {
			seenIpt[t.Family+" "+t.Name] = true
			a.IptablesTables = append(a.IptablesTables, t.Family+" "+t.Name)
		}
		if t.Name == "firewalld" {
			a.FirewalldTables = true
		}
		if t.Name == Fail2banTable {
			a.Fail2ban = true
		}
		if strings.HasPrefix(t.Name, "docker") {
			a.DockerDetected = true
		}
	}
	for _, c := range rs.Chains {
		if strings.HasPrefix(c.Name, "ufw-") || strings.HasPrefix(c.Name, "ufw6-") {
			a.UFWChains = true
		}
		if c.Name == "DOCKER" || strings.HasPrefix(c.Name, "DOCKER-") {
			a.DockerDetected = true
		}
		if c.Family == "netdev" && c.IsBase() {
			a.NetdevChains = append(a.NetdevChains, fmt.Sprintf("netdev %s %s", c.Table, c.Name))
		}
	}
	for _, r := range rs.Rules {
		if r.Family == TableFamily && r.Table == TableName {
			continue
		}
		for _, e := range r.Expr {
			if hasKey(e, "dnat") || hasKey(e, "redirect") || xtTargetName(e) == "DNAT" || xtTargetName(e) == "REDIRECT" {
				a.DNATRules++
			}
		}
	}
	for _, f := range rs.Flowtables {
		if slices.Contains(f.Devices(), ctx.Interface) {
			a.Flowtables = append(a.Flowtables, fmt.Sprintf("%s %s %s", f.Family, f.Table, f.Name))
		}
	}

	an := &analyzer{rs: rs, ctx: ctx, memo: map[string]classes{}}
	for _, c := range rs.Chains {
		relevant := relevantHooks[c.Hook] || c.Hook == "forward" && len(ctx.DockerBridges) > 0
		if !c.IsBase() || !relevant || (c.Family == TableFamily && c.Table == TableName) {
			continue
		}
		if c.Family != "ip" && c.Family != "ip6" && c.Family != "inet" {
			continue
		}
		a.Chains = append(a.Chains, an.chain(c))
	}
	return a
}

// classes is a pair of "may affect" flags for traffic classes A and B.
type classes struct{ A, B bool }

func (c classes) any() bool { return c.A || c.B }

// reaching are the classes a chain of family on hook may see: no IPv6
// inside the VPN, and no WireGuard transport forwarded.
func reaching(family, hook string) classes {
	return classes{A: family != "ip6", B: hook != "forward"}
}

type analyzer struct {
	rs    *Ruleset
	ctx   Context
	memo  map[string]classes
	stack map[string]bool
	// family/table of the rule being evaluated (named sets are per table)
	family, table string
	// ban is set by excludes for a match on a ban list.
	ban *banMatch
}

// banMatch is a match of the remote address against a ban list, with the
// listed addresses of Meshly's traffic classes.
type banMatch struct {
	set  string
	a, b []netip.Addr
}

func inbound(hook string) bool { return hook == "prerouting" || hook == "input" }

func (an *analyzer) chain(c Chain) ChainFinding {
	f := ChainFinding{
		Family: c.Family, Table: c.Table, Chain: c.Name, Hook: c.Hook,
		Priority: c.Priority(), Policy: c.Policy,
		IptablesManaged: isIptablesTable(an.rs, c.Family, c.Table),
		ByMeshly:        integratedByMeshly(an.rs, c),
	}
	if f.Policy == "" {
		f.Policy = "accept"
	}
	firstInterfering := -1
	integrationIdx := -1
	rules := an.rs.ChainRules(c.Family, c.Table, c.Name)
	for i, r := range rules {
		if integrationIdx < 0 && an.isIntegration(r) {
			integrationIdx = i
			f.IntegrationHandle = r.Handle
			continue
		}
		cl, ban := an.rule(r, c.Family, c.Hook)
		if cl.any() && ban != nil {
			b := Ban{Rule: r.Handle, Set: ban.set}
			if cl.A {
				b.Addrs = append(b.Addrs, ban.a...)
			}
			if cl.B {
				b.Addrs = append(b.Addrs, ban.b...)
			}
			f.Bans = append(f.Bans, b)
			continue
		}
		if cl.any() {
			f.Interfering = append(f.Interfering, r.Handle)
			if firstInterfering < 0 {
				firstInterfering = i
			}
		}
	}
	policyDrop := f.Policy == "drop" && reaching(c.Family, c.Hook).any()
	if len(f.Interfering) == 0 && !policyDrop {
		f.Status = "compatible"
		return f
	}
	reason := "policy drop"
	if len(f.Interfering) > 0 {
		reason = fmt.Sprintf("rules %v may drop meshly traffic", f.Interfering)
		if policyDrop {
			reason += " and policy is drop"
		}
	}
	switch {
	case f.IptablesManaged && !f.ByMeshly && c.Hook == "forward":
		f.Status = "unsupported"
		f.Detail = reason + "; meshly integrates only the FORWARD chain of the iptables filter table"
	case f.IptablesManaged && !f.ByMeshly:
		f.Status = "unsupported"
		f.Detail = reason + "; meshly integrates only the INPUT and OUTPUT chains of the iptables filter table"
		if len(an.ctx.DockerBridges) > 0 {
			f.Detail = reason + "; meshly integrates only the INPUT, OUTPUT and FORWARD chains of the iptables filter table"
		}
	case (c.Hook == "prerouting" || c.Hook == "output") && f.Priority <= PolicyPriority:
		f.Status = "unsupported"
		f.Detail = fmt.Sprintf("%s; chain priority %d runs before meshly (%d), integration is impossible", reason, f.Priority, PolicyPriority)
	case c.Hook == "forward" && f.Priority <= ForwardPriority:
		f.Status = "unsupported"
		f.Detail = fmt.Sprintf("%s; chain priority %d runs before meshly (%d), integration is impossible", reason, f.Priority, ForwardPriority)
	case integrationIdx < 0:
		f.Status = "needs-integration"
		f.Detail = reason
	case firstInterfering >= 0 && firstInterfering < integrationIdx:
		f.Status = "misplaced-integration"
		f.Detail = fmt.Sprintf("integration rule (handle %d) must come before rule handle %d", f.IntegrationHandle, rules[firstInterfering].Handle)
	default:
		f.Status = "integrated"
	}
	return f
}

// isIntegration matches exactly: meta mark & M == M [counter] accept.
func (an *analyzer) isIntegration(r Rule) bool {
	sawMatch, sawAccept := false, false
	for _, e := range r.Expr {
		switch {
		case hasKey(e, "counter"):
		case hasKey(e, "accept"):
			sawAccept = true
		case hasKey(e, "match"):
			var m struct {
				Match struct {
					Op   string `json:"op"`
					Left struct {
						And []json.RawMessage `json:"&"`
					} `json:"left"`
					Right json.RawMessage `json:"right"`
				} `json:"match"`
			}
			if json.Unmarshal(e, &m) != nil || m.Match.Op != "==" || len(m.Match.Left.And) != 2 {
				return false
			}
			var meta struct {
				Meta struct {
					Key string `json:"key"`
				} `json:"meta"`
			}
			var mask, right uint64
			if json.Unmarshal(m.Match.Left.And[0], &meta) != nil || meta.Meta.Key != "mark" ||
				json.Unmarshal(m.Match.Left.And[1], &mask) != nil || json.Unmarshal(m.Match.Right, &right) != nil ||
				mask != uint64(an.ctx.Mark) || right != uint64(an.ctx.Mark) {
				return false
			}
			sawMatch = true
		default:
			return false
		}
	}
	return sawMatch && sawAccept
}

// rule returns which classes a rule may drop. If it matches the remote
// address against a ban list, it drops only the listed addresses: ban
// describes them.
func (an *analyzer) rule(r Rule, family, hook string) (_ classes, ban *banMatch) {
	reach := reaching(family, hook)
	var effect classes
	an.family, an.table = r.Family, r.Table
	for _, e := range r.Expr {
		if hasKey(e, "match") {
			an.ban = nil
			ex := an.excludes(e, hook)
			if an.ban != nil && ban == nil {
				ban = an.ban
			}
			if ex.A {
				reach.A = false
			}
			if ex.B {
				reach.B = false
			}
			continue
		}
		switch {
		case hasKey(e, "drop"), hasKey(e, "reject"), hasKey(e, "queue"):
			effect = classes{true, true}
		case hasKey(e, "vmap"):
			effect = classes{true, true}
		case hasKey(e, "jump"), hasKey(e, "goto"):
			effect = an.target(e, r.Family, r.Table, hook)
		case hasKey(e, "xt"):
			if n := xtTargetName(e); n != "" && !harmlessXT[n] {
				effect = classes{true, true}
			}
		}
	}
	return classes{A: reach.A && effect.A, B: reach.B && effect.B}, ban
}

var harmlessXT = map[string]bool{
	"ACCEPT": true, "RETURN": true, "LOG": true, "NFLOG": true, "MARK": true, "CONNMARK": true,
	"DNAT": true, "SNAT": true, "MASQUERADE": true, "REDIRECT": true, "CT": true, "TCPMSS": true,
	"CHECKSUM": true, "TRACE": true,
}

func (an *analyzer) target(e json.RawMessage, family, table, hook string) classes {
	var v struct {
		Jump *struct {
			Target string `json:"target"`
		} `json:"jump"`
		Goto *struct {
			Target string `json:"target"`
		} `json:"goto"`
	}
	if json.Unmarshal(e, &v) != nil {
		return classes{true, true}
	}
	name := ""
	if v.Jump != nil {
		name = v.Jump.Target
	} else if v.Goto != nil {
		name = v.Goto.Target
	}
	key := family + "\x00" + table + "\x00" + name + "\x00" + hook
	if c, ok := an.memo[key]; ok {
		return c
	}
	if an.stack == nil {
		an.stack = map[string]bool{}
	}
	if an.stack[key] {
		return classes{true, true} // cycle: be conservative
	}
	an.stack[key] = true
	defer delete(an.stack, key)
	var out classes
	for _, r := range an.rs.ChainRules(family, table, name) {
		c, _ := an.rule(r, family, hook)
		out.A = out.A || c.A
		out.B = out.B || c.B
	}
	an.memo[key] = out
	return out
}

// excludes decides whether a match provably excludes class A or B.
func (an *analyzer) excludes(e json.RawMessage, hook string) classes {
	var m struct {
		Match struct {
			Op    string          `json:"op"`
			Left  json.RawMessage `json:"left"`
			Right json.RawMessage `json:"right"`
		} `json:"match"`
	}
	if json.Unmarshal(e, &m) != nil {
		return classes{}
	}
	op := m.Match.Op
	if op == "in" {
		op = "=="
	}
	if op != "==" && op != "!=" {
		return classes{}
	}
	var left struct {
		Meta *struct {
			Key string `json:"key"`
		} `json:"meta"`
		Payload *struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
		CT *struct {
			Key string `json:"key"`
		} `json:"ct"`
	}
	if json.Unmarshal(m.Match.Left, &left) != nil {
		return classes{}
	}
	in := inbound(hook)
	fwd := hook == "forward"
	values := an.values(m.Match.Right)
	switch {
	case left.Meta != nil:
		switch left.Meta.Key {
		case "iifname", "iif", "oifname", "oif":
			if fwd {
				return an.forwardIface(op, values)
			}
			isIn := strings.HasPrefix(left.Meta.Key, "i")
			if isIn != in {
				return classes{}
			}
			hasOurs := values.hasString(an.ctx.Interface)
			if op == "==" {
				onlyLoOrOurs := values.allStrings(func(s string) bool { return s == "lo" || s == an.ctx.Interface })
				return classes{A: !hasOurs, B: onlyLoOrOurs && values.known()}
			}
			return classes{A: hasOurs}
		case "l4proto":
			return an.protoExcl(op, values)
		case "nfproto":
			if op == "==" && values.known() && !values.hasString("ipv4") {
				return classes{A: true}
			}
		}
	case left.Payload != nil:
		p := left.Payload
		switch {
		case fwd && p.Protocol == "ip6":
			return classes{A: true} // no IPv6 inside the VPN
		case fwd && p.Protocol == "ip" && (p.Field == "saddr" || p.Field == "daddr"):
			return classes{} // peers' and containers' addresses
		case (p.Protocol == "ip" || p.Protocol == "ip6") && (p.Field == "saddr" && in || p.Field == "daddr" && !in):
			return an.remote(p.Protocol, op, m.Match.Right, values)
		case p.Protocol == "ip6":
			return classes{A: true}
		case p.Protocol == "ip" && p.Field == "protocol":
			return an.protoExcl(op, values)
		case p.Protocol == "tcp" || p.Protocol == "icmp" || p.Protocol == "icmpv6" || p.Protocol == "sctp":
			return classes{B: true}
		case p.Protocol == "udp" && (p.Field == "dport" && in || p.Field == "sport" && !in):
			if !values.known() {
				return classes{}
			}
			has := values.hasNumber(int(an.ctx.ListenPort))
			return classes{B: (op == "==" && !has) || (op == "!=" && has && values.single())}
		case p.Protocol == "ip" && (p.Field == "daddr" && in || p.Field == "saddr" && !in):
			if !values.known() {
				return classes{}
			}
			hasVPN := values.hasAddr(an.ctx.LocalVPN)
			hasLocal := false
			for _, l := range an.ctx.LocalAddrs {
				if values.hasAddr(l) {
					hasLocal = true
				}
			}
			if op == "==" {
				return classes{A: !hasVPN, B: !hasLocal}
			}
			return classes{A: hasVPN && values.single()}
		}
	case left.CT != nil && left.CT.Key == "state":
		if op == "==" && values.known() && values.allStrings(func(s string) bool { return s == "invalid" || s == "untracked" }) {
			return classes{A: true, B: true}
		}
	}
	return classes{}
}

// forwardIface decides an interface match on the forward hook: class A
// goes between the Meshly interface and a Docker bridge, in either
// direction. A trailing "*" matches by prefix, as in nft.
func (an *analyzer) forwardIface(op string, v valueSet) classes {
	if op != "==" || !v.known() || len(v.numbers) > 0 || len(v.prefixes) > 0 || len(v.ranges) > 0 {
		return classes{}
	}
	names := append([]string{an.ctx.Interface}, an.ctx.DockerBridges...)
	for _, s := range v.strings {
		for _, name := range names {
			if p, wild := strings.CutSuffix(s, "*"); s == name || wild && strings.HasPrefix(name, p) {
				return classes{}
			}
		}
	}
	return classes{A: true}
}

// remote decides a match on the remote address: the source of inbound and
// the destination of outbound packets. A named set without a range of VPN
// addresses is a ban list: it excludes all Meshly traffic but that of the
// listed peers, which an.ban records.
func (an *analyzer) remote(proto, op string, right json.RawMessage, values valueSet) classes {
	ex := classes{A: proto == "ip6"} // no IPv6 inside the VPN
	if !values.known() || op != "==" {
		return ex
	}
	var name string
	if json.Unmarshal(right, &name) == nil && strings.HasPrefix(name, "@") && !an.vpnRange(values) {
		b := &banMatch{set: strings.TrimPrefix(name, "@")}
		if proto == "ip" {
			b.a = an.vpnAddrs(values)
		}
		for _, e := range an.ctx.Endpoints {
			if values.hasAddr(e.Unmap()) {
				b.b = append(b.b, e.Unmap())
			}
		}
		an.ban = b
		return classes{A: len(b.a) == 0, B: len(b.b) == 0}
	}
	if proto == "ip6" || len(an.ctx.Peers) == 0 && !an.ctx.Network.IsValid() {
		return ex
	}
	return classes{A: len(an.vpnAddrs(values)) == 0 && (len(an.ctx.Peers) > 0 || !an.vpnRange(values))}
}

// vpnAddrs returns the peer addresses in values or, while no peer is
// known, the addresses of the VPN network.
func (an *analyzer) vpnAddrs(v valueSet) []netip.Addr {
	var out []netip.Addr
	if len(an.ctx.Peers) > 0 {
		for _, p := range an.ctx.Peers {
			if v.hasAddr(p) {
				out = append(out, p)
			}
		}
		return out
	}
	for _, p := range v.prefixes {
		if p.IsSingleIP() && an.ctx.Network.Contains(p.Addr()) {
			out = append(out, p.Addr())
		}
	}
	return out
}

// vpnRange reports whether values hold a range or prefix that overlaps
// the VPN network (or holds a peer when the network is unknown).
func (an *analyzer) vpnRange(v valueSet) bool {
	n := an.ctx.Network
	for _, p := range v.prefixes {
		if !p.IsSingleIP() && (n.IsValid() && p.Overlaps(n) || !n.IsValid() && slices.ContainsFunc(an.ctx.Peers, p.Contains)) {
			return true
		}
	}
	for _, r := range v.ranges {
		if n.IsValid() && r[0].Compare(lastAddr(n)) <= 0 && r[1].Compare(n.Masked().Addr()) >= 0 {
			return true
		}
		if !n.IsValid() && slices.ContainsFunc(an.ctx.Peers, func(a netip.Addr) bool { return a.Compare(r[0]) >= 0 && a.Compare(r[1]) <= 0 }) {
			return true
		}
	}
	return false
}

// lastAddr is the last address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		a[i/8] |= 1 << (7 - i%8)
	}
	out := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		out = out.Unmap()
	}
	return out
}

func (an *analyzer) protoExcl(op string, v valueSet) classes {
	if op != "==" || !v.known() {
		return classes{}
	}
	return classes{
		A: !v.hasString("tcp") && !v.hasString("udp") && !v.hasString("icmp") && !v.hasNumber(6) && !v.hasNumber(17) && !v.hasNumber(1),
		B: !v.hasString("udp") && !v.hasNumber(17),
	}
}

// valueSet is the right-hand side of a match, resolved where possible.
type valueSet struct {
	strings  []string
	numbers  []int
	prefixes []netip.Prefix
	ranges   [][2]netip.Addr
	unknown  bool
	count    int
}

func (v valueSet) known() bool  { return !v.unknown }
func (v valueSet) single() bool { return v.count == 1 }
func (v valueSet) hasString(s string) bool {
	return slices.Contains(v.strings, s)
}
func (v valueSet) hasNumber(n int) bool { return slices.Contains(v.numbers, n) }
func (v valueSet) allStrings(f func(string) bool) bool {
	if len(v.strings) == 0 || len(v.numbers) > 0 || len(v.prefixes) > 0 {
		return false
	}
	for _, s := range v.strings {
		if !f(s) {
			return false
		}
	}
	return true
}
func (v valueSet) hasAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range v.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	for _, r := range v.ranges {
		if a.Compare(r[0]) >= 0 && a.Compare(r[1]) <= 0 {
			return true
		}
	}
	return false
}

func (an *analyzer) values(raw json.RawMessage) valueSet {
	var v valueSet
	an.addValue(&v, raw, 0)
	return v
}

func (an *analyzer) addValue(v *valueSet, raw json.RawMessage, depth int) {
	if depth > 4 {
		v.unknown = true
		return
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if strings.HasPrefix(s, "@") {
			an.addNamedSet(v, strings.TrimPrefix(s, "@"), depth)
			return
		}
		v.count++
		if a, err := netip.ParseAddr(s); err == nil {
			v.prefixes = append(v.prefixes, netip.PrefixFrom(a, a.BitLen()))
			return
		}
		v.strings = append(v.strings, s)
		return
	}
	var n float64
	if json.Unmarshal(raw, &n) == nil {
		v.count++
		v.numbers = append(v.numbers, int(n))
		return
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		for _, x := range list {
			an.addValue(v, x, depth+1)
		}
		return
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		v.unknown = true
		return
	}
	switch {
	case obj["set"] != nil:
		an.addValue(v, obj["set"], depth+1)
	case obj["prefix"] != nil:
		var p struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if json.Unmarshal(obj["prefix"], &p) != nil {
			v.unknown = true
			return
		}
		a, err := netip.ParseAddr(p.Addr)
		if err != nil {
			v.unknown = true
			return
		}
		pr, err := a.Prefix(p.Len)
		if err != nil {
			v.unknown = true
			return
		}
		v.count += 2 // a prefix is never a "single" value
		v.prefixes = append(v.prefixes, pr)
	case obj["range"] != nil:
		var r []json.RawMessage
		if json.Unmarshal(obj["range"], &r) != nil || len(r) != 2 {
			v.unknown = true
			return
		}
		var lo, hi string
		var nlo, nhi float64
		if json.Unmarshal(r[0], &lo) == nil && json.Unmarshal(r[1], &hi) == nil {
			a, err1 := netip.ParseAddr(lo)
			b, err2 := netip.ParseAddr(hi)
			if err1 != nil || err2 != nil {
				v.unknown = true
				return
			}
			v.count += 2
			v.ranges = append(v.ranges, [2]netip.Addr{a, b})
			return
		}
		if json.Unmarshal(r[0], &nlo) == nil && json.Unmarshal(r[1], &nhi) == nil {
			v.count += 2
			for i := int(nlo); i <= int(nhi) && i-int(nlo) < 65536; i++ {
				v.numbers = append(v.numbers, i)
			}
			return
		}
		v.unknown = true
	case obj["elem"] != nil:
		var e struct {
			Val json.RawMessage `json:"val"`
		}
		if json.Unmarshal(obj["elem"], &e) != nil {
			v.unknown = true
			return
		}
		an.addValue(v, e.Val, depth+1)
	default:
		v.unknown = true
	}
}

func (an *analyzer) addNamedSet(v *valueSet, name string, depth int) {
	for _, s := range an.rs.Sets {
		if s.Family == an.family && s.Table == an.table && s.Name == name {
			if len(s.Elem) == 0 {
				return
			}
			for _, e := range s.Elem {
				an.addValue(v, e, depth+1)
			}
			v.count += 2 // named sets are mutable: never treat as single
			return
		}
	}
	v.unknown = true
}

func hasKey(raw json.RawMessage, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

func xtTargetName(raw json.RawMessage) string {
	var v struct {
		XT *struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"xt"`
	}
	if json.Unmarshal(raw, &v) != nil || v.XT == nil || v.XT.Type != "target" {
		return ""
	}
	return v.XT.Name
}
