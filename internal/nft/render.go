// Package nft renders, applies and inspects the Meshly nftables table and
// analyses foreign rulesets for compatibility.
//
// Meshly owns exactly one table, "inet meshly". It is always replaced as a
// whole in one nft transaction ("add; delete; define"), so packets observe
// either the old or the new policy, never a partial one. No other table is
// ever modified, except for one rule that Meshly keeps at the top of the
// iptables filter INPUT and OUTPUT chains (see iptables.go).
package nft

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/nikitakiselev/meshly/internal/model"
)

const (
	TableFamily = "inet"
	TableName   = "meshly"
	// MarkerPrefix starts the comment of the ownership marker rule.
	MarkerPrefix = "meshly:v1"

	// PolicyPriority places the policy chains after conntrack (-200) and
	// before mangle (-150) and DNAT (-100): decisions see the original
	// destination, and conntrack state is available.
	PolicyPriority = -180
	// ForwardPriority runs the forward guard before ordinary filter chains.
	ForwardPriority = -300
	// NATPriority and PostPriority bracket srcnat (100): meshly's own SNAT
	// runs just before it, the post-NAT check just after.
	NATPriority  = 99
	PostPriority = 101
)

// bridgeNameRe admits docker0 and br-<12 hex>; model.ValidateInterfaceName
// refuses the hyphen.
var bridgeNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)

// AllowEntry is one rendered allow rule.
type AllowEntry struct {
	Peer  netip.Addr
	Proto model.Proto
	Port  uint16
}

// Input is everything the renderer needs. All values are typed and
// validated; no free-form strings reach the ruleset.
type Input struct {
	NetworkID  string
	Interface  string
	LocalAddr  netip.Addr
	CIDR       netip.Prefix
	ListenPort uint16
	Mark       uint32
	Peers      []netip.Addr
	Allow      []AllowEntry
	// Exclusive are allow entries whose port only their peer may reach,
	// through Interface: guard_in drops every other packet for it, from
	// loopback or after DNAT too. Each must also be in Allow.
	Exclusive []AllowEntry
	// Lockdown leaves the WireGuard transport unmarked: in safe mode the
	// interface is gone, and the integration rule must not keep the listen
	// port open for whatever else binds it.
	Lockdown bool
	// Docker are the Docker bridge names. Not empty (and not Lockdown), the
	// table forwards between them and the interface; see docs/firewall.md#docker.
	Docker []string
}

// InputFromConfig derives the renderer input from a config. With lockdown
// set, peers and rules are omitted: everything on the interface is dropped,
// and the WireGuard transport is not marked.
func InputFromConfig(c *model.Config, lockdown bool) Input {
	in := Input{
		NetworkID:  c.Network.ID,
		Interface:  c.Interface.Name,
		LocalAddr:  c.Self.Address,
		CIDR:       c.Network.CIDR,
		ListenPort: c.Self.ListenPort,
		Mark:       c.Firewall.Mark,
		Lockdown:   lockdown,
	}
	if lockdown {
		return in
	}
	byName := map[string]netip.Addr{}
	for _, p := range c.Peers {
		in.Peers = append(in.Peers, p.Address)
		byName[p.Name] = p.Address
	}
	for _, r := range c.Rules {
		if a, ok := byName[r.Peer]; ok {
			in.Allow = append(in.Allow, AllowEntry{Peer: a, Proto: r.Proto, Port: r.Port})
		}
	}
	return in
}

func (in Input) validate() error {
	if err := model.ValidateNetworkID(in.NetworkID); err != nil {
		return fmt.Errorf("network id: %w", err)
	}
	if err := model.ValidateInterfaceName(in.Interface); err != nil {
		return err
	}
	if err := model.ValidateCIDR(in.CIDR); err != nil {
		return err
	}
	if err := model.ValidateHostAddress(in.CIDR, in.LocalAddr); err != nil {
		return err
	}
	if err := model.ValidatePort(int(in.ListenPort)); err != nil {
		return err
	}
	if err := model.ValidateMark(in.Mark); err != nil {
		return err
	}
	for _, p := range in.Peers {
		if err := model.ValidateHostAddress(in.CIDR, p); err != nil {
			return err
		}
	}
	for _, a := range in.Allow {
		if err := (model.Rule{Peer: "x", Proto: a.Proto, Port: a.Port}).Validate(); err != nil {
			return err
		}
		if !slices.Contains(in.Peers, a.Peer) {
			return fmt.Errorf("allow entry for unknown peer %s", a.Peer)
		}
	}
	for _, n := range in.Docker {
		if !bridgeNameRe.MatchString(n) {
			return fmt.Errorf("invalid docker bridge name %q", n)
		}
	}
	for _, x := range in.Exclusive {
		if x.Proto != model.ProtoTCP && x.Proto != model.ProtoUDP {
			return fmt.Errorf("exclusive entry for %s: only a TCP or UDP port can be exclusive", x.Peer)
		}
		if !slices.Contains(in.Allow, x) {
			return fmt.Errorf("exclusive entry %s %s/%d is not an allow entry", x.Peer, x.Proto, x.Port)
		}
	}
	return nil
}

// Rendered is a complete table definition.
type Rendered struct {
	// Definition is the "table inet meshly { ... }" block.
	Definition string
	// Hash identifies the policy (everything except the marker comment).
	Hash string
}

// ApplyScript replaces the table atomically: the leading add makes the
// delete valid when the table does not exist yet.
func (r Rendered) ApplyScript() string {
	return "table inet meshly\ndelete table inet meshly\n" + r.Definition
}

// DeleteScript removes the table.
const DeleteScript = "delete table inet meshly\n"

// Render builds the Meshly table. See docs/firewall.md for the packet path
// analysis behind each rule.
func Render(in Input) (Rendered, error) {
	if err := in.validate(); err != nil {
		return Rendered{}, fmt.Errorf("render firewall: %w", err)
	}
	const markerToken = "@@MARKER@@"
	m := fmt.Sprintf("0x%08x", in.Mark)
	nm := fmt.Sprintf("0x%08x", ^in.Mark)
	setMark := "meta mark set meta mark | " + m
	ifname := `"` + in.Interface + `"`
	local := in.LocalAddr.String()
	// Lockdown closes forwarding completely.
	docker := in.Docker
	if in.Lockdown {
		docker = nil
	}
	docker = slices.Compact(slices.Sorted(slices.Values(docker)))
	icmpErr := "icmp type { destination-unreachable, time-exceeded, parameter-problem }"

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("table inet meshly {")
	w("\tcomment %q", "managed by meshly; do not edit (network "+in.NetworkID+")")
	w("")
	w("\tset peers {")
	w("\t\ttype ipv4_addr")
	if els := peerElements(in.Peers); els != "" {
		w("\t\telements = { %s }", els)
	}
	w("\t}")
	w("")
	w("\tset allow_in {")
	w("\t\ttype ipv4_addr . inet_proto . inet_service")
	if els := allowElements(in.Allow); els != "" {
		w("\t\telements = { %s }", els)
	}
	w("\t}")
	w("")
	w("\tset allow_ping {")
	w("\t\ttype ipv4_addr")
	if els := pingElements(in.Allow); els != "" {
		w("\t\telements = { %s }", els)
	}
	w("\t}")
	w("")
	if len(docker) > 0 {
		quoted := make([]string, len(docker))
		for i, n := range docker {
			quoted[i] = `"` + n + `"`
		}
		w("\tset docker_ifs {")
		w("\t\ttype ifname")
		w("\t\telements = { %s }", strings.Join(quoted, ", "))
		w("\t}")
		w("")
	}
	// Inbound guard, before DNAT.
	w("\tchain guard_pre {")
	w("\t\ttype filter hook prerouting priority %d; policy accept;", PolicyPriority)
	w("\t\tmeta mark & %s == %s meta mark set meta mark & %s comment %s", m, m, nm, markerToken)
	w("\t\tiifname %s jump from_vpn", ifname)
	w("\t\tiifname != { \"lo\", %s } ip daddr %s counter drop comment \"vpn address reachable only through the vpn\"", ifname, local)
	w("\t\tiifname != { \"lo\", %s } ip saddr %s counter drop comment \"spoofed vpn source\"", ifname, in.CIDR)
	if !in.Lockdown {
		w("\t\tudp dport %d fib daddr type local counter %s comment \"wireguard transport\"", in.ListenPort, setMark)
	}
	w("\t}")
	w("")
	w("\tchain from_vpn {")
	w("\t\tmeta nfproto != ipv4 counter drop comment \"no ipv6 inside the vpn\"")
	w("\t\tip saddr != @peers counter drop comment \"unknown or spoofed peer address\"")
	w("\t\tip daddr != %s counter drop comment \"only the local vpn address\"", local)
	w("\t\tct state invalid,untracked counter drop")
	w("\t\tct direction reply ct state established %s accept comment \"replies to locally initiated connections\"", setMark)
	w("\t\tct state related %s %s accept", icmpErr, setMark)
	w("\t\tct direction original meta l4proto { tcp, udp } ip saddr . meta l4proto . th dport @allow_in %s accept", setMark)
	w("\t\tct direction original icmp type echo-request ip saddr @allow_ping %s accept", setMark)
	w("\t\tcounter drop comment \"default deny\"")
	w("\t}")
	w("")
	// After DNAT: anything rewritten is refused. An exclusive port is
	// checked here for every interface, because input sees loopback too
	// and the destination after DNAT.
	w("\tchain guard_in {")
	w("\t\ttype filter hook input priority %d; policy accept;", PolicyPriority)
	w("\t\tiifname %s ip daddr != %s counter drop comment \"rewritten destination\"", ifname, local)
	w("\t\tiifname %s ct status dnat counter drop comment \"dnat from the vpn is not supported\"", ifname)
	for _, x := range exclusiveRules(in.Exclusive, ifname) {
		w("\t\tip daddr %s %s dport %d iifname . ip saddr != { %s } counter drop comment \"reachable only from its peer through the vpn\"", local, x.proto, x.port, x.from)
	}
	w("\t}")
	w("")
	w("\tchain guard_fwd {")
	w("\t\ttype filter hook forward priority %d; policy accept;", ForwardPriority)
	if len(docker) > 0 {
		// Only tunnel traffic: this hook sees every packet the host forwards.
		w("\t\tiifname %s ct state invalid,untracked counter drop", ifname)
		w("\t\toifname %s ct state invalid,untracked counter drop", ifname)
		w("\t\tiifname %s oifname @docker_ifs ct direction original ct status dnat ct original ip daddr %s %s accept comment \"published container port\"", ifname, local, setMark)
		w("\t\tiifname %s oifname @docker_ifs ct direction reply ct status snat %s accept comment \"replies to containers\"", ifname, setMark)
		w("\t\toifname %s iifname @docker_ifs ct direction original ip daddr @peers %s accept comment \"connections from containers\"", ifname, setMark)
		w("\t\toifname %s iifname @docker_ifs ct direction reply ct status dnat %s accept comment \"replies of published container ports\"", ifname, setMark)
	}
	w("\t\tiifname %s counter drop comment \"no forwarding from the vpn\"", ifname)
	w("\t\toifname %s counter drop comment \"no forwarding into the vpn\"", ifname)
	w("\t}")
	w("")
	if len(docker) > 0 {
		w("\tchain nat_out {")
		w("\t\ttype nat hook postrouting priority %d; policy accept;", NATPriority)
		w("\t\toifname %s ip saddr != %s counter snat ip to %s comment \"containers appear as this node\"", ifname, local, local)
		w("\t}")
		w("")
		w("\tchain guard_post {")
		w("\t\ttype filter hook postrouting priority %d; policy accept;", PostPriority)
		w("\t\toifname %s ip saddr != %s counter drop comment \"only the vpn address into the vpn\"", ifname, local)
		w("\t\toifname %s iifname @docker_ifs ct direction reply ct status dnat meta l4proto { tcp, udp } ip daddr . meta l4proto . th sport != @allow_in counter drop comment \"replies of denied container ports\"", ifname)
		w("\t}")
		w("")
	}
	w("\tchain guard_out {")
	w("\t\ttype filter hook output priority %d; policy accept;", PolicyPriority)
	w("\t\tmeta mark & %s == %s meta mark set meta mark & %s", m, m, nm)
	w("\t\toifname %s jump to_vpn", ifname)
	if !in.Lockdown {
		w("\t\tudp sport %d %s comment \"wireguard transport\"", in.ListenPort, setMark)
	}
	w("\t}")
	w("")
	w("\tchain to_vpn {")
	w("\t\tmeta nfproto != ipv4 counter drop")
	w("\t\tip saddr != %s counter drop", local)
	w("\t\tip daddr != @peers counter drop")
	w("\t\tct state invalid,untracked counter drop")
	w("\t\tct direction original %s accept comment \"locally initiated\"", setMark)
	w("\t\tct status & (snat | dnat) != 0 counter drop")
	w("\t\tct direction reply ct state established meta l4proto { tcp, udp } ip daddr . meta l4proto . th sport @allow_in %s accept", setMark)
	w("\t\tct direction reply ct state established icmp type echo-reply ip daddr @allow_ping %s accept", setMark)
	w("\t\tct state related %s %s accept", icmpErr, setMark)
	w("\t\tcounter drop comment \"replies of denied connections\"")
	w("\t}")
	w("}")

	body := b.String()
	sum := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(sum[:8])
	marker := fmt.Sprintf("%q", MarkerPrefix+" net="+in.NetworkID+" hash="+hash)
	return Rendered{Definition: strings.Replace(body, markerToken, marker, 1), Hash: hash}, nil
}

func peerElements(ps []netip.Addr) string {
	s := slices.Clone(ps)
	slices.SortFunc(s, func(a, b netip.Addr) int { return a.Compare(b) })
	s = slices.Compact(s)
	parts := make([]string, len(s))
	for i, a := range s {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

func allowElements(as []AllowEntry) string {
	var parts []string
	for _, a := range sortedAllow(as) {
		if a.Proto == model.ProtoTCP || a.Proto == model.ProtoUDP {
			parts = append(parts, fmt.Sprintf("%s . %s . %d", a.Peer, a.Proto, a.Port))
		}
	}
	return strings.Join(slices.Compact(parts), ", ")
}

func pingElements(as []AllowEntry) string {
	var ps []netip.Addr
	for _, a := range as {
		if a.Proto == model.ProtoPing {
			ps = append(ps, a.Peer)
		}
	}
	return peerElements(ps)
}

// exclusiveRule is one port of the local VPN address that only the
// interface and peer pairs in from may reach.
type exclusiveRule struct {
	proto model.Proto
	port  uint16
	from  string
}

// exclusiveRules groups the entries by port: peers that share a port share
// its rule, or each rule would drop the other peers.
func exclusiveRules(xs []AllowEntry, ifname string) []exclusiveRule {
	var out []exclusiveRule
	for _, x := range slices.Compact(sortedPort(xs)) {
		el := ifname + " . " + x.Peer.String()
		if n := len(out); n > 0 && out[n-1].proto == x.Proto && out[n-1].port == x.Port {
			out[n-1].from += ", " + el
			continue
		}
		out = append(out, exclusiveRule{proto: x.Proto, port: x.Port, from: el})
	}
	return out
}

// sortedPort sorts by protocol, port and peer.
func sortedPort(as []AllowEntry) []AllowEntry {
	s := slices.Clone(as)
	slices.SortFunc(s, func(a, b AllowEntry) int {
		if c := strings.Compare(string(a.Proto), string(b.Proto)); c != 0 {
			return c
		}
		if c := int(a.Port) - int(b.Port); c != 0 {
			return c
		}
		return a.Peer.Compare(b.Peer)
	})
	return s
}

func sortedAllow(as []AllowEntry) []AllowEntry {
	s := slices.Clone(as)
	slices.SortFunc(s, func(a, b AllowEntry) int {
		if c := a.Peer.Compare(b.Peer); c != 0 {
			return c
		}
		if c := strings.Compare(string(a.Proto), string(b.Proto)); c != 0 {
			return c
		}
		return int(a.Port) - int(b.Port)
	})
	return s
}

// IntegrationRule is the single rule an administrator adds to their own
// base chains (profile "nftables") so Meshly-accepted packets pass them.
func IntegrationRule(mark uint32) string {
	return fmt.Sprintf("meta mark & 0x%08x == 0x%08x accept comment \"meshly\"", mark, mark)
}
