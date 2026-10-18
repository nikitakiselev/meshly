package nft

import (
	"fmt"
	"strings"
)

// IptablesComment marks the rule Meshly keeps at the top of the iptables
// filter INPUT and OUTPUT chains. It is Meshly's only object outside table
// inet meshly.
const IptablesComment = MarkerPrefix + " integration"

// IptablesChain is a built-in chain of an iptables-nft filter table into
// which Meshly puts its integration rule itself (iptables or UFW manage
// the chain; their rules still decide everything else).
type IptablesChain struct {
	Family string // "ip" or "ip6"
	Chain  string // "INPUT" or "OUTPUT"
	Policy string
	// Ours are the handles of Meshly's rules in the chain, in chain order.
	Ours []int
	// First: the chain starts with Meshly's rule for the current mark, and
	// has no other rule of Meshly.
	First bool
	// Needed: the chain may drop Meshly traffic (policy drop or any rule
	// besides Meshly's), or it already has Meshly's rule.
	Needed bool
}

func (c IptablesChain) String() string { return c.Family + " filter " + c.Chain }

// OK reports whether the chain is as Meshly wants it.
func (c IptablesChain) OK() bool { return !c.Needed || c.First }

// iptablesHooks maps the hooks of the integrated chains to their names.
var iptablesHooks = map[string]string{"input": "INPUT", "output": "OUTPUT"}

// integratedByMeshly reports whether a chain is one Meshly integrates
// itself: INPUT or OUTPUT of an iptables-nft filter table.
func integratedByMeshly(rs *Ruleset, c Chain) bool {
	return (c.Family == "ip" || c.Family == "ip6") && c.Table == "filter" && c.IsBase() &&
		iptablesHooks[c.Hook] == c.Name && isIptablesTable(rs, c.Family, c.Table)
}

// IptablesChains returns the integrated chains present in the ruleset,
// with Meshly's rule for mark observed in each.
func (rs *Ruleset) IptablesChains(mark uint32) []IptablesChain {
	an := &analyzer{rs: rs, ctx: Context{Mark: mark}}
	var out []IptablesChain
	for _, c := range rs.Chains {
		if !integratedByMeshly(rs, c) {
			continue
		}
		ic := IptablesChain{Family: c.Family, Chain: c.Name, Policy: c.Policy}
		rules := rs.ChainRules(c.Family, c.Table, c.Name)
		for _, r := range rules {
			if r.Comment == IptablesComment {
				ic.Ours = append(ic.Ours, r.Handle)
			}
		}
		ic.First = len(ic.Ours) == 1 && rules[0].Handle == ic.Ours[0] && an.isIntegration(rules[0])
		ic.Needed = c.Policy == "drop" || len(rules) > 0
		out = append(out, ic)
	}
	return out
}

// IptablesRule is Meshly's integration rule as an nft statement.
func IptablesRule(mark uint32) string {
	return fmt.Sprintf("meta mark & 0x%08x == 0x%08x counter accept comment %q", mark, mark, IptablesComment)
}

// IptablesScript puts Meshly's rule first in every chain that needs it and
// is not as wanted: Meshly's old rules are deleted by handle and one rule
// is inserted at the top, in one transaction. It returns "" when nothing
// is to be done.
func IptablesScript(chains []IptablesChain, mark uint32) string {
	var b strings.Builder
	for _, c := range chains {
		if c.OK() {
			continue
		}
		for _, h := range c.Ours {
			fmt.Fprintf(&b, "delete rule %s filter %s handle %d\n", c.Family, c.Chain, h)
		}
		fmt.Fprintf(&b, "insert rule %s filter %s %s\n", c.Family, c.Chain, IptablesRule(mark))
	}
	return b.String()
}

// IptablesRemoveScript deletes every rule of Meshly from the chains, or
// returns "" when there is none.
func IptablesRemoveScript(chains []IptablesChain) string {
	var b strings.Builder
	for _, c := range chains {
		for _, h := range c.Ours {
			fmt.Fprintf(&b, "delete rule %s filter %s handle %d\n", c.Family, c.Chain, h)
		}
	}
	return b.String()
}

// IptablesNames lists chains for messages, e.g. "ip filter INPUT, ip6
// filter INPUT".
func IptablesNames(chains []IptablesChain) string {
	var s []string
	for _, c := range chains {
		s = append(s, c.String())
	}
	return strings.Join(s, ", ")
}
