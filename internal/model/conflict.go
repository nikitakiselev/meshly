package model

import (
	"fmt"
	"net/netip"
)

// UsedPrefix is an address or route already present on the system.
type UsedPrefix struct {
	Prefix netip.Prefix
	Source string // human readable origin, e.g. "address on eth0" or "route via docker0"
}

// Conflict reports an overlap between the VPN CIDR and existing state.
type Conflict struct {
	Prefix netip.Prefix
	Source string
}

func (c Conflict) String() string { return fmt.Sprintf("%s (%s)", c.Prefix, c.Source) }

// FindConflicts returns existing IPv4 prefixes that overlap cidr. Default
// routes are ignored: a /32 route for the peer is more specific and does not
// change where the rest of the traffic goes.
func FindConflicts(cidr netip.Prefix, used []UsedPrefix) []Conflict {
	var out []Conflict
	for _, u := range used {
		p := u.Prefix
		if !p.IsValid() || !p.Addr().Unmap().Is4() {
			continue
		}
		bits := p.Bits()
		if p.Addr().Is4In6() {
			bits -= 96 // ::ffff:a.b.c.d/(96+n) is a.b.c.d/n
		}
		if bits <= 0 {
			continue
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits).Masked()
		if p.Overlaps(cidr) {
			out = append(out, Conflict{Prefix: p, Source: u.Source})
		}
	}
	return out
}

// SuggestCIDR proposes a /24 that does not overlap anything in used.
func SuggestCIDR(used []UsedPrefix) (netip.Prefix, bool) {
	candidates := []string{}
	for i := 100; i < 256; i++ {
		candidates = append(candidates, fmt.Sprintf("10.%d.0.0/24", i))
	}
	for i := 16; i < 32; i++ {
		candidates = append(candidates, fmt.Sprintf("172.%d.200.0/24", i))
	}
	for _, c := range candidates {
		p := netip.MustParsePrefix(c)
		if len(FindConflicts(p, used)) == 0 {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
