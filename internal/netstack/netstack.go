// Package netstack manages the Meshly interface, its addresses, routes and
// per-interface sysctls. Ownership of kernel objects is explicit:
//
//   - the interface must be of type wireguard and carry the alias
//     "meshly:<network-id>" (set by Meshly on creation);
//   - routes are installed with the dedicated routing protocol number
//     RouteProtocol and only on the owned interface.
//
// Objects without these markers are never modified or removed.
package netstack

import (
	"net/netip"
	"strings"
)

// RouteProtocol marks routes installed by Meshly (rtm_protocol). 109 is
// not assigned in linux/rtnetlink.h or iproute2's rt_protos.
const RouteProtocol = 109

// AliasPrefix is the IFLA_IFALIAS prefix of owned interfaces.
const AliasPrefix = "meshly:"

// Alias returns the alias for a network.
func Alias(networkID string) string { return AliasPrefix + networkID }

// IsOwnedAlias reports whether an alias marks a Meshly interface.
func IsOwnedAlias(a string) bool { return strings.HasPrefix(a, AliasPrefix) }

// Link is the observed state of the managed interface.
type Link struct {
	Exists bool
	Index  int
	Type   string
	Alias  string
	MTU    int
	Up     bool
	Addrs  []netip.Prefix
	// Routes are Meshly-owned routes (RouteProtocol) on this link.
	Routes []Route
	// ForeignRoutes are other routes on this link (kernel/local ones).
	ForeignRoutes int
}

// Owned reports whether the link carries Meshly's ownership markers.
func (l Link) Owned() bool { return l.Exists && l.Type == "wireguard" && IsOwnedAlias(l.Alias) }

// Route is an IPv4 host route via the managed interface.
type Route struct {
	Dst netip.Prefix
	Src netip.Addr
}

// Sysctls are the per-interface (never global) settings Meshly applies:
// no forwarding of packets received on the interface, strict reverse path
// filtering, no redirects or source routing, IPv6 disabled on the
// interface only.
var Sysctls = []struct {
	Path  string // relative to /proc/sys, with %s for the interface
	Value string
}{
	{"net/ipv4/conf/%s/forwarding", "0"},
	{"net/ipv4/conf/%s/rp_filter", "1"},
	{"net/ipv4/conf/%s/accept_redirects", "0"},
	{"net/ipv4/conf/%s/send_redirects", "0"},
	{"net/ipv4/conf/%s/accept_source_route", "0"},
	{"net/ipv6/conf/%s/disable_ipv6", "1"},
}
