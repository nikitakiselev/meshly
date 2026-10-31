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
	"slices"
	"strings"

	"github.com/nikitakiselev/meshly/internal/model"
)

// RouteProtocol marks routes installed by Meshly (rtm_protocol). 109 is
// not assigned in linux/rtnetlink.h or iproute2's rt_protos.
const RouteProtocol = 109

// AliasPrefix is the IFLA_IFALIAS prefix of owned interfaces.
const AliasPrefix = "meshly:"

// Alias returns the alias for a network.
func Alias(networkID string) string { return AliasPrefix + networkID }

// IsOwnedAlias reports whether an alias marks a Meshly interface.
func IsOwnedAlias(a string) bool {
	id, ok := strings.CutPrefix(a, AliasPrefix)
	return ok && model.ValidateNetworkID(id) == nil
}

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

// Route is an IPv4 route via the managed interface: the VPN network, or a
// host route to a peer.
type Route struct {
	Dst netip.Prefix
	Src netip.Addr
}

// Sysctls are the per-interface (never global) settings Meshly applies:
// strict reverse path filtering, no redirects or source routing, IPv6
// disabled on the interface only. Forwarding (ForwardingSysctl) is set
// apart: on only while the node has Docker networks.
var Sysctls = []struct {
	Path  string // relative to /proc/sys, with %s for the interface
	Value string
}{
	{"net/ipv4/conf/%s/rp_filter", "1"},
	{"net/ipv4/conf/%s/accept_redirects", "0"},
	{"net/ipv4/conf/%s/send_redirects", "0"},
	{"net/ipv4/conf/%s/accept_source_route", "0"},
	{"net/ipv6/conf/%s/disable_ipv6", "1"},
}

// ForwardingSysctl is the per-interface forwarding switch (%s: interface).
const ForwardingSysctl = "net/ipv4/conf/%s/forwarding"

// RouteTable and RulePriority identify Meshly's policy routing: packets
// entering from the tunnel look up RouteTable, which only knows Docker
// bridge subnets and an unreachable default.
const (
	RouteTable   = 109
	RulePriority = 109
)

// Bridge is a Docker bridge with its masked IPv4 subnets (sorted, unique).
type Bridge struct {
	Name     string
	Prefixes []netip.Prefix
	// Down: set administratively down, no route can use it.
	Down bool
}

// ServedBridges returns the bridges meshly serves through the tunnel: none
// while RouteTable has routes of another program (foreign), otherwise the
// ones that are up, each subnet with the first bridge (by name) that has it.
// A bridge whose subnets are all taken stays, without routes.
func ServedBridges(bridges []Bridge, foreign int) []Bridge {
	if foreign > 0 {
		return nil
	}
	var out []Bridge
	routed := map[netip.Prefix]bool{}
	for _, b := range bridges {
		if b.Down {
			continue
		}
		s := Bridge{Name: b.Name}
		for _, p := range b.Prefixes {
			if !routed[p] {
				routed[p] = true
				s.Prefixes = append(s.Prefixes, p)
			}
		}
		out = append(out, s)
	}
	return out
}

// IsDockerBridge reports whether an interface of the given kind is
// docker0 or a user-defined Docker network bridge (br-<12 hex digits>).
func IsDockerBridge(name, kind string) bool {
	if kind != "bridge" {
		return false
	}
	if name == "docker0" {
		return true
	}
	id, ok := strings.CutPrefix(name, "br-")
	if !ok || len(id) != 12 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// PolicyRule is "iif <Iif> lookup <Table>" at Priority.
type PolicyRule struct {
	Iif             string
	Table, Priority int
}

// TableRoute is a route in RouteTable. An empty Dev means unreachable.
type TableRoute struct {
	Dst netip.Prefix
	Dev string
}

// DockerRouting is the policy routing state: rules and RouteTable routes.
type DockerRouting struct {
	Rules  []PolicyRule
	Routes []TableRoute
	// Foreign counts RouteTable routes of another protocol (observed only).
	Foreign int
}

// WantDockerRouting returns the routing for the bridges: nothing without
// bridges, otherwise a rule for ifname, a route per subnet and an
// unreachable default.
func WantDockerRouting(ifname string, bridges []Bridge) DockerRouting {
	if len(bridges) == 0 {
		return DockerRouting{}
	}
	w := DockerRouting{Rules: []PolicyRule{{Iif: ifname, Table: RouteTable, Priority: RulePriority}}}
	for _, b := range bridges {
		for _, p := range b.Prefixes {
			w.Routes = append(w.Routes, TableRoute{Dst: p, Dev: b.Name})
		}
	}
	w.Routes = append(w.Routes, TableRoute{Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0)})
	return w
}

// Equal compares rules and routes as sets; Foreign is ignored.
func (r DockerRouting) Equal(o DockerRouting) bool {
	return sameSet(r.Rules, o.Rules) && sameSet(r.Routes, o.Routes)
}

// Empty reports whether there are no rules and no routes.
func (r DockerRouting) Empty() bool { return len(r.Rules) == 0 && len(r.Routes) == 0 }

func sameSet[T comparable](a, b []T) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}
