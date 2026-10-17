//go:build linux

package netstack

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Netlink implements the engine's link operations with rtnetlink.
type Netlink struct {
	// ProcSys is the sysctl root ("/proc/sys").
	ProcSys string
}

// New returns the production implementation.
func New() *Netlink { return &Netlink{ProcSys: "/proc/sys"} }

// Observe reads the state of the interface name.
func (n *Netlink) Observe(name string) (Link, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return Link{}, nil
		}
		return Link{}, fmt.Errorf("read link %s: %w", name, err)
	}
	attrs := l.Attrs()
	out := Link{
		Exists: true,
		Index:  attrs.Index,
		Type:   l.Type(),
		Alias:  attrs.Alias,
		MTU:    attrs.MTU,
		Up:     attrs.Flags&net.FlagUp != 0,
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return Link{}, fmt.Errorf("list addresses of %s: %w", name, err)
	}
	for _, a := range addrs {
		if p, ok := prefixOf(a.IPNet); ok {
			out.Addrs = append(out.Addrs, p)
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: attrs.Index, Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return Link{}, fmt.Errorf("list routes of %s: %w", name, err)
	}
	for _, r := range routes {
		if int(r.Protocol) != RouteProtocol {
			out.ForeignRoutes++
			continue
		}
		dst, ok := prefixOf(r.Dst)
		if !ok {
			continue
		}
		src, _ := netip.AddrFromSlice(r.Src)
		out.Routes = append(out.Routes, Route{Dst: dst, Src: src.Unmap()})
	}
	return out, nil
}

func prefixOf(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones), true
}

func (n *Netlink) owned(name string) (netlink.Link, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("link %s: %w", name, err)
	}
	if l.Type() != "wireguard" || !IsOwnedAlias(l.Attrs().Alias) {
		return nil, fmt.Errorf("refusing to modify %s: it is not owned by meshly (type %s, alias %q)", name, l.Type(), l.Attrs().Alias)
	}
	return l, nil
}

// Create adds a new WireGuard interface in down state with the ownership
// alias. It fails if the name is taken.
func (n *Netlink) Create(name string, mtu int, alias string) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	la.MTU = mtu
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("create %s: kernel WireGuard is not available (%v); on Debian/Ubuntu it is part of the standard kernel, check `modprobe wireguard`", name, err)
		}
		return fmt.Errorf("create %s: %w", name, err)
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetAlias(l, alias); err != nil {
		_ = netlink.LinkDel(l)
		return fmt.Errorf("set alias on %s: %w", name, err)
	}
	return nil
}

// Delete removes an owned interface (its routes and peers go with it).
func (n *Netlink) Delete(name string) error {
	l, err := n.owned(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(l)
}

// SetDown sets an owned interface down.
func (n *Netlink) SetDown(name string) error {
	l, err := n.owned(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetDown(l)
}

// SetUp sets an owned interface up.
func (n *Netlink) SetUp(name string) error {
	l, err := n.owned(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

// SetMTU sets the MTU of an owned interface.
func (n *Netlink) SetMTU(name string, mtu int) error {
	l, err := n.owned(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(l, mtu)
}

// SetAlias rewrites the alias of an owned interface.
func (n *Netlink) SetAlias(name, alias string) error {
	l, err := n.owned(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetAlias(l, alias)
}

// SyncAddrs makes want the only address of the owned interface.
func (n *Netlink) SyncAddrs(name string, want netip.Prefix) error {
	l, err := n.owned(name)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	have := false
	for _, a := range addrs {
		p, ok := prefixOf(a.IPNet)
		if ok && p == want {
			have = true
			continue
		}
		if err := netlink.AddrDel(l, &a); err != nil {
			return fmt.Errorf("remove address %s from %s: %w", p, name, err)
		}
	}
	if have {
		return nil
	}
	return netlink.AddrAdd(l, &netlink.Addr{IPNet: ipnet(want)})
}

// SyncRoutes makes want the exact set of Meshly routes on the interface.
// Routes of other protocols are never touched.
func (n *Netlink) SyncRoutes(name string, want []Route) error {
	l, err := n.owned(name)
	if err != nil {
		return err
	}
	idx := l.Attrs().Index
	cur, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{LinkIndex: idx, Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	keep := map[Route]bool{}
	for _, r := range cur {
		if int(r.Protocol) != RouteProtocol {
			continue
		}
		dst, ok := prefixOf(r.Dst)
		src, _ := netip.AddrFromSlice(r.Src)
		rt := Route{Dst: dst, Src: src.Unmap()}
		if ok && containsRoute(want, rt) && !keep[rt] {
			keep[rt] = true
			continue
		}
		r := r
		if err := netlink.RouteDel(&r); err != nil {
			return fmt.Errorf("remove meshly route %s: %w", dst, err)
		}
	}
	for _, w := range want {
		if keep[w] {
			continue
		}
		rt := &netlink.Route{
			LinkIndex: idx,
			Dst:       ipnet(w.Dst),
			Src:       w.Src.AsSlice(),
			Scope:     netlink.SCOPE_LINK,
			Protocol:  netlink.RouteProtocol(RouteProtocol),
			Table:     unix.RT_TABLE_MAIN,
		}
		if err := netlink.RouteAdd(rt); err != nil {
			return fmt.Errorf("add route %s dev %s: %w", w.Dst, name, err)
		}
	}
	return nil
}

func containsRoute(rs []Route, r Route) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// ApplySysctls writes the per-interface sysctls. IPv6 keys are skipped
// when IPv6 is not available.
func (n *Netlink) ApplySysctls(name string) error {
	if err := model.ValidateInterfaceName(name); err != nil {
		return err
	}
	for _, s := range Sysctls {
		p := filepath.Join(n.ProcSys, fmt.Sprintf(s.Path, name))
		if strings.Contains(s.Path, "ipv6") {
			if _, err := os.Stat(p); err != nil {
				continue
			}
		}
		if err := os.WriteFile(p, []byte(s.Value), 0o644); err != nil {
			return fmt.Errorf("sysctl %s: %w", p, err)
		}
	}
	return nil
}

// SysctlsOK reports per-interface sysctls that differ from Meshly's values.
func (n *Netlink) SysctlsOK(name string) []string {
	var bad []string
	for _, s := range Sysctls {
		p := filepath.Join(n.ProcSys, fmt.Sprintf(s.Path, name))
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) != s.Value {
			bad = append(bad, fmt.Sprintf(s.Path, name)+"="+strings.TrimSpace(string(b)))
		}
	}
	return bad
}

// UsedPrefixes lists addresses and routes (all tables) that do not belong
// to the excluded interface, for CIDR conflict detection.
func (n *Netlink) UsedPrefixes(exclude string) ([]model.UsedPrefix, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	excludedIdx := -1
	for _, l := range links {
		names[l.Attrs().Index] = l.Attrs().Name
		if l.Attrs().Name == exclude && l.Type() == "wireguard" && IsOwnedAlias(l.Attrs().Alias) {
			excludedIdx = l.Attrs().Index
		}
	}
	var out []model.UsedPrefix
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if a.LinkIndex == excludedIdx {
			continue
		}
		if p, ok := prefixOf(a.IPNet); ok {
			out = append(out, model.UsedPrefix{Prefix: p.Masked(), Source: "address " + p.String() + " on " + names[a.LinkIndex]})
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.LinkIndex == excludedIdx && excludedIdx >= 0 {
			continue
		}
		if r.Table == unix.RT_TABLE_LOCAL {
			continue // local/broadcast entries mirror addresses
		}
		p, ok := prefixOf(r.Dst)
		if !ok {
			continue // default route
		}
		src := "route " + p.String()
		if dev := names[r.LinkIndex]; dev != "" {
			src += " dev " + dev
		}
		if r.Table != unix.RT_TABLE_MAIN {
			src += fmt.Sprintf(" table %d", r.Table)
		}
		out = append(out, model.UsedPrefix{Prefix: p, Source: src})
	}
	return out, nil
}

// LocalAddrs returns all unicast addresses of the host.
func (n *Netlink) LocalAddrs() ([]netip.Addr, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, ok := prefixOf(a.IPNet); ok {
			out = append(out, p.Addr())
		}
	}
	return out, nil
}

// DefaultRouteAddrs returns the IPv4 addresses of the interfaces that carry
// an IPv4 default route in the main table. It only reads the kernel state.
func (n *Netlink) DefaultRouteAddrs() ([]model.LinkAddr, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	var idx []int
	for _, r := range routes {
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		idx = append(idx, r.LinkIndex)
		for _, nh := range r.MultiPath {
			idx = append(idx, nh.LinkIndex)
		}
	}
	var out []model.LinkAddr
	for _, i := range idx {
		if i <= 0 {
			continue
		}
		l, err := netlink.LinkByIndex(i)
		if err != nil {
			return nil, fmt.Errorf("read link %d: %w", i, err)
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("list addresses of %s: %w", l.Attrs().Name, err)
		}
		for _, a := range addrs {
			if p, ok := prefixOf(a.IPNet); ok && a.Scope == int(netlink.SCOPE_UNIVERSE) {
				out = append(out, model.LinkAddr{Addr: p.Addr(), Link: l.Attrs().Name})
			}
		}
	}
	return out, nil
}

// LinkExists reports whether any link (of any type) has the name, and
// whether it is owned by Meshly.
func (n *Netlink) LinkExists(name string) (exists, owned bool, kind string, err error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return false, false, "", nil
		}
		return false, false, "", err
	}
	return true, l.Type() == "wireguard" && IsOwnedAlias(l.Attrs().Alias), l.Type(), nil
}
