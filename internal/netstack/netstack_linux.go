//go:build linux

package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
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
	addrs, err := addrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return Link{}, fmt.Errorf("list addresses of %s: %w", name, err)
	}
	for _, a := range addrs {
		if p, ok := prefixOf(a.IPNet); ok {
			out.Addrs = append(out.Addrs, p)
		}
	}
	routes, err := routeList(&netlink.Route{LinkIndex: attrs.Index, Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
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

// dumpTries is how often a netlink dump is tried while changes interrupt
// it (netlink.ErrDumpInterrupted): links of containers come and go.
const dumpTries = 3

// dump runs a netlink dump again while it was interrupted, up to dumpTries
// times; its result is incomplete then.
func dump[T any](f func() ([]T, error)) ([]T, error) {
	var out []T
	var err error
	for range dumpTries {
		if out, err = f(); !errors.Is(err, netlink.ErrDumpInterrupted) {
			break
		}
	}
	return out, err
}

func linkList() ([]netlink.Link, error) { return dump(netlink.LinkList) }

func addrList(l netlink.Link, family int) ([]netlink.Addr, error) {
	return dump(func() ([]netlink.Addr, error) { return netlink.AddrList(l, family) })
}

func routeList(filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
	return dump(func() ([]netlink.Route, error) { return netlink.RouteListFiltered(netlink.FAMILY_V4, filter, mask) })
}

func ruleList() ([]netlink.Rule, error) {
	return dump(func() ([]netlink.Rule, error) { return netlink.RuleList(netlink.FAMILY_V4) })
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
	addrs, err := addrList(l, netlink.FAMILY_ALL)
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
	cur, err := routeList(&netlink.Route{LinkIndex: idx, Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
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

// ApplySysctls writes forwarding (on only while the node has Docker
// networks) and the per-interface sysctls. IPv6 keys are skipped when IPv6
// is not available.
func (n *Netlink) ApplySysctls(name string, forwarding bool) error {
	if err := model.ValidateInterfaceName(name); err != nil {
		return err
	}
	fwd := "0"
	if forwarding {
		fwd = "1"
	}
	p := filepath.Join(n.ProcSys, fmt.Sprintf(ForwardingSysctl, name))
	if err := os.WriteFile(p, []byte(fwd), 0o644); err != nil {
		return fmt.Errorf("sysctl %s: %w", p, err)
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

// SysctlsOK reports per-interface sysctls that differ from Meshly's values
// (forwarding aside: see Forwarding).
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
	links, err := linkList()
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
	addrs, err := addrList(nil, netlink.FAMILY_V4)
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
	routes, err := routeList(&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
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
	addrs, err := addrList(nil, netlink.FAMILY_ALL)
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
	routes, err := routeList(&netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
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
		addrs, err := addrList(l, netlink.FAMILY_V4)
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

// DockerBridges lists Docker bridges with their IPv4 subnets, by name.
func (n *Netlink) DockerBridges() ([]Bridge, error) {
	links, err := linkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	var out []Bridge
	for _, l := range links {
		attrs := l.Attrs()
		if !IsDockerBridge(attrs.Name, l.Type()) {
			continue
		}
		addrs, err := addrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("list addresses of %s: %w", attrs.Name, err)
		}
		b := Bridge{Name: attrs.Name, Down: attrs.Flags&net.FlagUp == 0}
		for _, a := range addrs {
			if p, ok := prefixOf(a.IPNet); ok && p.Addr().Is4() {
				b.Prefixes = append(b.Prefixes, p.Masked())
			}
		}
		sort.Slice(b.Prefixes, func(i, j int) bool {
			return b.Prefixes[i].Addr().Less(b.Prefixes[j].Addr()) ||
				b.Prefixes[i].Addr() == b.Prefixes[j].Addr() && b.Prefixes[i].Bits() < b.Prefixes[j].Bits()
		})
		b.Prefixes = slices.Compact(b.Prefixes)
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Forwarding reads the per-interface forwarding sysctl. A missing file
// (interface or IPv4 absent) counts as off.
func (n *Netlink) Forwarding(name string) (bool, error) {
	if err := model.ValidateInterfaceName(name); err != nil {
		return false, err
	}
	b, err := os.ReadFile(filepath.Join(n.ProcSys, fmt.Sprintf(ForwardingSysctl, name)))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read forwarding of %s: %w", name, err)
	}
	return strings.TrimSpace(string(b)) == "1", nil
}

func tablePrefix(r netlink.Route) (netip.Prefix, bool) {
	if r.Dst == nil {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	return prefixOf(r.Dst)
}

// ObserveDockerRouting reads Meshly's rules (RouteProtocol) and the routes
// of RouteTable; routes of another protocol are only counted.
func (n *Netlink) ObserveDockerRouting() (DockerRouting, error) {
	out, _, err := n.dockerRouting()
	return out, err
}

// dockerRouting is ObserveDockerRouting plus the kernel's routes behind
// out.Routes, index for index.
func (n *Netlink) dockerRouting() (DockerRouting, []netlink.Route, error) {
	var out DockerRouting
	rules, err := ruleList()
	if err != nil {
		return out, nil, fmt.Errorf("list rules: %w", err)
	}
	for _, r := range rules {
		if int(r.Protocol) != RouteProtocol {
			continue
		}
		out.Rules = append(out.Rules, PolicyRule{Iif: r.IifName, Table: r.Table, Priority: r.Priority})
	}
	routes, err := routeList(&netlink.Route{Table: RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return out, nil, fmt.Errorf("list routes of table %d: %w", RouteTable, err)
	}
	var raw []netlink.Route
	out.Routes, raw, out.Foreign = tableRoutes(routes, func(i int) (string, error) {
		l, err := netlink.LinkByIndex(i)
		if err != nil {
			return "", err
		}
		return l.Attrs().Name, nil
	})
	return out, raw, nil
}

// tableRoutes converts the routes of RouteTable: Meshly's (RouteProtocol),
// with raw their kernel routes, and a count of the others. A route of
// Meshly's whose link went away during the dump has Dev ""; one through no
// link that is not unreachable is not of a kind Meshly creates and counts
// as foreign.
func tableRoutes(routes []netlink.Route, name func(index int) (string, error)) (out []TableRoute, raw []netlink.Route, foreign int) {
	for _, r := range routes {
		if int(r.Protocol) != RouteProtocol {
			foreign++
			continue
		}
		dst, ok := tablePrefix(r)
		if !ok {
			continue
		}
		tr := TableRoute{Dst: dst}
		switch {
		case r.Type == unix.RTN_UNREACHABLE:
		case r.LinkIndex <= 0:
			foreign++
			continue
		default:
			tr.Dev, _ = name(r.LinkIndex)
		}
		out = append(out, tr)
		raw = append(raw, r)
	}
	return out, raw, foreign
}

// SyncDockerRouting makes want the exact set of Meshly rules and routes
// of RouteTable. Objects of other protocols are never touched.
func (n *Netlink) SyncDockerRouting(want DockerRouting) error {
	have, raw, err := n.dockerRouting()
	if err != nil {
		return err
	}
	// Rules go before routes on removal and after them on addition, so the
	// rule never selects a half-built table.
	for _, r := range have.Rules {
		if slices.Contains(want.Rules, r) {
			continue
		}
		if err := netlink.RuleDel(policyRule(r)); err != nil {
			return fmt.Errorf("remove rule iif %s lookup %d: %w", r.Iif, r.Table, err)
		}
	}
	for i, r := range have.Routes {
		if slices.Contains(want.Routes, r) {
			continue
		}
		// Gone already: the routes of a removed link go with it.
		if err := netlink.RouteDel(&raw[i]); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove route %s from table %d: %w", r.Dst, RouteTable, err)
		}
	}
	for _, r := range want.Routes {
		if slices.Contains(have.Routes, r) {
			continue
		}
		nr, err := tableRoute(r)
		if err != nil {
			return err
		}
		if err := netlink.RouteAdd(nr); err != nil {
			return fmt.Errorf("add route %s to table %d: %w", r.Dst, RouteTable, err)
		}
	}
	for _, r := range want.Rules {
		if slices.Contains(have.Rules, r) {
			continue
		}
		if err := netlink.RuleAdd(policyRule(r)); err != nil {
			return fmt.Errorf("add rule iif %s lookup %d: %w", r.Iif, r.Table, err)
		}
	}
	return nil
}

func policyRule(r PolicyRule) *netlink.Rule {
	nr := netlink.NewRule()
	nr.Family = netlink.FAMILY_V4
	nr.IifName = r.Iif
	nr.Table = r.Table
	nr.Priority = r.Priority
	nr.Protocol = RouteProtocol
	return nr
}

func tableRoute(r TableRoute) (*netlink.Route, error) {
	nr := &netlink.Route{
		Dst:      ipnet(r.Dst),
		Protocol: netlink.RouteProtocol(RouteProtocol),
		Table:    RouteTable,
	}
	if r.Dev == "" {
		nr.Type = unix.RTN_UNREACHABLE
		return nr, nil
	}
	l, err := netlink.LinkByName(r.Dev)
	if err != nil {
		return nil, fmt.Errorf("link %s: %w", r.Dev, err)
	}
	nr.LinkIndex = l.Attrs().Index
	nr.Scope = netlink.SCOPE_LINK
	return nr, nil
}

// SubscribeChanges reports changes of the links (RTNLGRP_LINK) and of
// nftables (NFNLGRP_NFTABLES, which needs CAP_NET_ADMIN). A value on the
// channel means at least one change since the previous one was received.
// The channel is closed when ctx ends or a subscription fails.
func SubscribeChanges(ctx context.Context) (<-chan struct{}, error) {
	nfts, err := nl.Subscribe(unix.NETLINK_NETFILTER, unix.NFNLGRP_NFTABLES)
	if err != nil {
		return nil, fmt.Errorf("subscribe to nftables events: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	links := make(chan netlink.LinkUpdate)
	if err := netlink.LinkSubscribeWithOptions(links, ctx.Done(), netlink.LinkSubscribeOptions{}); err != nil {
		cancel()
		nfts.Close()
		return nil, fmt.Errorf("subscribe to link events: %w", err)
	}
	out := make(chan struct{}, 1)
	notify := func() {
		select {
		case out <- struct{}{}:
		default:
		}
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		defer cancel()
		// Drained until closed: the sender would block forever otherwise.
		for range links {
			notify()
		}
	})
	wg.Go(func() {
		defer cancel()
		for {
			_, _, err := nfts.Receive()
			switch {
			case errors.Is(err, unix.ENOBUFS):
				// The socket overran: the lost events were changes too.
				notify()
			case err != nil:
				return
			default:
				notify()
			}
		}
	})
	go func() {
		<-ctx.Done()
		nfts.Close()
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	return out, nil
}
