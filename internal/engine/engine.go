// Package engine turns a desired configuration into kernel state.
//
// It observes the OS (interface, WireGuard, routes, nftables), builds an
// ordered plan, applies it inside a journaled transaction, verifies the
// result and either commits, rolls back or enters safe mode. Ordering
// invariants:
//
//   - bring-up: firewall first, then interface, addresses, WireGuard
//     peers, link up, routes — protection exists before any traffic path;
//   - tear-down: traffic path first (interface with its peers and routes),
//     protective firewall table last.
package engine

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/netstack"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LinkOps manages the interface (implemented by netstack.Netlink).
type LinkOps interface {
	Observe(name string) (netstack.Link, error)
	Create(name string, mtu int, alias string) error
	Delete(name string) error
	SetUp(name string) error
	SetDown(name string) error
	SetMTU(name string, mtu int) error
	SetAlias(name, alias string) error
	SyncAddrs(name string, want netip.Prefix) error
	SyncRoutes(name string, want []netstack.Route) error
	ApplySysctls(name string) error
	SysctlsOK(name string) []string
}

// WGOps manages WireGuard (implemented by wg.Kernel).
type WGOps interface {
	Observe(name string) (*wg.Device, error)
	Configure(name string, priv wgtypes.Key, listenPort int, want []wg.DesiredPeer, current *wg.Device) error
	RemoveAllPeers(name string) error
}

// FirewallOps manages nftables (implemented by nft.Client).
type FirewallOps interface {
	ListRuleset(ctx context.Context) (*nft.Ruleset, error)
	Check(ctx context.Context, script string) error
	ApplyScript(ctx context.Context, script string) error
}

// ErrConflict means an object with Meshly's name exists but is not owned
// by Meshly. Nothing is changed.
var ErrConflict = errors.New("ownership conflict")

// Desired is the kernel state derived from a config.
type Desired struct {
	Present    bool
	Config     *model.Config
	Interface  string
	Alias      string
	MTU        int
	Address    netip.Prefix
	ListenPort int
	WGPublic   string
	Peers      []wg.DesiredPeer
	Routes     []netstack.Route
	Firewall   nft.Rendered
}

// DesiredFrom derives desired state; a nil config or admin state "down"
// means nothing may exist. ifname names the interface to tear down when
// the config is nil.
func DesiredFrom(cfg *model.Config, ifname string) (*Desired, error) {
	if cfg == nil {
		if ifname == "" {
			ifname = model.DefaultInterface
		}
		return &Desired{Interface: ifname}, nil
	}
	d := &Desired{Config: cfg, Interface: cfg.Interface.Name}
	if cfg.AdminState != model.AdminUp {
		return d, nil
	}
	d.Present = true
	d.Alias = netstack.Alias(cfg.Network.ID)
	d.MTU = cfg.Interface.MTU
	d.Address = netip.PrefixFrom(cfg.Self.Address, 32)
	d.ListenPort = int(cfg.Self.ListenPort)
	d.WGPublic = cfg.Self.WGPublicKey
	for _, p := range cfg.Peers {
		d.Peers = append(d.Peers, wg.DesiredPeer{
			PublicKey: p.WGPublicKey,
			Endpoint:  p.Endpoint,
			AllowedIP: netip.PrefixFrom(p.Address, 32),
			Keepalive: p.Keepalive,
		})
		d.Routes = append(d.Routes, netstack.Route{Dst: netip.PrefixFrom(p.Address, 32), Src: cfg.Self.Address})
	}
	r, err := nft.Render(nft.InputFromConfig(cfg, false))
	if err != nil {
		return nil, err
	}
	d.Firewall = r
	return d, nil
}

// Observed is the relevant kernel state.
type Observed struct {
	Link         netstack.Link
	WG           *wg.Device
	SysctlIssues []string
	Ruleset      *nft.Ruleset
	TablePresent bool
	TableOwned   bool
	MarkerHash   string
	LiveHash     string
	RecordedHash string
}

// Engine executes plans.
type Engine struct {
	Links    LinkOps
	WG       WGOps
	FW       FirewallOps
	Paths    store.Paths
	LoadKeys func() (*store.Keys, error)
	Now      func() time.Time
	// Progress receives human readable progress lines (may be nil).
	Progress func(string)
}

func (e *Engine) progress(format string, a ...any) {
	if e.Progress != nil {
		e.Progress(fmt.Sprintf(format, a...))
	}
}

// Observe reads the kernel state relevant for interface ifname.
func (e *Engine) Observe(ctx context.Context, ifname string) (*Observed, error) {
	o := &Observed{}
	l, err := e.Links.Observe(ifname)
	if err != nil {
		return nil, err
	}
	o.Link = l
	if l.Exists && l.Type == "wireguard" {
		if o.WG, err = e.WG.Observe(ifname); err != nil {
			return nil, err
		}
		o.SysctlIssues = e.Links.SysctlsOK(ifname)
	}
	rs, err := e.FW.ListRuleset(ctx)
	if err != nil {
		return nil, err
	}
	o.Ruleset = rs
	if t := rs.Table(nft.TableFamily, nft.TableName); t != nil {
		o.TablePresent = true
		_, o.MarkerHash, o.TableOwned = t.Marker()
		o.LiveHash = t.ContentHash()
	}
	if rt, err := e.Paths.LoadRuntime(); err == nil {
		o.RecordedHash = rt.FirewallLiveHash
	}
	return o, nil
}

// Step is one plan item.
type Step struct {
	Name string
	Desc string
	run  func(ctx context.Context) error
}

// Plan computes the ordered steps to move from o to d.
func (e *Engine) Plan(d *Desired, o *Observed) ([]Step, error) {
	if !d.Present {
		return e.planTeardown(d, o), nil
	}
	if o.Link.Exists && !o.Link.Owned() {
		return nil, fmt.Errorf("%w: interface %s already exists (type %s) and was not created by meshly; choose another name with --interface or remove it", ErrConflict, d.Interface, o.Link.Type)
	}
	if o.TablePresent && !o.TableOwned {
		return nil, fmt.Errorf("%w: nftables table inet %s exists but has no meshly ownership marker; rename or remove it", ErrConflict, nft.TableName)
	}
	var steps []Step
	name := d.Interface
	fwStale := !o.TablePresent || o.MarkerHash != d.Firewall.Hash || o.LiveHash != o.RecordedHash
	if fwStale {
		desc := "install firewall table inet meshly"
		switch {
		case o.TablePresent && o.MarkerHash == d.Firewall.Hash:
			desc = "restore firewall table inet meshly (modified outside meshly)"
		case o.TablePresent:
			desc = "replace firewall table inet meshly atomically"
		}
		fw := d.Firewall
		steps = append(steps, Step{Name: "firewall.apply", Desc: desc, run: func(ctx context.Context) error { return e.applyFirewall(ctx, fw) }})
	}
	created := !o.Link.Exists
	if created {
		steps = append(steps, Step{Name: "link.create", Desc: fmt.Sprintf("create WireGuard interface %s (down, mtu %d)", name, d.MTU), run: func(context.Context) error {
			return e.Links.Create(name, d.MTU, d.Alias)
		}})
	} else {
		if o.Link.Alias != d.Alias {
			steps = append(steps, Step{Name: "link.alias", Desc: "update ownership alias of " + name, run: func(context.Context) error { return e.Links.SetAlias(name, d.Alias) }})
		}
		if o.Link.MTU != d.MTU {
			steps = append(steps, Step{Name: "link.mtu", Desc: fmt.Sprintf("set mtu of %s to %d", name, d.MTU), run: func(context.Context) error { return e.Links.SetMTU(name, d.MTU) }})
		}
	}
	if created || len(o.SysctlIssues) > 0 {
		steps = append(steps, Step{Name: "link.sysctl", Desc: "set per-interface sysctls (no forwarding, strict rp_filter, no IPv6)", run: func(context.Context) error { return e.Links.ApplySysctls(name) }})
	}
	if created || !slices.Equal(o.Link.Addrs, []netip.Prefix{d.Address}) {
		steps = append(steps, Step{Name: "link.address", Desc: fmt.Sprintf("set address %s on %s", d.Address, name), run: func(context.Context) error { return e.Links.SyncAddrs(name, d.Address) }})
	}
	if created || wgDiffers(d, o.WG) {
		steps = append(steps, Step{Name: "wireguard.configure", Desc: wgDesc(d), run: func(context.Context) error { return e.configureWG(name, d) }})
	}
	if created || !o.Link.Up {
		steps = append(steps, Step{Name: "link.up", Desc: "set " + name + " up", run: func(context.Context) error { return e.Links.SetUp(name) }})
	}
	if (created && len(d.Routes) > 0) || (!created && !sameRoutes(o.Link.Routes, d.Routes)) {
		steps = append(steps, Step{Name: "routes.sync", Desc: routesDesc(name, d.Routes), run: func(context.Context) error { return e.Links.SyncRoutes(name, d.Routes) }})
	}
	return steps, nil
}

func (e *Engine) planTeardown(d *Desired, o *Observed) []Step {
	var steps []Step
	name := d.Interface
	if o.Link.Owned() {
		steps = append(steps, Step{Name: "link.down", Desc: "set " + name + " down (stop VPN traffic)", run: func(context.Context) error {
			e.RememberEndpoints(name)
			return e.Links.SetDown(name)
		}})
		steps = append(steps, Step{Name: "link.delete", Desc: "delete interface " + name + " with its peers and routes", run: func(context.Context) error { return e.Links.Delete(name) }})
	}
	if o.TablePresent && o.TableOwned {
		steps = append(steps, Step{Name: "firewall.remove", Desc: "remove firewall table inet meshly", run: func(ctx context.Context) error {
			if err := e.FW.ApplyScript(ctx, nft.DeleteScript); err != nil {
				return err
			}
			rt, err := e.Paths.LoadRuntime()
			if err != nil {
				rt = &store.Runtime{}
			}
			rt.FirewallLiveHash, rt.FirewallAppliedAt = "", time.Time{}
			return e.Paths.SaveRuntime(rt)
		}})
	}
	return steps
}

func (e *Engine) applyFirewall(ctx context.Context, fw nft.Rendered) error {
	script := fw.ApplyScript()
	if err := e.FW.Check(ctx, script); err != nil {
		return fmt.Errorf("kernel rejected the firewall ruleset (nothing applied): %w", err)
	}
	if err := e.FW.ApplyScript(ctx, script); err != nil {
		return err
	}
	rs, err := e.FW.ListRuleset(ctx)
	if err != nil {
		return err
	}
	t := rs.Table(nft.TableFamily, nft.TableName)
	if t == nil {
		return errors.New("firewall table missing right after apply")
	}
	if _, h, ok := t.Marker(); !ok || h != fw.Hash {
		return errors.New("firewall table content differs from what was applied")
	}
	rt, err := e.Paths.LoadRuntime()
	if err != nil {
		rt = &store.Runtime{}
	}
	rt.FirewallLiveHash, rt.FirewallAppliedAt = t.ContentHash(), e.Now()
	return e.Paths.SaveRuntime(rt)
}

func (e *Engine) configureWG(name string, d *Desired) error {
	keys, err := e.LoadKeys()
	if err != nil {
		return err
	}
	defer keys.Wipe()
	if keys.WGPublic() != d.WGPublic {
		return errors.New("WireGuard private key does not match the public key in the config; refusing to configure")
	}
	cur, err := e.WG.Observe(name)
	if err != nil {
		return err
	}
	peers := slices.Clone(d.Peers)
	if rt, err := e.Paths.LoadRuntime(); err == nil {
		for i, p := range peers {
			if p.Endpoint.IsValid() {
				continue
			}
			if cur != nil {
				if ps, ok := cur.Peer(p.PublicKey); ok && ps.Endpoint.IsValid() {
					continue // already known to the kernel
				}
			}
			if hint, err := netip.ParseAddrPort(rt.PeerEndpoints[p.PublicKey]); err == nil && hint.Addr().Is4() {
				peers[i].Endpoint = hint
			}
		}
	}
	return e.WG.Configure(name, keys.WG, d.ListenPort, peers, cur)
}

// RememberEndpoints records the endpoints the kernel learned for peers
// that completed a handshake recently (best effort, never fails).
func (e *Engine) RememberEndpoints(name string) {
	dev, err := e.WG.Observe(name)
	if err != nil || dev == nil {
		return
	}
	rt, err := e.Paths.LoadRuntime()
	if err != nil {
		return
	}
	learned := map[string]string{}
	for _, p := range dev.Peers {
		if p.Endpoint.IsValid() && !p.LastHandshake.IsZero() && e.Now().Sub(p.LastHandshake) < 10*time.Minute {
			learned[p.PublicKey] = p.Endpoint.String()
		}
	}
	if len(learned) == 0 || maps.Equal(learned, rt.PeerEndpoints) {
		return
	}
	rt.PeerEndpoints = learned
	_ = e.Paths.SaveRuntime(rt)
}

func wgDiffers(d *Desired, dev *wg.Device) bool {
	if dev == nil || dev.PublicKey != d.WGPublic || dev.ListenPort != d.ListenPort || len(dev.Peers) != len(d.Peers) {
		return true
	}
	for _, p := range d.Peers {
		ps, ok := dev.Peer(p.PublicKey)
		if !ok || ps.Keepalive != p.Keepalive || !slices.Equal(ps.AllowedIPs, []netip.Prefix{p.AllowedIP}) {
			return true
		}
		if p.Endpoint.IsValid() && ps.Endpoint != p.Endpoint {
			return true
		}
	}
	return false
}

func wgDesc(d *Desired) string {
	s := fmt.Sprintf("configure WireGuard: listen port %d, %d peer(s)", d.ListenPort, len(d.Peers))
	for _, p := range d.Peers {
		s += fmt.Sprintf("; peer allowed-ips %s", p.AllowedIP)
		if p.Endpoint.IsValid() {
			s += " endpoint " + p.Endpoint.String()
		}
		if p.Keepalive > 0 {
			s += fmt.Sprintf(" keepalive %ds", p.Keepalive)
		}
	}
	return s
}

func routesDesc(name string, rs []netstack.Route) string {
	if len(rs) == 0 {
		return "remove meshly routes on " + name
	}
	s := "set meshly routes on " + name + ":"
	for _, r := range rs {
		s += fmt.Sprintf(" %s src %s", r.Dst, r.Src)
	}
	return s
}

func sameRoutes(a, b []netstack.Route) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// run executes steps in order.
func (e *Engine) run(ctx context.Context, steps []Step, hook func(Step) error) error {
	for _, s := range steps {
		if hook != nil {
			if err := hook(s); err != nil {
				return fmt.Errorf("%s: %w", s.Name, err)
			}
		}
		e.progress("  - %s", s.Desc)
		if err := s.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	return nil
}

// Reconcile applies cfg without journaling (used inside transactions and
// recovery) and verifies the result.
func (e *Engine) Reconcile(ctx context.Context, cfg *model.Config, ifname string, hook func(Step) error) ([]Step, error) {
	d, err := DesiredFrom(cfg, ifname)
	if err != nil {
		return nil, err
	}
	o, err := e.Observe(ctx, d.Interface)
	if err != nil {
		return nil, err
	}
	steps, err := e.Plan(d, o)
	if err != nil {
		return nil, err
	}
	if err := e.run(ctx, steps, hook); err != nil {
		return steps, err
	}
	return steps, e.Verify(ctx, d)
}

// Verify checks local invariants: observing again must yield an empty
// plan. Connectivity to the peer is deliberately not part of this check.
func (e *Engine) Verify(ctx context.Context, d *Desired) error {
	o, err := e.Observe(ctx, d.Interface)
	if err != nil {
		return err
	}
	steps, err := e.Plan(d, o)
	if err != nil {
		return err
	}
	if len(steps) > 0 {
		var names []string
		for _, s := range steps {
			names = append(names, s.Name)
		}
		return fmt.Errorf("verification failed, still pending: %v", names)
	}
	return nil
}

// Drift describes differences between desired and observed state.
func (e *Engine) Drift(ctx context.Context, cfg *model.Config) ([]string, error) {
	d, err := DesiredFrom(cfg, "")
	if err != nil {
		return nil, err
	}
	o, err := e.Observe(ctx, d.Interface)
	if err != nil {
		return nil, err
	}
	steps, err := e.Plan(d, o)
	if err != nil {
		return []string{err.Error()}, nil
	}
	var out []string
	for _, s := range steps {
		out = append(out, s.Desc)
	}
	return out, nil
}

// SafeMode closes the VPN path without touching anything else: a lockdown
// firewall table (nothing allowed on the interface), then removal of the
// interface. Errors are collected; every step is attempted.
func (e *Engine) SafeMode(ctx context.Context, cfg *model.Config, ifname string) error {
	var errs []error
	if cfg != nil {
		if r, err := nft.Render(nft.InputFromConfig(cfg, true)); err == nil {
			o, oerr := e.Observe(ctx, cfg.Interface.Name)
			if oerr == nil && (!o.TablePresent || o.TableOwned) {
				if err := e.FW.ApplyScript(ctx, r.ApplyScript()); err != nil {
					errs = append(errs, fmt.Errorf("lockdown firewall: %w", err))
				}
			}
		}
		ifname = cfg.Interface.Name
	}
	if ifname == "" {
		ifname = model.DefaultInterface
	}
	if l, err := e.Links.Observe(ifname); err == nil && l.Owned() {
		if err := e.Links.Delete(ifname); err != nil {
			errs = append(errs, fmt.Errorf("delete interface: %w", err))
			if err := e.WG.RemoveAllPeers(ifname); err != nil {
				errs = append(errs, fmt.Errorf("remove peers: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}
