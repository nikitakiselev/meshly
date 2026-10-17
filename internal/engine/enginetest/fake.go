// Package enginetest provides an in-memory kernel (links, WireGuard,
// nftables) for unit tests of the engine and the CLI.
package enginetest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/netstack"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Kernel is the shared fake state.
type Kernel struct {
	mu     sync.Mutex
	Links  map[string]*netstack.Link
	Sysctl map[string][]string
	Devs   map[string]*wg.Device
	// psks maps a peer public key to its preshared key.
	psks map[string]wgtypes.Key
	// Table is the marker comment of the meshly table ("" = absent).
	Table string
	// Tamper adds a rule to the meshly table (modified outside meshly).
	Tamper bool
	// Foreign is a table named inet meshly without a marker.
	Foreign bool
	// Scripts records every nft script applied.
	Scripts []string
	Calls   []string
	failOn  map[string]int
	after   map[string]int
	cascade map[string]string
	// Version is reported by `nft --version`.
	Version string
	// DefaultRoute lists the addresses of the interfaces with a default route.
	DefaultRoute []model.LinkAddr
}

// New returns an empty kernel.
func New() *Kernel {
	return &Kernel{
		Links: map[string]*netstack.Link{}, Sysctl: map[string][]string{}, Devs: map[string]*wg.Device{}, psks: map[string]wgtypes.Key{},
		failOn: map[string]int{}, after: map[string]int{}, cascade: map[string]string{}, Version: "nftables v1.0.6 (Lester Gooch #5)",
	}
}

// Fail makes the next n calls of op fail (n < 0: always). Ops are
// link.create, link.delete, link.up, link.down, link.mtu, link.alias,
// link.address, routes.sync, link.sysctl, wireguard.configure, nft.check,
// nft.apply.
func (k *Kernel) Fail(op string, n int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failOn[op] = n
}

// FailAfterEffect makes the next n calls of a link op perform their change
// and then report failure (n < 0: always): a partially applied step.
func (k *Kernel) FailAfterEffect(op string, n int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.after[op] = n
}

// Cascade makes op `then` fail permanently once op `when` has failed.
func (k *Kernel) Cascade(when, then string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cascade[when] = then
}

func (k *Kernel) call(op string) error {
	k.Calls = append(k.Calls, op)
	if n, ok := k.failOn[op]; ok && n != 0 {
		if n > 0 {
			k.failOn[op] = n - 1
		}
		if next, ok := k.cascade[op]; ok {
			k.failOn[next] = -1
		}
		return fmt.Errorf("fake %s failure", op)
	}
	return nil
}

// ---- links (engine.LinkOps and preflight.Links) ----

// LinkOps returns the link implementation.
func (k *Kernel) LinkOps() *Links { return &Links{k} }

type Links struct{ k *Kernel }

func (f *Links) Observe(name string) (netstack.Link, error) {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if l, ok := f.k.Links[name]; ok {
		c := *l
		c.Addrs = slices.Clone(l.Addrs)
		c.Routes = slices.Clone(l.Routes)
		return c, nil
	}
	return netstack.Link{}, nil
}

func (f *Links) Create(name string, mtu int, alias string) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if err := f.k.call("link.create"); err != nil {
		return err
	}
	f.k.Links[name] = &netstack.Link{Exists: true, Type: "wireguard", Alias: alias, MTU: mtu}
	f.k.Sysctl[name] = []string{"forwarding"}
	f.k.Devs[name] = &wg.Device{}
	return nil
}

func (f *Links) Delete(name string) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if err := f.k.call("link.delete"); err != nil {
		return err
	}
	delete(f.k.Links, name)
	if d := f.k.Devs[name]; d != nil {
		for _, p := range d.Peers {
			delete(f.k.psks, p.PublicKey)
		}
	}
	delete(f.k.Devs, name)
	return nil
}

func (f *Links) set(op, name string, fn func(*netstack.Link)) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if err := f.k.call(op); err != nil {
		return err
	}
	l, ok := f.k.Links[name]
	if !ok {
		return errors.New("no such link")
	}
	fn(l)
	if n, ok := f.k.after[op]; ok && n != 0 {
		if n > 0 {
			f.k.after[op] = n - 1
		}
		return fmt.Errorf("fake %s failure after the change", op)
	}
	return nil
}

func (f *Links) SetUp(n string) error {
	return f.set("link.up", n, func(l *netstack.Link) { l.Up = true })
}
func (f *Links) SetDown(n string) error {
	return f.set("link.down", n, func(l *netstack.Link) { l.Up = false })
}
func (f *Links) SetMTU(n string, m int) error {
	return f.set("link.mtu", n, func(l *netstack.Link) { l.MTU = m })
}
func (f *Links) SetAlias(n, a string) error {
	return f.set("link.alias", n, func(l *netstack.Link) { l.Alias = a })
}
func (f *Links) SyncAddrs(n string, p netip.Prefix) error {
	return f.set("link.address", n, func(l *netstack.Link) { l.Addrs = []netip.Prefix{p} })
}
func (f *Links) SyncRoutes(n string, r []netstack.Route) error {
	return f.set("routes.sync", n, func(l *netstack.Link) { l.Routes = slices.Clone(r) })
}

func (f *Links) ApplySysctls(n string) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if err := f.k.call("link.sysctl"); err != nil {
		return err
	}
	f.k.Sysctl[n] = nil
	return nil
}

func (f *Links) SysctlsOK(n string) []string {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	return slices.Clone(f.k.Sysctl[n])
}

func (f *Links) UsedPrefixes(exclude string) ([]model.UsedPrefix, error) {
	return []model.UsedPrefix{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Source: "address on eth0"}}, nil
}

func (f *Links) LocalAddrs() ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

func (f *Links) DefaultRouteAddrs() ([]model.LinkAddr, error) {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	return slices.Clone(f.k.DefaultRoute), nil
}

func (f *Links) LinkExists(name string) (exists, owned bool, kind string, err error) {
	l, _ := f.Observe(name)
	return l.Exists, l.Owned(), l.Type, nil
}

// PresharedKey returns the preshared key of the peer (zero when none).
func (k *Kernel) PresharedKey(peer string) wgtypes.Key {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.psks[peer]
}

// ---- WireGuard (engine.WGOps) ----

// WGOps returns the WireGuard implementation.
func (k *Kernel) WGOps() *WG { return &WG{k} }

type WG struct{ k *Kernel }

func (f *WG) Observe(name string) (*wg.Device, error) {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	d, ok := f.k.Devs[name]
	if !ok {
		return nil, nil
	}
	c := *d
	c.Peers = slices.Clone(d.Peers)
	return &c, nil
}

func (f *WG) Configure(name string, priv wgtypes.Key, port int, want []wg.DesiredPeer, _ *wg.Device) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if err := f.k.call("wireguard.configure"); err != nil {
		return err
	}
	d, ok := f.k.Devs[name]
	if !ok {
		return errors.New("no device")
	}
	d.PublicKey, d.ListenPort = priv.PublicKey().String(), port
	var peers []wg.PeerState
	for _, p := range want {
		ps := wg.PeerState{PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: []netip.Prefix{p.AllowedIP}, Keepalive: p.Keepalive}
		if old, ok := d.Peer(p.PublicKey); ok && !p.Endpoint.IsValid() {
			ps.Endpoint, ps.LastHandshake = old.Endpoint, old.LastHandshake
		}
		peers = append(peers, ps)
		if p.PresharedKey == (wgtypes.Key{}) {
			delete(f.k.psks, p.PublicKey)
		} else {
			f.k.psks[p.PublicKey] = p.PresharedKey
		}
	}
	for _, old := range d.Peers {
		if !slices.ContainsFunc(want, func(p wg.DesiredPeer) bool { return p.PublicKey == old.PublicKey }) {
			delete(f.k.psks, old.PublicKey)
		}
	}
	d.Peers = peers
	return nil
}

func (f *WG) RemoveAllPeers(name string) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if d, ok := f.k.Devs[name]; ok {
		for _, p := range d.Peers {
			delete(f.k.psks, p.PublicKey)
		}
		d.Peers = nil
	}
	return nil
}

// ---- nft (nft.Runner) ----

// NFT returns an nft client backed by the fake kernel.
func (k *Kernel) NFT() nft.Client { return nft.Client{R: runner{k}} }

type runner struct{ k *Kernel }

var markerRe = regexp.MustCompile(`meshly:v1 net=[0-9a-f]+ hash=[0-9a-f]+`)

func (r runner) Run(_ context.Context, stdin string, args ...string) ([]byte, error) {
	k := r.k
	k.mu.Lock()
	defer k.mu.Unlock()
	switch strings.Join(args, " ") {
	case "--version":
		return []byte(k.Version + "\n"), nil
	case "-c -f -":
		if err := k.call("nft.check"); err != nil {
			return nil, err
		}
		if strings.Contains(stdin, "flush ruleset") {
			return nil, errors.New("meshly must never flush the ruleset")
		}
		return nil, nil
	case "-f -":
		if err := k.call("nft.apply"); err != nil {
			return nil, err
		}
		k.Scripts = append(k.Scripts, stdin)
		if stdin == nft.DeleteScript {
			k.Table, k.Tamper = "", false
			return nil, nil
		}
		k.Table, k.Tamper = markerRe.FindString(stdin), false
		return nil, nil
	case "-j list ruleset":
		return []byte(k.rulesetJSON()), nil
	}
	return nil, fmt.Errorf("fake nft: unsupported arguments %q", args)
}

func (k *Kernel) rulesetJSON() string {
	objs := []string{`{"metainfo":{"json_schema_version":1}}`}
	if k.Table != "" || k.Foreign {
		objs = append(objs, `{"table":{"family":"inet","name":"meshly","handle":1}}`,
			`{"chain":{"family":"inet","table":"meshly","name":"guard_pre","handle":2,"type":"filter","hook":"prerouting","prio":-180,"policy":"accept"}}`)
	}
	if k.Table != "" {
		objs = append(objs, fmt.Sprintf(`{"rule":{"family":"inet","table":"meshly","chain":"guard_pre","handle":3,"comment":%q,"expr":[{"accept":null}]}}`, k.Table))
	}
	if k.Tamper {
		objs = append(objs, `{"rule":{"family":"inet","table":"meshly","chain":"guard_pre","handle":9,"expr":[{"accept":null}]}}`)
	}
	return `{"nftables":[` + strings.Join(objs, ",") + `]}`
}
