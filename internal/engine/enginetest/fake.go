// Package enginetest provides an in-memory kernel (links, WireGuard,
// nftables, Docker bridges and policy routing) for unit tests of the
// engine and the CLI.
package enginetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

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
	// Iptables are built-in chains of iptables-nft filter tables.
	Iptables []*IptablesChain
	handle   int
	// Docker are the Docker bridges of the node.
	Docker []netstack.Bridge
	// Forward is the forwarding sysctl per interface.
	Forward map[string]bool
	// Routing is meshly's policy routing; Foreign is kept by a sync.
	Routing netstack.DockerRouting
	// dockerIfs are the elements of set docker_ifs of the meshly table.
	dockerIfs []string
}

// IptablesChain is a built-in chain of table "ip filter" or "ip6 filter"
// as iptables-nft creates it.
type IptablesChain struct {
	Family, Chain, Policy string
	Rules                 []IptablesRule
}

// IptablesRule is a rule of an IptablesChain: meshly's when Comment is
// set, otherwise a foreign jump to a UFW chain.
type IptablesRule struct {
	Handle  int
	Comment string
	Mark    uint32
}

// AddIptables adds a chain with n foreign rules, as UFW leaves INPUT and
// OUTPUT.
func (k *Kernel) AddIptables(family, chain, policy string, n int) *IptablesChain {
	k.mu.Lock()
	defer k.mu.Unlock()
	c := &IptablesChain{Family: family, Chain: chain, Policy: policy}
	for range n {
		k.handle++
		c.Rules = append(c.Rules, IptablesRule{Handle: k.handle})
	}
	k.Iptables = append(k.Iptables, c)
	return c
}

// IptablesRules returns a copy of the rules of a chain.
func (k *Kernel) IptablesRules(family, chain string) []IptablesRule {
	k.mu.Lock()
	defer k.mu.Unlock()
	if c := k.iptablesChain(family, chain); c != nil {
		return slices.Clone(c.Rules)
	}
	return nil
}

// SetIptablesRules replaces the rules of a chain, as iptables-restore
// would.
func (k *Kernel) SetIptablesRules(family, chain string, rules []IptablesRule) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if c := k.iptablesChain(family, chain); c != nil {
		c.Rules = slices.Clone(rules)
	}
}

func (k *Kernel) iptablesChain(family, chain string) *IptablesChain {
	for _, c := range k.Iptables {
		if c.Family == family && c.Chain == chain {
			return c
		}
	}
	return nil
}

// New returns an empty kernel.
func New() *Kernel {
	return &Kernel{
		Links: map[string]*netstack.Link{}, Sysctl: map[string][]string{}, Devs: map[string]*wg.Device{}, psks: map[string]wgtypes.Key{},
		Forward: map[string]bool{}, failOn: map[string]int{}, after: map[string]int{}, cascade: map[string]string{}, Version: "nftables v1.0.6 (Lester Gooch #5)",
	}
}

// Fail makes the next n calls of op fail (n < 0: always). Ops are
// link.create, link.delete, link.up, link.down, link.mtu, link.alias,
// link.address, routes.sync, link.sysctl, docker.routing,
// wireguard.configure, nft.check, nft.apply, iptables.check,
// iptables.apply.
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
	f.k.Sysctl[name] = []string{"rp_filter"}
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
	delete(f.k.Forward, name)
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

func (f *Links) ApplySysctls(n string, forwarding bool) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if err := f.k.call("link.sysctl"); err != nil {
		return err
	}
	f.k.Sysctl[n] = nil
	f.k.Forward[n] = forwarding
	return nil
}

func (f *Links) Forwarding(n string) (bool, error) {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	return f.k.Forward[n], nil
}

func (f *Links) DockerBridges() ([]netstack.Bridge, error) {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	var out []netstack.Bridge
	for _, b := range f.k.Docker {
		out = append(out, netstack.Bridge{Name: b.Name, Prefixes: slices.Clone(b.Prefixes)})
	}
	return out, nil
}

func (f *Links) ObserveDockerRouting() (netstack.DockerRouting, error) {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	r := f.k.Routing
	return netstack.DockerRouting{Rules: slices.Clone(r.Rules), Routes: slices.Clone(r.Routes), Foreign: r.Foreign}, nil
}

func (f *Links) SyncDockerRouting(want netstack.DockerRouting) error {
	f.k.mu.Lock()
	defer f.k.mu.Unlock()
	if err := f.k.call("docker.routing"); err != nil {
		return err
	}
	f.k.Routing = netstack.DockerRouting{Rules: slices.Clone(want.Rules), Routes: slices.Clone(want.Routes), Foreign: f.k.Routing.Foreign}
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

// Handshake records a completed WireGuard handshake with peer on device
// dev at the given time, as authenticated traffic would.
func (k *Kernel) Handshake(dev, peer string, at time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if d := k.Devs[dev]; d != nil {
		for i := range d.Peers {
			if d.Peers[i].PublicKey == peer {
				d.Peers[i].LastHandshake = at
			}
		}
	}
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
		if old, ok := d.Peer(p.PublicKey); ok {
			// Like the kernel, a peer updated in place keeps its last
			// handshake, even across a new private or preshared key.
			ps.LastHandshake = old.LastHandshake
			if !p.Endpoint.IsValid() {
				ps.Endpoint = old.Endpoint
			}
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

var (
	markerRe    = regexp.MustCompile(`meshly:v1 net=[0-9a-f]+ hash=[0-9a-f]+`)
	dockerIfsRe = regexp.MustCompile(`set docker_ifs \{\s*type ifname\s*elements = \{ ([^}]*) \}`)
)

func (r runner) Run(_ context.Context, stdin string, args ...string) ([]byte, error) {
	k := r.k
	k.mu.Lock()
	defer k.mu.Unlock()
	switch strings.Join(args, " ") {
	case "--version":
		return []byte(k.Version + "\n"), nil
	case "-c -f -":
		if strings.Contains(stdin, "flush ruleset") {
			return nil, errors.New("meshly must never flush the ruleset")
		}
		if isIptablesScript(stdin) {
			if err := k.call("iptables.check"); err != nil {
				return nil, err
			}
			return nil, k.iptablesScript(stdin, true)
		}
		if err := k.call("nft.check"); err != nil {
			return nil, err
		}
		return nil, nil
	case "-f -":
		if isIptablesScript(stdin) {
			if err := k.call("iptables.apply"); err != nil {
				return nil, err
			}
			k.Scripts = append(k.Scripts, stdin)
			return nil, k.iptablesScript(stdin, false)
		}
		if err := k.call("nft.apply"); err != nil {
			return nil, err
		}
		k.Scripts = append(k.Scripts, stdin)
		k.dockerIfs = nil
		if stdin == nft.DeleteScript {
			k.Table, k.Tamper = "", false
			return nil, nil
		}
		k.Table, k.Tamper = markerRe.FindString(stdin), false
		if m := dockerIfsRe.FindStringSubmatch(stdin); m != nil {
			for _, e := range strings.Split(m[1], ", ") {
				k.dockerIfs = append(k.dockerIfs, strings.Trim(e, `"`))
			}
		}
		return nil, nil
	case "-j list ruleset":
		return []byte(k.rulesetJSON()), nil
	}
	return nil, fmt.Errorf("fake nft: unsupported arguments %q", args)
}

func isIptablesScript(s string) bool {
	return strings.HasPrefix(s, "insert rule ") || strings.HasPrefix(s, "delete rule ")
}

var (
	iptDeleteRe = regexp.MustCompile(`^delete rule (ip6?) filter (INPUT|OUTPUT|FORWARD) handle (\d+)$`)
	iptInsertRe = regexp.MustCompile(`^insert rule (ip6?) filter (INPUT|OUTPUT|FORWARD) meta mark & 0x([0-9a-f]{8}) == 0x([0-9a-f]{8}) counter accept comment "([^"]+)"$`)
)

// iptablesScript applies (or with check only validates) a script of
// meshly's iptables statements, all or nothing.
func (k *Kernel) iptablesScript(script string, check bool) error {
	chains := map[*IptablesChain][]IptablesRule{}
	rules := func(c *IptablesChain) []IptablesRule {
		if r, ok := chains[c]; ok {
			return r
		}
		return slices.Clone(c.Rules)
	}
	handle := k.handle
	for _, line := range strings.Split(strings.TrimSuffix(script, "\n"), "\n") {
		if m := iptDeleteRe.FindStringSubmatch(line); m != nil {
			c := k.iptablesChain(m[1], m[2])
			if c == nil {
				return fmt.Errorf("fake nft: no chain %s filter %s", m[1], m[2])
			}
			var h int
			fmt.Sscan(m[3], &h)
			rs := rules(c)
			i := slices.IndexFunc(rs, func(r IptablesRule) bool { return r.Handle == h })
			if i < 0 {
				return fmt.Errorf("fake nft: no rule with handle %d in %s filter %s", h, m[1], m[2])
			}
			chains[c] = slices.Delete(rs, i, i+1)
			continue
		}
		m := iptInsertRe.FindStringSubmatch(line)
		if m == nil || m[3] != m[4] {
			return fmt.Errorf("fake nft: unexpected statement %q", line)
		}
		c := k.iptablesChain(m[1], m[2])
		if c == nil {
			return fmt.Errorf("fake nft: no chain %s filter %s", m[1], m[2])
		}
		var mark uint32
		fmt.Sscanf(m[3], "%x", &mark)
		handle++
		chains[c] = append([]IptablesRule{{Handle: handle, Comment: m[5], Mark: mark}}, rules(c)...)
	}
	if check {
		return nil
	}
	k.handle = handle
	for c, rs := range chains {
		c.Rules = rs
	}
	return nil
}

func (k *Kernel) rulesetJSON() string {
	objs := []string{`{"metainfo":{"json_schema_version":1}}`}
	tables := map[string]bool{}
	for _, c := range k.Iptables {
		if !tables[c.Family] {
			tables[c.Family] = true
			objs = append(objs, fmt.Sprintf(`{"table":{"family":%q,"name":"filter","handle":100}}`, c.Family))
		}
		hook := strings.ToLower(c.Chain)
		objs = append(objs, fmt.Sprintf(`{"chain":{"family":%q,"table":"filter","name":%q,"handle":101,"type":"filter","hook":%q,"prio":0,"policy":%q}}`, c.Family, c.Chain, hook, c.Policy))
		for _, r := range c.Rules {
			if r.Comment == "" {
				objs = append(objs, fmt.Sprintf(`{"rule":{"family":%q,"table":"filter","chain":%q,"handle":%d,"expr":[{"counter":{"packets":0,"bytes":0}},{"jump":{"target":"ufw-before-%s"}}]}}`, c.Family, c.Chain, r.Handle, hook))
				continue
			}
			objs = append(objs, fmt.Sprintf(`{"rule":{"family":%q,"table":"filter","chain":%q,"handle":%d,"comment":%q,"expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},%d]},"right":%d}},{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}`, c.Family, c.Chain, r.Handle, r.Comment, r.Mark, r.Mark))
		}
	}
	if k.Table != "" || k.Foreign {
		objs = append(objs, `{"table":{"family":"inet","name":"meshly","handle":1}}`,
			`{"chain":{"family":"inet","table":"meshly","name":"guard_pre","handle":2,"type":"filter","hook":"prerouting","prio":-180,"policy":"accept"}}`)
	}
	if k.Table != "" {
		objs = append(objs, fmt.Sprintf(`{"rule":{"family":"inet","table":"meshly","chain":"guard_pre","handle":3,"comment":%q,"expr":[{"accept":null}]}}`, k.Table))
	}
	if k.Table != "" && len(k.dockerIfs) > 0 {
		elem, _ := json.Marshal(k.dockerIfs)
		objs = append(objs, fmt.Sprintf(`{"set":{"family":"inet","table":"meshly","name":"docker_ifs","handle":4,"type":"ifname","elem":%s}}`, elem))
	}
	if k.Tamper {
		objs = append(objs, `{"rule":{"family":"inet","table":"meshly","chain":"guard_pre","handle":9,"expr":[{"accept":null}]}}`)
	}
	return `{"nftables":[` + strings.Join(objs, ",") + `]}`
}
