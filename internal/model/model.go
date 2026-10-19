// Package model defines the declarative Meshly configuration (networks,
// nodes, peers, access rules) together with strict validation of every
// field that may later be rendered into kernel objects or firewall rules.
package model

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConfigSchemaVersion is the only supported on-disk config schema.
const ConfigSchemaVersion = 1

// Defaults.
const (
	DefaultInterface    = "meshly0"
	DefaultMTU          = 1420
	DefaultListenPort   = 51820
	DefaultKeepalive    = 25
	DefaultFirewallMark = uint32(0x10000000)
	DefaultCIDR         = "10.100.0.0/24"
)

// AdminState is the administrator's intent for the link.
type AdminState string

const (
	AdminUp   AdminState = "up"
	AdminDown AdminState = "down"
)

// Firewall profiles.
const (
	ProfileNone     = "none"
	ProfileNftables = "nftables"
)

// Config is the desired configuration of this node. It never contains
// secrets: private keys live in separate files (see package store).
type Config struct {
	SchemaVersion int        `json:"schema_version"`
	Revision      uint64     `json:"revision"`
	UpdatedAt     time.Time  `json:"updated_at"`
	AdminState    AdminState `json:"admin_state"`
	Network       Network    `json:"network"`
	Self          Self       `json:"self"`
	Interface     Interface  `json:"interface"`
	Firewall      Firewall   `json:"firewall"`
	Peers         []Peer     `json:"peers"`
	Rules         []Rule     `json:"rules"`
}

// Network describes the VPN network shared by its nodes.
type Network struct {
	ID   string       `json:"id"`
	Name string       `json:"name"`
	CIDR netip.Prefix `json:"cidr"`
}

// Self describes the local node.
type Self struct {
	Name        string         `json:"name"`
	Address     netip.Addr     `json:"address"`
	ListenPort  uint16         `json:"listen_port"`
	Endpoint    netip.AddrPort `json:"endpoint,omitzero"`
	WGPublicKey string         `json:"wg_public_key"`
}

// Interface holds settings of the managed WireGuard interface.
type Interface struct {
	Name string `json:"name"`
	MTU  int    `json:"mtu"`
}

// Firewall holds firewall integration settings.
type Firewall struct {
	Profile string `json:"profile"`
	Mark    uint32 `json:"mark"`
}

// Peer is a remote node paired through an invite code.
type Peer struct {
	Name        string         `json:"name"`
	Address     netip.Addr     `json:"address"`
	WGPublicKey string         `json:"wg_public_key"`
	Endpoint    netip.AddrPort `json:"endpoint,omitzero"`
	Keepalive   int            `json:"keepalive"`
	AddedAt     time.Time      `json:"added_at"`
}

// Clone returns a deep copy of the config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	n := *c
	n.Peers = slices.Clone(c.Peers)
	n.Rules = slices.Clone(c.Rules)
	return &n
}

// Peer returns the peer with the given name.
func (c *Config) Peer(name string) (*Peer, bool) {
	for i := range c.Peers {
		if c.Peers[i].Name == name {
			return &c.Peers[i], true
		}
	}
	return nil, false
}

// NextAddress returns the lowest host address of the network that neither
// this node nor a peer has: the address of the next node to join. An
// address freed by a revoke is given out again. ok is false when the
// network is full.
func (c *Config) NextAddress() (a netip.Addr, ok bool) {
	used := map[netip.Addr]bool{c.Self.Address: true}
	for _, p := range c.Peers {
		used[p.Address] = true
	}
	cidr := c.Network.CIDR.Masked()
	for a = cidr.Addr().Next(); cidr.Contains(a); a = a.Next() {
		if !used[a] && ValidateHostAddress(cidr, a) == nil {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// RulesFor returns the rules referencing the peer.
func (c *Config) RulesFor(peer string) []Rule {
	var out []Rule
	for _, r := range c.Rules {
		if r.Peer == peer {
			out = append(out, r)
		}
	}
	return out
}

// Validate checks the internal consistency of a config. It is called on
// every load and before every save, so a corrupted or hand-edited file can
// never be turned into kernel state.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf("unsupported config schema_version %d (this meshly supports %d)", c.SchemaVersion, ConfigSchemaVersion)
	}
	if c.AdminState != AdminUp && c.AdminState != AdminDown {
		add("admin_state must be %q or %q", AdminUp, AdminDown)
	}
	if err := ValidateNetworkID(c.Network.ID); err != nil {
		add("network.id: %v", err)
	}
	if err := ValidateName(c.Network.Name); err != nil {
		add("network.name: %v", err)
	}
	if err := ValidateCIDR(c.Network.CIDR); err != nil {
		add("network.cidr: %v", err)
	}
	if err := ValidateName(c.Self.Name); err != nil {
		add("self.name: %v", err)
	}
	if err := ValidateHostAddress(c.Network.CIDR, c.Self.Address); err != nil {
		add("self.address: %v", err)
	}
	if err := ValidatePort(int(c.Self.ListenPort)); err != nil {
		add("self.listen_port: %v", err)
	}
	if c.Self.Endpoint.IsValid() {
		if err := ValidateEndpoint(c.Self.Endpoint); err != nil {
			add("self.endpoint: %v", err)
		}
	}
	if err := ValidateWGPublicKey(c.Self.WGPublicKey); err != nil {
		add("self.wg_public_key: %v", err)
	}
	if err := ValidateInterfaceName(c.Interface.Name); err != nil {
		add("interface.name: %v", err)
	}
	if err := ValidateMTU(c.Interface.MTU); err != nil {
		add("interface.mtu: %v", err)
	}
	if c.Firewall.Profile != ProfileNone && c.Firewall.Profile != ProfileNftables {
		add("firewall.profile must be %q or %q", ProfileNone, ProfileNftables)
	}
	if err := ValidateMark(c.Firewall.Mark); err != nil {
		add("firewall.mark: %v", err)
	}
	names := map[string]bool{c.Self.Name: true}
	addrs := map[netip.Addr]bool{c.Self.Address: true}
	keys := map[string]bool{c.Self.WGPublicKey: true}
	for i, p := range c.Peers {
		if err := ValidateName(p.Name); err != nil {
			add("peers[%d].name: %v", i, err)
		} else if names[p.Name] {
			add("peers[%d].name %q is not unique", i, p.Name)
		}
		names[p.Name] = true
		if err := ValidateHostAddress(c.Network.CIDR, p.Address); err != nil {
			add("peers[%d].address: %v", i, err)
		} else if addrs[p.Address] {
			add("peers[%d].address %s is not unique", i, p.Address)
		}
		addrs[p.Address] = true
		if err := ValidateWGPublicKey(p.WGPublicKey); err != nil {
			add("peers[%d].wg_public_key: %v", i, err)
		} else if keys[p.WGPublicKey] {
			add("peers[%d].wg_public_key is not unique", i)
		}
		keys[p.WGPublicKey] = true
		if p.Endpoint.IsValid() {
			if err := ValidateEndpoint(p.Endpoint); err != nil {
				add("peers[%d].endpoint: %v", i, err)
			}
		}
		if err := ValidateKeepalive(p.Keepalive); err != nil {
			add("peers[%d].keepalive: %v", i, err)
		}
	}
	seen := map[Rule]bool{}
	for i, r := range c.Rules {
		if err := r.Validate(); err != nil {
			add("rules[%d]: %v", i, err)
			continue
		}
		if _, ok := c.Peer(r.Peer); !ok {
			add("rules[%d] references unknown peer %q", i, r.Peer)
		}
		if seen[r] {
			add("rules[%d] duplicates %q", i, r.String())
		}
		seen[r] = true
	}
	return errors.Join(errs...)
}

// ParseWGPublicKey parses a base64 WireGuard public key.
func ParseWGPublicKey(s string) (wgtypes.Key, error) {
	if err := ValidateWGPublicKey(s); err != nil {
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(s)
}
