// Package diag builds `meshly status` and `meshly doctor` reports. Local
// configuration correctness and current connectivity are reported
// separately: a correct node may have no handshake because the peer is
// switched off.
package diag

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/lock"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/systemd"
)

// StatusSchema identifies the JSON layout of Status.
const StatusSchema = "meshly.status/v1"

// HandshakeFresh is how recent a handshake must be to call the link
// connected (WireGuard rekeys every 120 s while traffic flows).
const HandshakeFresh = 180 * time.Second

// Status is the machine readable status. It never contains secrets.
type Status struct {
	Schema      string           `json:"schema"`
	Initialized bool             `json:"initialized"`
	Privileged  bool             `json:"privileged"`
	Busy        bool             `json:"operation_in_progress"`
	Config      *ConfigInfo      `json:"config,omitempty"`
	Service     *ServiceInfo     `json:"service,omitempty"`
	Interface   *InterfaceInfo   `json:"interface,omitempty"`
	Firewall    *FirewallInfo    `json:"firewall,omitempty"`
	Peers       []PeerInfo       `json:"peers"`
	Transaction *TransactionInfo `json:"transaction"`
	Invite      *InviteInfo      `json:"invite,omitempty"`
	Drift       []string         `json:"drift"`
	Errors      []string         `json:"errors,omitempty"`
}

// InviteInfo is an open `meshly invite`. Only its expiry is ever shown.
type InviteInfo struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// OpenInvite reports the invite that waits for a node to join, or nil. It
// is open only for a privileged run (the marker is root's), while the marker
// is readable, the lock is held and the marker's time has not passed: the
// code's expiry, or the confirmation deadline of a node that joined.
func OpenInvite(d Deps) *InviteInfo {
	if !d.Privileged {
		return nil
	}
	m, err := d.Paths.LoadInviteMarker()
	if err != nil || !m.ExpiresAt.After(d.Now()) {
		return nil
	}
	if held, err := lock.Probe(d.Paths.LockFile()); err != nil || !held {
		return nil
	}
	return &InviteInfo{ExpiresAt: m.ExpiresAt}
}

// ConfigInfo is the saved desired configuration.
type ConfigInfo struct {
	Revision    uint64     `json:"revision"`
	UpdatedAt   time.Time  `json:"updated_at"`
	AdminState  string     `json:"admin_state"`
	NetworkID   string     `json:"network_id"`
	NetworkName string     `json:"network_name"`
	CIDR        string     `json:"cidr"`
	Name        string     `json:"name"`
	Address     string     `json:"address"`
	ListenPort  int        `json:"listen_port"`
	Endpoint    string     `json:"endpoint,omitempty"`
	WGPublicKey string     `json:"wg_public_key"`
	Interface   string     `json:"interface"`
	MTU         int        `json:"mtu"`
	Profile     string     `json:"firewall_profile"`
	Rules       []RuleInfo `json:"rules"`
}

// RuleInfo is one allow rule.
type RuleInfo struct {
	Peer    string `json:"peer"`
	Proto   string `json:"proto"`
	Port    int    `json:"port,omitempty"`
	Rule    string `json:"rule"`
	Meaning string `json:"meaning"`
}

// ServiceInfo is the systemd state (independent of connectivity).
type ServiceInfo struct {
	Systemd      bool   `json:"systemd"`
	Installed    bool   `json:"installed"`
	Active       string `json:"active"`
	Enabled      string `json:"enabled"`
	TimerActive  string `json:"check_timer_active"`
	TimerEnabled string `json:"check_timer_enabled"`
}

// InterfaceInfo is the observed interface.
type InterfaceInfo struct {
	Name            string   `json:"name"`
	Exists          bool     `json:"exists"`
	Owned           bool     `json:"owned"`
	Up              bool     `json:"up"`
	MTU             int      `json:"mtu"`
	Addresses       []string `json:"addresses"`
	ListenPort      int      `json:"listen_port"`
	KeyMatchesCfg   bool     `json:"public_key_matches_config"`
	ForeignRoutes   int      `json:"foreign_routes"`
	SysctlDeviation []string `json:"sysctl_deviations,omitempty"`
}

// FirewallInfo is the observed Meshly table.
type FirewallInfo struct {
	Profile         string    `json:"profile"`
	TablePresent    bool      `json:"table_present"`
	Owned           bool      `json:"owned"`
	MatchesConfig   bool      `json:"matches_config"`
	ModifiedOutside bool      `json:"modified_outside_meshly"`
	AppliedAt       time.Time `json:"applied_at,omitzero"`
	TransportPkts   *uint64   `json:"wireguard_udp_packets_received,omitempty"`
	DeniedPkts      *uint64   `json:"vpn_packets_denied,omitempty"`
}

// PeerInfo is one peer: configuration plus live WireGuard data.
type PeerInfo struct {
	Name               string     `json:"name"`
	Address            string     `json:"address"`
	WGPublicKey        string     `json:"wg_public_key"`
	ConfiguredEndpoint string     `json:"configured_endpoint,omitempty"`
	CurrentEndpoint    string     `json:"current_endpoint,omitempty"`
	Keepalive          int        `json:"keepalive"`
	InWireGuard        bool       `json:"in_wireguard"`
	AllowedIPsOK       bool       `json:"allowed_ips_ok"`
	RouteOK            bool       `json:"route_ok"`
	LastHandshake      *time.Time `json:"last_handshake,omitempty"`
	HandshakeAge       *int64     `json:"handshake_age_seconds,omitempty"`
	RxBytes            int64      `json:"rx_bytes"`
	TxBytes            int64      `json:"tx_bytes"`
	// Connectivity: "handshake-recent", "handshake-stale", "no-handshake",
	// "unknown" (not observable: interface down or not privileged).
	Connectivity string   `json:"connectivity"`
	AllowedFrom  []string `json:"services_it_may_use_here"`
}

// TransactionInfo describes the journal.
type TransactionInfo struct {
	Incomplete     bool      `json:"incomplete"`
	IncompleteOp   string    `json:"incomplete_op,omitempty"`
	IncompleteID   string    `json:"incomplete_op_id,omitempty"`
	IncompleteTime time.Time `json:"incomplete_started,omitzero"`
	LastOp         string    `json:"last_op,omitempty"`
	LastEvent      string    `json:"last_event,omitempty"`
	LastTime       time.Time `json:"last_time,omitzero"`
	LastDetail     string    `json:"last_detail,omitempty"`
}

// Deps are the collaborators of the reports.
type Deps struct {
	Paths      store.Paths
	Engine     *engine.Engine
	Journal    *journal.Journal
	Systemd    *systemd.Manager
	Privileged bool
	Now        func() time.Time
}

// RuleMeaning explains a rule in plain words.
func RuleMeaning(c *model.Config, r model.Rule) string {
	if r.Proto == model.ProtoPing {
		return fmt.Sprintf("peer %s may ping %s through the VPN", r.Peer, c.Self.Address)
	}
	return fmt.Sprintf("peer %s may open %s connections to %s:%d through the VPN only", r.Peer, r.Proto, c.Self.Address, r.Port)
}

// Collect gathers status.
func Collect(ctx context.Context, d Deps) *Status {
	st := &Status{Schema: StatusSchema, Privileged: d.Privileged, Peers: []PeerInfo{}, Drift: []string{}, Transaction: &TransactionInfo{}}
	if held, err := lock.Probe(d.Paths.LockFile()); err == nil {
		st.Busy = held
	}
	cfg, err := d.Paths.LoadConfig()
	switch {
	case errors.Is(err, store.ErrNotInitialized):
	case err != nil:
		st.Errors = append(st.Errors, "config: "+err.Error())
	default:
		st.Initialized = true
	}
	collectJournal(d, st)
	if d.Systemd != nil {
		si := &ServiceInfo{Systemd: d.Systemd.Available, Installed: d.Systemd.Installed()}
		si.Active, si.Enabled = d.Systemd.State(ctx, systemd.Unit)
		si.TimerActive, si.TimerEnabled = d.Systemd.State(ctx, systemd.TimerUnit)
		st.Service = si
	}
	if cfg == nil {
		return st
	}
	st.Config = configInfo(cfg)
	if !d.Privileged {
		st.Errors = append(st.Errors, "run as root to see WireGuard, firewall and drift details")
		for _, p := range cfg.Peers {
			st.Peers = append(st.Peers, basePeer(cfg, p))
		}
		return st
	}
	obs, err := d.Engine.Observe(ctx, cfg.Interface.Name)
	if err != nil {
		st.Errors = append(st.Errors, "observe: "+err.Error())
		return st
	}
	desired, err := engine.DesiredFrom(cfg, "")
	if err != nil {
		st.Errors = append(st.Errors, err.Error())
		return st
	}
	st.Interface = &InterfaceInfo{
		Name: cfg.Interface.Name, Exists: obs.Link.Exists, Owned: obs.Link.Owned(), Up: obs.Link.Up, MTU: obs.Link.MTU,
		Addresses: []string{}, ForeignRoutes: obs.Link.ForeignRoutes, SysctlDeviation: obs.SysctlIssues,
	}
	for _, a := range obs.Link.Addrs {
		st.Interface.Addresses = append(st.Interface.Addresses, a.String())
	}
	if obs.WG != nil {
		st.Interface.ListenPort = obs.WG.ListenPort
		st.Interface.KeyMatchesCfg = obs.WG.PublicKey == cfg.Self.WGPublicKey
	}
	fw := &FirewallInfo{Profile: cfg.Firewall.Profile, TablePresent: obs.TablePresent, Owned: obs.TableOwned}
	if desired.Present {
		fw.MatchesConfig = obs.TablePresent && obs.TableOwned && obs.MarkerHash == desired.Firewall.Hash
	}
	fw.ModifiedOutside = obs.TablePresent && obs.LiveHash != obs.RecordedHash
	if rt, err := d.Paths.LoadRuntime(); err == nil {
		fw.AppliedAt = rt.FirewallAppliedAt
	}
	if t := obs.Ruleset.Table(nft.TableFamily, nft.TableName); t != nil {
		if n, ok := t.Counter("guard_pre", "wireguard transport"); ok {
			fw.TransportPkts = &n
		}
		if n, ok := t.Counter("from_vpn", "default deny"); ok {
			fw.DeniedPkts = &n
		}
	}
	st.Firewall = fw
	for _, p := range cfg.Peers {
		pi := basePeer(cfg, p)
		want := netip.PrefixFrom(p.Address, 32)
		for _, r := range obs.Link.Routes {
			if r.Dst == want && r.Src == cfg.Self.Address {
				pi.RouteOK = true
			}
		}
		pi.Connectivity = "unknown"
		if obs.WG != nil {
			if ps, ok := obs.WG.Peer(p.WGPublicKey); ok {
				pi.InWireGuard = true
				pi.AllowedIPsOK = len(ps.AllowedIPs) == 1 && ps.AllowedIPs[0] == want
				if ps.Endpoint.IsValid() {
					pi.CurrentEndpoint = ps.Endpoint.String()
				}
				pi.RxBytes, pi.TxBytes = ps.RxBytes, ps.TxBytes
				if !ps.LastHandshake.IsZero() && ps.LastHandshake.Unix() > 0 {
					hs := ps.LastHandshake.UTC()
					age := int64(d.Now().Sub(hs) / time.Second)
					pi.LastHandshake, pi.HandshakeAge = &hs, &age
					if d.Now().Sub(hs) <= HandshakeFresh {
						pi.Connectivity = "handshake-recent"
					} else {
						pi.Connectivity = "handshake-stale"
					}
				} else {
					pi.Connectivity = "no-handshake"
				}
			}
		}
		st.Peers = append(st.Peers, pi)
	}
	// The overlay of an open invite is not in the saved configuration.
	st.Invite = OpenInvite(d)
	if st.Invite != nil {
		return st
	}
	if steps, err := d.Engine.Plan(desired, obs); err != nil {
		st.Drift = append(st.Drift, err.Error())
	} else {
		for _, s := range steps {
			st.Drift = append(st.Drift, s.Desc)
		}
	}
	return st
}

func basePeer(cfg *model.Config, p model.Peer) PeerInfo {
	pi := PeerInfo{
		Name: p.Name, Address: p.Address.String(),
		WGPublicKey: p.WGPublicKey, Keepalive: p.Keepalive, Connectivity: "unknown", AllowedFrom: []string{},
	}
	if p.Endpoint.IsValid() {
		pi.ConfiguredEndpoint = p.Endpoint.String()
	}
	for _, r := range cfg.RulesFor(p.Name) {
		pi.AllowedFrom = append(pi.AllowedFrom, r.Service())
	}
	return pi
}

func configInfo(cfg *model.Config) *ConfigInfo {
	ci := &ConfigInfo{
		Revision: cfg.Revision, UpdatedAt: cfg.UpdatedAt, AdminState: string(cfg.AdminState),
		NetworkID: cfg.Network.ID, NetworkName: cfg.Network.Name, CIDR: cfg.Network.CIDR.String(),
		Name: cfg.Self.Name, Address: cfg.Self.Address.String(), ListenPort: int(cfg.Self.ListenPort),
		WGPublicKey: cfg.Self.WGPublicKey,
		Interface:   cfg.Interface.Name, MTU: cfg.Interface.MTU, Profile: cfg.Firewall.Profile, Rules: []RuleInfo{},
	}
	if cfg.Self.Endpoint.IsValid() {
		ci.Endpoint = cfg.Self.Endpoint.String()
	}
	for _, r := range cfg.Rules {
		ci.Rules = append(ci.Rules, RuleInfo{Peer: r.Peer, Proto: string(r.Proto), Port: int(r.Port), Rule: r.String(), Meaning: RuleMeaning(cfg, r)})
	}
	return ci
}

func collectJournal(d Deps, st *Status) {
	if d.Journal == nil {
		return
	}
	if inc, err := d.Journal.Incomplete(); err == nil && inc != nil {
		st.Transaction.Incomplete = true
		st.Transaction.IncompleteOp = inc.Op
		st.Transaction.IncompleteID = inc.OpID
		st.Transaction.IncompleteTime = inc.Time
	}
	recs, err := d.Journal.Last(50)
	if err != nil {
		return
	}
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		if r.Event == journal.EventBegin || r.Event == journal.EventPhase || r.Event == journal.EventAudit {
			continue
		}
		st.Transaction.LastOp, st.Transaction.LastEvent, st.Transaction.LastTime, st.Transaction.LastDetail = r.Op, r.Event, r.Time, r.Detail
		break
	}
}
