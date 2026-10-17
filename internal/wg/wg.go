// Package wg configures kernel WireGuard through generic netlink (wgctrl).
// Private keys are passed over netlink only; they never appear in process
// arguments, files outside /etc/meshly/keys, or output.
package wg

import (
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerState is the observed state of a WireGuard peer.
type PeerState struct {
	PublicKey     string
	Endpoint      netip.AddrPort
	AllowedIPs    []netip.Prefix
	Keepalive     int
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Device is the observed state of a WireGuard interface (no private key).
type Device struct {
	PublicKey  string
	ListenPort int
	FwMark     int
	Peers      []PeerState
}

// Peer returns the peer with the public key.
func (d *Device) Peer(pub string) (*PeerState, bool) {
	for i := range d.Peers {
		if d.Peers[i].PublicKey == pub {
			return &d.Peers[i], true
		}
	}
	return nil, false
}

// DesiredPeer is the configuration Meshly wants for a peer.
type DesiredPeer struct {
	PublicKey string
	// Endpoint is only set when configured; otherwise WireGuard learns the
	// peer's current address from authenticated packets (roaming).
	Endpoint  netip.AddrPort
	AllowedIP netip.Prefix
	Keepalive int
	// PresharedKey is the optional PSK of the peer. The zero key means none
	// and clears a PSK left on an existing peer.
	PresharedKey wgtypes.Key
}
