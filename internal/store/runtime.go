package store

import (
	"encoding/json"
	"errors"
	"io/fs"
	"time"
)

// Runtime is non-authoritative state recorded after applying changes.
type Runtime struct {
	// FirewallLiveHash is the normalised hash of the Meshly table as read
	// back from the kernel right after it was applied; a different live
	// hash later means the table was modified outside Meshly.
	FirewallLiveHash  string    `json:"firewall_live_hash,omitempty"`
	FirewallAppliedAt time.Time `json:"firewall_applied_at,omitzero"`
	// PeerEndpoints maps a peer's WireGuard public key to the endpoint
	// last learned from its authenticated packets. After a restart it is
	// used as a hint for peers without a configured endpoint (e.g. behind
	// NAT), so this node can re-establish the session itself instead of
	// waiting for the peer.
	PeerEndpoints map[string]string `json:"peer_endpoints,omitempty"`
}

// LoadRuntime reads runtime state (missing file: empty state).
func (p Paths) LoadRuntime() (*Runtime, error) {
	b, err := ReadFile(p.RuntimeFile(), 0o600, p.Owner, 1<<16)
	if errors.Is(err, fs.ErrNotExist) {
		return &Runtime{}, nil
	}
	if err != nil {
		return nil, err
	}
	var r Runtime
	if err := json.Unmarshal(b, &r); err != nil {
		return &Runtime{}, nil
	}
	return &r, nil
}

// SaveRuntime writes runtime state.
func (p Paths) SaveRuntime(r *Runtime) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(p.RuntimeFile(), append(b, '\n'), 0o600)
}
