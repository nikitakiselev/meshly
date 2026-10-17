package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"time"
)

const bootstrapSchema = 1

// InviteStatus is the lifecycle state of an issued invite.
type InviteStatus string

const (
	// InviteIssued: created, not yet used by any request.
	InviteIssued InviteStatus = "issued"
	// InviteReserved: bound to exactly one request; approval was decided
	// but applying it has not completed yet.
	InviteReserved InviteStatus = "reserved"
	// InviteApproved: the bound request was approved and applied.
	InviteApproved InviteStatus = "approved"
	// InviteCancelled: superseded by a newer invite (`meshly invite --new`).
	// A revoked peer's invite stays approved; its request is refused as revoked.
	InviteCancelled InviteStatus = "cancelled"
)

// InviteRecord is the inviter-side record of an invite. Records are kept
// after use so a used invite id can never be accepted again.
type InviteRecord struct {
	InviteID        string       `json:"invite_id"`
	Digest          string       `json:"digest"`
	CreatedAt       time.Time    `json:"created_at"`
	ExpiresAt       time.Time    `json:"expires_at"`
	AssignedAddress netip.Addr   `json:"assigned_address"`
	Envelope        string       `json:"envelope"`
	Status          InviteStatus `json:"status"`
	RequestID       string       `json:"request_id,omitempty"`
	RequestDigest   string       `json:"request_digest,omitempty"`
	CandidateName   string       `json:"candidate_name,omitempty"`
	Fingerprint     string       `json:"candidate_fingerprint,omitempty"`
	Accept          string       `json:"accept,omitempty"`
	DecidedAt       time.Time    `json:"decided_at,omitzero"`
}

// PendingJoin is the joiner-side state between `join` and `activate`.
type PendingJoin struct {
	NetworkID      string         `json:"network_id"`
	InviteID       string         `json:"invite_id"`
	InviteDigest   string         `json:"invite_digest"`
	Invite         string         `json:"invite"`
	Request        string         `json:"request"`
	RequestID      string         `json:"request_id"`
	RequestDigest  string         `json:"request_digest"`
	ExpiresAt      time.Time      `json:"expires_at"`
	CreatedAt      time.Time      `json:"created_at"`
	Name           string         `json:"name"`
	ListenPort     uint16         `json:"listen_port"`
	Keepalive      int            `json:"keepalive"`
	Endpoint       netip.AddrPort `json:"endpoint,omitzero"`
	Interface      string         `json:"interface"`
	Profile        string         `json:"firewall_profile"`
	IssuerIdentity string         `json:"issuer_identity_key"`
}

// Activation records a consumed accept (replay protection, idempotency).
type Activation struct {
	NetworkID     string    `json:"network_id"`
	AcceptDigest  string    `json:"accept_digest"`
	RequestDigest string    `json:"request_digest"`
	ActivatedAt   time.Time `json:"activated_at"`
}

// BootstrapState is persisted in /var/lib/meshly/bootstrap.json.
type BootstrapState struct {
	SchemaVersion int            `json:"schema_version"`
	Invites       []InviteRecord `json:"invites"`
	Pending       *PendingJoin   `json:"pending_join,omitempty"`
	Activations   []Activation   `json:"activations"`
}

// Invite returns the record with the given id.
func (s *BootstrapState) Invite(id string) *InviteRecord {
	for i := range s.Invites {
		if s.Invites[i].InviteID == id {
			return &s.Invites[i]
		}
	}
	return nil
}

// ActiveInvite returns an invite that is issued or reserved and unexpired.
func (s *BootstrapState) ActiveInvite(now time.Time) *InviteRecord {
	for i := len(s.Invites) - 1; i >= 0; i-- {
		r := &s.Invites[i]
		if (r.Status == InviteIssued || r.Status == InviteReserved) && now.Before(r.ExpiresAt) {
			return r
		}
	}
	return nil
}

// Prune keeps at most the newest 200 invite records.
func (s *BootstrapState) Prune() {
	const max = 200
	if len(s.Invites) > max {
		s.Invites = append([]InviteRecord(nil), s.Invites[len(s.Invites)-max:]...)
	}
	if len(s.Activations) > max {
		s.Activations = append([]Activation(nil), s.Activations[len(s.Activations)-max:]...)
	}
}

// LoadBootstrap reads bootstrap state; a missing file is an empty state.
func (p Paths) LoadBootstrap() (*BootstrapState, error) {
	b, err := ReadFile(p.BootstrapFile(), 0o600, p.Owner, 4<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return &BootstrapState{SchemaVersion: bootstrapSchema}, nil
	}
	if err != nil {
		return nil, err
	}
	var s BootstrapState
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("bootstrap state is corrupted: %s", sanitizeJSONErr(err))
	}
	if s.SchemaVersion != bootstrapSchema {
		return nil, fmt.Errorf("unsupported bootstrap state schema %d", s.SchemaVersion)
	}
	return &s, nil
}

// SaveBootstrap atomically writes bootstrap state.
func (p Paths) SaveBootstrap(s *BootstrapState) error {
	s.SchemaVersion = bootstrapSchema
	s.Prune()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(p.BootstrapFile(), append(b, '\n'), 0o600)
}
