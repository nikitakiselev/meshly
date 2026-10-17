package store

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

var bt0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func TestLoadBootstrapMissing(t *testing.T) {
	p := newPaths(t)
	s, err := p.LoadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != bootstrapSchema || len(s.Invites) != 0 || s.Pending != nil || len(s.Activations) != 0 {
		t.Errorf("unexpected empty state: %+v", s)
	}
}

func TestSaveLoadBootstrap(t *testing.T) {
	p := newPaths(t)
	s := &BootstrapState{
		Invites: []InviteRecord{{
			InviteID: strings.Repeat("01", 16), Digest: "d1", CreatedAt: bt0, ExpiresAt: bt0.Add(time.Hour),
			AssignedAddress: netip.MustParseAddr("10.100.0.2"), Envelope: "MESHLY-INVITE...", Status: InviteReserved,
			RequestID: strings.Repeat("02", 16), CandidateName: "beta", DecidedAt: bt0.Add(time.Minute),
		}},
		Pending: &PendingJoin{
			NetworkID: strings.Repeat("ab", 16), Name: "beta", ListenPort: 51820, Keepalive: 25,
			Endpoint: netip.MustParseAddrPort("198.51.100.2:51820"), ExpiresAt: bt0.Add(time.Hour), CreatedAt: bt0,
		},
		Activations: []Activation{{NetworkID: strings.Repeat("ab", 16), AcceptDigest: "a", ActivatedAt: bt0}},
	}
	if err := p.SaveBootstrap(s); err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != bootstrapSchema {
		t.Error("SaveBootstrap did not set the schema version")
	}
	if m := permOf(t, p.BootstrapFile()); m != 0o600 {
		t.Errorf("bootstrap.json mode %04o, want 0600", m)
	}
	got, err := p.LoadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Invites) != 1 || got.Invites[0].Status != InviteReserved || !got.Invites[0].ExpiresAt.Equal(bt0.Add(time.Hour)) ||
		got.Invites[0].AssignedAddress != s.Invites[0].AssignedAddress || got.Invites[0].CandidateName != "beta" {
		t.Errorf("invites = %+v", got.Invites)
	}
	if got.Pending == nil || got.Pending.Endpoint != s.Pending.Endpoint || got.Pending.Name != "beta" {
		t.Errorf("pending = %+v", got.Pending)
	}
	if len(got.Activations) != 1 || got.Activations[0].AcceptDigest != "a" {
		t.Errorf("activations = %+v", got.Activations)
	}
}

func TestLoadBootstrapRejectsBroken(t *testing.T) {
	tests := []struct {
		name, content, want string
		mode                os.FileMode
	}{
		{"garbage", "SECRET-GARBAGE", "corrupted", 0o600},
		{"unknown field", `{"schema_version":1,"invites":[],"activations":[],"extra":1}`, `unknown field "extra"`, 0o600},
		{"wrong type", `{"schema_version":"SECRET"}`, "wrong type", 0o600},
		{"schema 2", `{"schema_version":2,"invites":[],"activations":[]}`, "unsupported bootstrap state schema 2", 0o600},
		{"schema 0", `{}`, "unsupported bootstrap state schema 0", 0o600},
		{"readable by others", `{"schema_version":1}`, "insecure", 0o644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPaths(t)
			writeFile(t, p.BootstrapFile(), tt.content, tt.mode)
			s, err := p.LoadBootstrap()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadBootstrap = %+v, %v; want %q", s, err, tt.want)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Errorf("error echoes content: %v", err)
			}
		})
	}
}

func TestBootstrapPrune(t *testing.T) {
	s := &BootstrapState{}
	for i := 0; i < 250; i++ {
		s.Invites = append(s.Invites, InviteRecord{InviteID: fmt.Sprint(i)})
		s.Activations = append(s.Activations, Activation{AcceptDigest: fmt.Sprint(i)})
	}
	s.Prune()
	if len(s.Invites) != 200 || s.Invites[0].InviteID != "50" || s.Invites[199].InviteID != "249" {
		t.Errorf("invites after prune: %d, first %s", len(s.Invites), s.Invites[0].InviteID)
	}
	if len(s.Activations) != 200 || s.Activations[0].AcceptDigest != "50" || s.Activations[199].AcceptDigest != "249" {
		t.Errorf("activations after prune: %d", len(s.Activations))
	}

	small := &BootstrapState{Invites: make([]InviteRecord, 200), Activations: make([]Activation, 3)}
	small.Prune()
	if len(small.Invites) != 200 || len(small.Activations) != 3 {
		t.Errorf("prune of small state changed it: %d %d", len(small.Invites), len(small.Activations))
	}

	// SaveBootstrap prunes too.
	p := newPaths(t)
	big := &BootstrapState{}
	for i := 0; i < 205; i++ {
		big.Invites = append(big.Invites, InviteRecord{InviteID: fmt.Sprint(i), Status: InviteCancelled})
	}
	if err := p.SaveBootstrap(big); err != nil {
		t.Fatal(err)
	}
	got, err := p.LoadBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Invites) != 200 || got.Invites[0].InviteID != "5" || got.Invite("4") != nil || got.Invite("204") == nil {
		t.Errorf("saved state not pruned: %d invites", len(got.Invites))
	}
}

func TestActiveInvite(t *testing.T) {
	exp := bt0.Add(time.Hour)
	rec := func(id string, st InviteStatus, expires time.Time) InviteRecord {
		return InviteRecord{InviteID: id, Status: st, ExpiresAt: expires}
	}
	tests := []struct {
		name    string
		invites []InviteRecord
		now     time.Time
		want    string // "" means none
	}{
		{"empty", nil, bt0, ""},
		{"issued", []InviteRecord{rec("a", InviteIssued, exp)}, bt0, "a"},
		{"reserved", []InviteRecord{rec("a", InviteReserved, exp)}, bt0, "a"},
		{"approved is not active", []InviteRecord{rec("a", InviteApproved, exp)}, bt0, ""},
		{"cancelled is not active", []InviteRecord{rec("a", InviteCancelled, exp)}, bt0, ""},
		{"expired", []InviteRecord{rec("a", InviteIssued, exp)}, exp.Add(time.Second), ""},
		{"expires exactly now", []InviteRecord{rec("a", InviteIssued, exp)}, exp, ""},
		{"one second before expiry", []InviteRecord{rec("a", InviteIssued, exp)}, exp.Add(-time.Second), "a"},
		{"newest active wins", []InviteRecord{
			rec("old", InviteIssued, exp), rec("mid", InviteReserved, exp), rec("done", InviteApproved, exp), rec("x", InviteCancelled, exp),
		}, bt0, "mid"},
		{"skips newer expired", []InviteRecord{rec("old", InviteIssued, exp.Add(time.Hour)), rec("new", InviteIssued, bt0)}, bt0.Add(time.Minute), "old"},
		{"unknown status", []InviteRecord{rec("a", "weird", exp)}, bt0, ""},
	}
	for _, tt := range tests {
		s := &BootstrapState{Invites: tt.invites}
		got := s.ActiveInvite(tt.now)
		switch {
		case tt.want == "" && got != nil:
			t.Errorf("%s: ActiveInvite = %s, want none", tt.name, got.InviteID)
		case tt.want != "" && (got == nil || got.InviteID != tt.want):
			t.Errorf("%s: ActiveInvite = %v, want %s", tt.name, got, tt.want)
		}
	}

	// The result points into the state, so callers can update it.
	s := &BootstrapState{Invites: []InviteRecord{rec("a", InviteIssued, exp)}}
	s.ActiveInvite(bt0).Status = InviteCancelled
	if s.Invites[0].Status != InviteCancelled || s.ActiveInvite(bt0) != nil {
		t.Error("ActiveInvite does not return a pointer into the state")
	}
}

func TestInviteLookup(t *testing.T) {
	s := &BootstrapState{Invites: []InviteRecord{{InviteID: "a"}, {InviteID: "b"}}}
	if r := s.Invite("b"); r == nil || r != &s.Invites[1] {
		t.Errorf("Invite(b) = %v", r)
	}
	if r := s.Invite("c"); r != nil {
		t.Errorf("Invite(c) = %v", r)
	}
	if r := s.Invite(""); r != nil {
		t.Errorf("Invite(\"\") = %v", r)
	}
}

func TestLoadBootstrapWrongOwner(t *testing.T) {
	p := newPaths(t)
	if err := p.SaveBootstrap(&BootstrapState{}); err != nil {
		t.Fatal(err)
	}
	p.Owner++
	if _, err := p.LoadBootstrap(); !errors.Is(err, ErrInsecure) {
		t.Errorf("LoadBootstrap with wrong owner = %v", err)
	}
}
