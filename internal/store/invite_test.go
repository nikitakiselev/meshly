package store

import (
	"errors"
	"io/fs"
	"testing"
	"time"
)

func TestInviteMarkerRoundTrip(t *testing.T) {
	p := newPaths(t)
	if _, err := p.LoadInviteMarker(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadInviteMarker(missing) = %v, want fs.ErrNotExist", err)
	}
	want := InviteMarker{ExpiresAt: time.Date(2026, 10, 18, 20, 40, 0, 0, time.UTC)}
	if err := p.SaveInviteMarker(want); err != nil {
		t.Fatal(err)
	}
	if m := permOf(t, p.InviteFile()); m != 0o600 {
		t.Errorf("invite.json mode %04o, want 0600", m)
	}
	got, err := p.LoadInviteMarker()
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("LoadInviteMarker = %+v, want %+v", got, want)
	}
	if err := p.RemoveInviteMarker(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.LoadInviteMarker(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadInviteMarker after remove = %v, want fs.ErrNotExist", err)
	}
	// Removing a marker that is not there is not an error.
	if err := p.RemoveInviteMarker(); err != nil {
		t.Errorf("RemoveInviteMarker(missing) = %v", err)
	}
}

func TestInviteMarkerInsecure(t *testing.T) {
	p := newPaths(t)
	writeFile(t, p.InviteFile(), `{"expires_at":"2026-10-18T20:40:00Z"}`, 0o644)
	if _, err := p.LoadInviteMarker(); !errors.Is(err, ErrInsecure) {
		t.Errorf("LoadInviteMarker(0644) = %v, want ErrInsecure", err)
	}
	writeFile(t, p.InviteFile(), "not json", 0o600)
	if _, err := p.LoadInviteMarker(); err == nil {
		t.Error("corrupt invite marker accepted")
	}
}
