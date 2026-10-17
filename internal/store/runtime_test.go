package store

import (
	"errors"
	"testing"
	"time"
)

func TestRuntimeRoundTrip(t *testing.T) {
	p := newPaths(t)
	r, err := p.LoadRuntime()
	if err != nil || r == nil || r.FirewallLiveHash != "" || r.PeerEndpoints != nil {
		t.Fatalf("LoadRuntime(missing) = %+v, %v", r, err)
	}
	want := &Runtime{
		FirewallLiveHash:  "abc123",
		FirewallAppliedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
		PeerEndpoints:     map[string]string{b64(3): "198.51.100.2:51820"},
	}
	if err := p.SaveRuntime(want); err != nil {
		t.Fatal(err)
	}
	if m := permOf(t, p.RuntimeFile()); m != 0o600 {
		t.Errorf("runtime.json mode %04o, want 0600", m)
	}
	got, err := p.LoadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if got.FirewallLiveHash != want.FirewallLiveHash || !got.FirewallAppliedAt.Equal(want.FirewallAppliedAt) ||
		len(got.PeerEndpoints) != 1 || got.PeerEndpoints[b64(3)] != "198.51.100.2:51820" {
		t.Errorf("LoadRuntime = %+v", got)
	}
	// An empty runtime omits every field.
	if err := p.SaveRuntime(&Runtime{}); err != nil {
		t.Fatal(err)
	}
	if s := readString(t, p.RuntimeFile()); s != "{}\n" {
		t.Errorf("empty runtime encoded as %q", s)
	}
}

func TestLoadRuntimeCorrupt(t *testing.T) {
	// Runtime state is non-authoritative: a corrupt file yields an empty
	// state rather than an error.
	for _, content := range []string{"", "{", "not json", `{"peer_endpoints": 5}`, "[]"} {
		p := newPaths(t)
		writeFile(t, p.RuntimeFile(), content, 0o600)
		r, err := p.LoadRuntime()
		if err != nil {
			t.Errorf("LoadRuntime(%q) error: %v", content, err)
			continue
		}
		if r == nil || r.FirewallLiveHash != "" || len(r.PeerEndpoints) != 0 || !r.FirewallAppliedAt.IsZero() {
			t.Errorf("LoadRuntime(%q) = %+v, want empty", content, r)
		}
	}
}

func TestLoadRuntimeInsecure(t *testing.T) {
	p := newPaths(t)
	writeFile(t, p.RuntimeFile(), `{"firewall_live_hash":"x"}`, 0o644)
	if _, err := p.LoadRuntime(); !errors.Is(err, ErrInsecure) {
		t.Errorf("LoadRuntime(0644) = %v, want ErrInsecure", err)
	}
	writeFile(t, p.RuntimeFile(), string(make([]byte, 1<<16+1)), 0o600)
	if _, err := p.LoadRuntime(); err == nil {
		t.Error("oversized runtime file accepted")
	}
}
