package engine

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nikitakiselev/meshly/internal/netstack"
)

func TestCleanupOwnedClosesEveryPathBeforeFirewall(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Interface.Name = "vpn0"
	v.commit(c)
	v.k.Links["vpn1"] = &netstack.Link{Exists: true, Type: "wireguard", Alias: "meshly:" + c.Network.ID, Up: true}
	v.k.Calls = nil
	if err := v.e.CleanupOwned(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstFirewall := slices.Index(v.k.Calls, "nft.apply")
	if firstFirewall < 0 {
		t.Fatal("owned firewall was not removed")
	}
	deletes := 0
	for _, call := range v.k.Calls[:firstFirewall] {
		if call == "link.delete" {
			deletes++
		}
	}
	if deletes != 2 {
		t.Fatalf("shared firewall removed before both paths: %v", v.k.Calls)
	}
	if len(v.k.Links) != 0 || v.k.Table != "" {
		t.Fatalf("leftover state: links=%v table=%s", v.k.Links, v.k.Table)
	}
	if err := v.e.CleanupOwned(context.Background()); err != nil {
		t.Fatalf("repeated cleanup: %v", err)
	}
}

func TestCleanupOwnedRetainsProtectionOnDiscoveryFailure(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Interface.Name = "vpn0"
	v.commit(c)
	v.k.Fail("link.list", -1)
	err := v.e.CleanupOwned(context.Background())
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.SafeMode {
		t.Fatalf("want safe-mode failure, got %v", err)
	}
	if v.k.Table == "" || !v.k.Links["vpn0"].Up {
		t.Fatal("incomplete inventory permitted destructive cleanup")
	}
}

func TestCleanupOwnedPreservesForeignTable(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Interface.Name = "vpn0"
	v.commit(c)
	v.k.Foreign = true
	if err := v.e.CleanupOwned(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !v.k.Foreign {
		t.Fatal("foreign table removed")
	}
	if v.k.Links["vpn0"] != nil {
		t.Fatal("owned path survives cleanup")
	}
}

func TestCleanupOwnedAttemptsAllPathsOnFailure(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Interface.Name = "vpn0"
	v.commit(c)
	v.k.Links["vpn1"] = &netstack.Link{Exists: true, Type: "wireguard", Alias: "meshly:" + c.Network.ID, Up: true}
	v.k.Fail("link.delete", -1)
	err := v.e.CleanupOwned(context.Background())
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.SafeMode {
		t.Fatalf("want safe-mode failure, got %v", err)
	}
	for _, name := range []string{"vpn0", "vpn1"} {
		if v.k.Links[name].Up {
			t.Errorf("%s left up after another link failed", name)
		}
	}
	if len(v.k.Devs["vpn0"].Peers) != 0 {
		t.Error("failed deletion did not remove peers")
	}
	if v.k.Table == "" {
		t.Error("protective firewall removed despite incomplete cleanup")
	}
}
