//go:build linux

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/nikitakiselev/meshly/internal/netstack"
)

// A missing default-name link must not permit removing the shared firewall
// while another owned WireGuard path remains open.
func TestCleanupWithoutConfigClosesAllOwnedLinks(t *testing.T) {
	for _, action := range []string{"reset", "service-stop"} {
		for _, corrupt := range []bool{false, true} {
			t.Run(action+map[bool]string{false: "/missing", true: "/corrupt"}[corrupt], func(t *testing.T) {
				n := newTestNode(t, start)
				n.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820", "--interface", "vpn0")
				alias := n.k.Links["vpn0"].Alias
				n.k.Links["vpn1"] = &netstack.Link{Exists: true, Type: "wireguard", Alias: alias, Up: true}
				n.k.Links["meshly0"] = &netstack.Link{Exists: true, Type: "dummy", Alias: alias, Up: true}
				n.k.Links["foreign0"] = &netstack.Link{Exists: true, Type: "wireguard", Alias: "meshly:invalid", Up: true}
				if corrupt {
					if err := os.WriteFile(n.app.Paths.ConfigFile(), []byte("{"), 0644); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Remove(n.app.Paths.ConfigFile()); err != nil {
					t.Fatal(err)
				}
				args := []string{"reset", "--yes"}
				if action == "service-stop" {
					args = []string{"service", "stop"}
				}
				code, _, stderr := n.run(args...)
				if action == "reset" || !corrupt {
					if code != 0 {
						t.Fatalf("exit %d: %s", code, stderr)
					}
				}
				for _, name := range []string{"vpn0", "vpn1"} {
					if n.k.Links[name] != nil {
						t.Errorf("owned %s remains after cleanup; firewall present=%v", name, n.k.Table != "")
					}
				}
				for _, name := range []string{"meshly0", "foreign0"} {
					if l := n.k.Links[name]; l == nil || !l.Up {
						t.Errorf("foreign %s modified", name)
					}
				}
				if n.k.Table != "" {
					t.Error("firewall remains after successful cleanup")
				}
			})
		}
	}
}

func TestCleanupWithoutConfigRetainsFirewallOnCloseFailure(t *testing.T) {
	n := newTestNode(t, start)
	n.must("init", "homelab", "--name", "vps", "--endpoint", "203.0.113.10:51820", "--interface", "vpn0")
	if err := os.WriteFile(n.app.Paths.ConfigFile(), []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}
	n.k.Fail("link.down", -1)
	n.k.Fail("link.delete", -1)
	code, _, stderr := n.run("reset", "--yes")
	if code != ExitSafeMode {
		t.Errorf("exit %d, want safe mode: %s", code, stderr)
	}
	if n.k.Table == "" {
		t.Error("protective firewall removed despite failure to close owned interface")
	}
	if _, err := n.app.Paths.LoadKeys(); err != nil {
		t.Errorf("keys removed despite cleanup failure: %v", err)
	}
	if !strings.Contains(stderr, "vpn0") {
		t.Errorf("failure does not identify custom interface: %s", stderr)
	}
}
