//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// Configuration loss must never make reset/service stop remove the firewall
// before a custom-named WireGuard path and all other owned links are gone.
func TestIssue1CleanupWithoutConfig(t *testing.T) {
	for _, action := range []string{"reset", "service-stop"} {
		for _, corrupt := range []bool{false, true} {
			name := action + map[bool]string{false: "/missing", true: "/corrupt"}[corrupt]
			t.Run(name, func(t *testing.T) {
				l := newLab(t, distros[0])
				vps, home := l.Node("vps"), l.Node("home")
				vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820", "--interface", "vpn0")
				code := vps.Invite()
				if r := home.Join(code, "--name", "home"); r.Code != 0 {
					t.Fatalf("join: %s", r)
				}
				if code, errout := vps.InviteExit(30 * time.Second); code != 0 {
					t.Fatalf("invite exit %d: %s", code, errout)
				}
				l.WaitHandshake(home, 20*time.Second)
				vps.Listen("tcp", 8080)
				vps.Listen("tcp", 8081)
				vps.MustMeshly("allow", "8080/tcp", "from", "home")
				if !home.Probe("tcp", "10.100.0.1", 8080) {
					t.Fatal("custom-interface tunnel is not carrying allowed packets")
				}
				if home.Probe("tcp", "10.100.0.1", 8081) {
					t.Fatal("default-deny service reachable before cleanup")
				}
				// A second owned link must also disappear. Wrong-kind and malformed
				// ownership markers, including a foreign default-name link, stay intact.
				vps.MustSh(`alias=$(cat /sys/class/net/vpn0/ifalias)
ip link add vpn1 type wireguard
ip link set vpn1 alias "$alias" up
ip link add meshly0 type dummy
ip link set meshly0 alias "$alias" up
ip link add foreign0 type wireguard
ip link set foreign0 alias meshly:invalid up
nft add table inet issue1_foreign
nft add chain inet issue1_foreign sentinel`)
				before := vps.MustSh("ip -j link show meshly0; ip -j link show foreign0; nft -j list table inet issue1_foreign")
				if corrupt {
					vps.WriteFile("/etc/meshly/meshly.json", []byte("{"))
				} else {
					vps.MustSh("rm /etc/meshly/meshly.json")
				}
				args := []string{"reset", "--yes"}
				if action == "service-stop" {
					args = []string{"service", "stop"}
				}
				r := vps.Meshly(args...)
				if action == "service-stop" && corrupt {
					if r.Code == 0 {
						t.Fatal("service stop did not report unreadable config")
					}
				} else if r.Code != 0 {
					t.Fatalf("cleanup: %s", r)
				}
				for _, name := range []string{"vpn0", "vpn1"} {
					if vps.Sh("ip link show "+name).Code == 0 {
						t.Errorf("owned interface %s remains", name)
					}
				}
				if vps.Sh("nft list table inet meshly").Code == 0 {
					t.Error("owned firewall remains after successful cleanup")
				}
				after := vps.MustSh("ip -j link show meshly0; ip -j link show foreign0; nft -j list table inet issue1_foreign")
				if strings.TrimSpace(before) != strings.TrimSpace(after) {
					t.Errorf("foreign state changed:\nbefore %s\nafter %s", before, after)
				}
				if home.Probe("tcp", "10.100.0.1", 8080) || home.Probe("tcp", "10.100.0.1", 8081) {
					t.Fatal("VPN service reachable after configuration-loss cleanup")
				}
			})
		}
	}
}
