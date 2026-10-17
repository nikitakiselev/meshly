//go:build integration

package integration

import (
	"strings"
	"testing"
)

const integrationRule = `meta mark & 0x10000000 == 0x10000000 accept comment "meshly"`

// untouched asserts that a refused command changed nothing.
func untouched(t *testing.T, n *Node, before string) {
	t.Helper()
	if n.Sh("ip link show meshly0").Code == 0 || n.Sh("nft list table inet meshly").Code == 0 {
		t.Fatal("refused command created meshly objects")
	}
	if n.Sh("test -e /etc/meshly/meshly.json").Code == 0 {
		t.Fatal("refused command saved a configuration")
	}
	if after := n.Foreign(); after != before {
		t.Fatalf("refused command changed foreign state:\n%s\n---\n%s", before, after)
	}
}

func initArgs() []string {
	return []string{"init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820"}
}

// Unsupported firewalls are detected before any change.
func TestUnsupportedFirewalls(t *testing.T) {
	l := newLab(t, distros[0])
	vps := l.Node("vps")
	cases := []struct {
		name, setup, undo, want string
	}{
		{"ufw", "mkdir -p /etc/ufw && printf 'ENABLED=yes\\n' > /etc/ufw/ufw.conf", "rm -rf /etc/ufw", "UFW"},
		{"firewalld", "mkdir -p /run/firewalld && echo 1 > /run/firewalld/firewalld.pid", "rm -rf /run/firewalld", "firewalld"},
		{"iptables-legacy", "iptables-legacy -A INPUT -p tcp --dport 25 -j DROP", "iptables-legacy -F INPUT", "legacy iptables"},
		{"iptables-nft-drop", "iptables-nft -P INPUT DROP && iptables-nft -A INPUT -p tcp --dport 22 -j ACCEPT", "iptables-nft -P INPUT ACCEPT && iptables-nft -F INPUT && nft delete table ip filter", "chain ip filter INPUT"},
	}
	for _, c := range cases {
		l.Run(c.name, func(t *testing.T) {
			vps.MustSh(c.setup)
			defer vps.MustSh(c.undo)
			before := vps.Foreign()
			r := vps.ExpectCode(3, initArgs()...)
			if !strings.Contains(r.Err, c.want) {
				t.Fatalf("diagnostic does not name %q:\n%s", c.want, r)
			}
			r = vps.Meshly(append(initArgs(), "--dry-run")...)
			if r.Code != 3 {
				t.Fatalf("dry-run should report the same problem: %s", r)
			}
			untouched(t, vps, before)
		})
	}
}

// The native nftables profile: a host firewall with policy drop, an
// explicit integration rule, fail-closed behaviour when the meshly table
// disappears, and public ports that stay closed.
func TestNativeNftablesProfile(t *testing.T) {
	l := newLab(t, distros[0])
	vps, attacker := l.Node("vps"), l.Node("attacker")
	hostfw := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif lo accept
		ct state established,related accept
		tcp dport 22 accept
		%s
	}
	chain forward { type filter hook forward priority filter; policy drop; }
}`
	vps.MustSh("nft -f - <<'EOF'\n" + strings.Replace(hostfw, "%s", "", 1) + "\nEOF")
	vps.Listen("tcp", 22)
	vps.Listen("tcp", 8080)
	before := vps.Foreign()

	// Without the integration rule: refused, with the rule to add.
	r := vps.ExpectCode(3, initArgs()...)
	if !strings.Contains(r.Err, integrationRule) || !strings.Contains(r.Err, "chain inet filter input") {
		t.Fatalf("no actionable integration instruction:\n%s", r)
	}
	untouched(t, vps, before)

	// Misplaced: after a rule that drops.
	vps.MustSh("nft delete table inet filter && nft -f - <<'EOF'\n" + strings.Replace(hostfw, "%s", "tcp dport 0-65535 drop\n\t\t"+integrationRule, 1) + "\nEOF")
	r = vps.ExpectCode(3, initArgs()...)
	if !strings.Contains(r.Err, "move the rule") {
		t.Fatalf("misplaced integration not detected:\n%s", r)
	}

	// Correct placement.
	vps.MustSh("nft delete table inet filter && nft -f - <<'EOF'\n" + strings.Replace(hostfw, "%s", integrationRule, 1) + "\nEOF")
	before = vps.Foreign()
	vps, home := l.Pair()
	if r := vps.MustMeshly("status"); !strings.Contains(r.Out, "firewall profile nftables") {
		t.Fatalf("auto profile is not nftables:\n%s", r.Out)
	}
	vps.MustMeshly("allow", "8080/tcp", "from", "home")
	if !home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("allowed service unreachable through the host firewall")
	}
	// Public: the application port stays closed, SSH stays open.
	if attacker.Probe("tcp", "198.51.100.10", 8080) {
		t.Fatal("meshly opened the application port publicly")
	}
	if !attacker.Probe("tcp", "198.51.100.10", 22) {
		t.Fatal("public SSH broken")
	}
	if home.Probe("tcp", "10.100.0.1", 22) {
		t.Fatal("SSH reachable through the VPN without a rule (host accepts tcp/22 on all interfaces)")
	}
	if after := vps.Foreign(); after != before {
		t.Fatalf("host firewall modified:\n%s\n---\n%s", before, after)
	}

	// Fail closed: without the meshly table nothing is marked, so what
	// meshly opened is closed again. (Ports the host firewall itself opens
	// on all interfaces, like 22 here, are then as open to the peer as to
	// any internet host — documented in docs/firewall.md.)
	vps.MustSh("nft delete table inet meshly")
	if home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("VPN service reachable after the meshly table was removed")
	}
	vps.MustMeshly("service", "check")
	if !home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("not repaired by the check")
	}

	// The integration rule disappears (e.g. nftables.conf rewritten):
	// opening access is refused, reducing access still works.
	vps.MustSh("nft delete table inet filter && nft -f - <<'EOF'\n" + strings.Replace(hostfw, "%s", "", 1) + "\nEOF")
	vps.ExpectCode(3, "allow", "9090/tcp", "from", "home")
	r = vps.MustMeshly("deny", "8080/tcp", "from", "home")
	if !strings.Contains(r.Err, "warning") {
		t.Fatalf("access-reducing command should warn, not fail:\n%s", r)
	}
	vps.MustMeshly("revoke", "home", "--yes")
	if r := vps.Meshly("doctor"); r.Code != 12 || !strings.Contains(r.Out, integrationRule) {
		t.Fatalf("doctor does not report the missing integration rule:\n%s", r)
	}
}
