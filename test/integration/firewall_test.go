//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
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
		{"firewalld", "mkdir -p /run/firewalld && echo 1 > /run/firewalld/firewalld.pid", "rm -rf /run/firewalld", "firewalld"},
		{"iptables-legacy", "iptables-legacy -A INPUT -p tcp --dport 25 -j DROP", "iptables-legacy -F INPUT", "legacy iptables"},
		{"iptables-nft mangle drop", "iptables-nft -t mangle -A INPUT -p udp -j DROP", "iptables-nft -t mangle -F INPUT && nft delete table ip mangle", "chain ip mangle INPUT"},
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

// UFW on both nodes (default deny incoming, SSH allowed on the vps):
// pairing and allowed services work without any UFW rule for meshly, UFW
// still closes everything else, UFW's own commands keep meshly's rule, and
// the rule comes back after iptables-restore removes it.
func TestUFW(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newLab(t, distro)
		vps, home, attacker := l.Node("vps"), l.Node("home"), l.Node("attacker")
		vps.MustSh("ufw allow 22/tcp && ufw --force enable")
		home.MustSh("ufw --force enable")
		vps.Listen("tcp", 22)
		vps.Listen("tcp", 8080)
		before := vps.Foreign()

		r := vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
		if !strings.Contains(r.Out, "meshly rule first in ip filter INPUT, ip filter OUTPUT, ip6 filter INPUT, ip6 filter OUTPUT; UFW is enabled") {
			t.Fatalf("init does not say what it did with the UFW chains:\n%s", r)
		}
		code := vps.Invite()
		if r := home.Join(code, "--name", "home"); r.Code != 0 {
			t.Fatalf("join through UFW: %s\n%s", r, vps.Sh("cat /root/invite.err").Out)
		}
		if c, inv := vps.InviteExit(30 * time.Second); c != 0 {
			t.Fatalf("invite: exit %d\n%s", c, inv)
		}
		l.WaitHandshake(home, 20*time.Second)
		for _, n := range []*Node{vps, home} {
			if !n.IptablesFirst() {
				t.Fatalf("%s: meshly rule not first:\n%s", n.Name, n.Sh("iptables -S; ip6tables -S").Out)
			}
		}

		vps.MustMeshly("allow", "8080/tcp", "from", "home")
		if !home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("allowed service unreachable through UFW")
		}
		if home.Probe("tcp", "10.100.0.1", 22) {
			t.Fatal("SSH reachable through the VPN without a meshly rule (UFW allows it on all interfaces)")
		}
		if attacker.Probe("tcp", "198.51.100.10", 8080) {
			t.Fatal("the application port is open publicly")
		}
		if !attacker.Probe("tcp", "198.51.100.10", 22) {
			t.Fatal("public SSH broken")
		}
		if after := vps.Foreign(); after != before {
			t.Fatalf("UFW rules changed:\n%s\n---\n%s", before, after)
		}

		// UFW's own commands leave the rule in place.
		vps.MustSh("ufw allow 80/tcp && ufw reload && ufw disable && ufw --force enable")
		if !vps.IptablesFirst() || !home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatalf("meshly rule lost after UFW commands:\n%s", vps.Sh("iptables -S INPUT").Out)
		}
		if r := vps.MustMeshly("status"); strings.Contains(r.Out, "MISSING") || !strings.Contains(r.Out, "none: kernel state matches the configuration") {
			t.Fatalf("status after UFW commands:\n%s", r.Out)
		}

		// iptables-restore without the rule: closed, until the check puts
		// it back.
		vps.MustSh("iptables-save | grep -v 'meshly:v1 integration' | iptables-restore")
		if home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("VPN service reachable through UFW without meshly's rule")
		}
		if r := vps.MustMeshly("status"); !strings.Contains(r.Out, "ip filter INPUT MISSING") {
			t.Fatalf("status does not show the missing rule:\n%s", r.Out)
		}
		vps.MustMeshly("service", "check")
		if !vps.IptablesFirst() || !home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("not repaired by the check")
		}

		// stop removes the rule, start puts it back, reset leaves UFW as
		// it was (iptables-restore above reordered the tables, hence a new
		// snapshot).
		before = vps.Foreign()
		vps.MustMeshly("stop")
		if strings.Contains(vps.MustSh("iptables-save; ip6tables-save"), "meshly") {
			t.Fatal("meshly rule left after stop")
		}
		vps.MustMeshly("start")
		if !vps.IptablesFirst() || !home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("start did not bring the rule back")
		}
		vps.MustMeshly("reset", "--yes")
		if strings.Contains(vps.MustSh("iptables-save; ip6tables-save"), "meshly") {
			t.Fatal("meshly rule left after reset")
		}
		if after := vps.Foreign(); after != before {
			t.Fatalf("UFW rules changed by reset:\n%s\n---\n%s", before, after)
		}
	})
}

// Hand-written iptables rules (policy DROP, as with iptables-persistent):
// the WireGuard port needs no rule, allowed services work, and reset
// leaves the rules exactly as they were.
func TestIptablesHost(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home, attacker := l.Node("vps"), l.Node("home"), l.Node("attacker")
	for _, ipt := range []string{"iptables", "ip6tables"} {
		vps.MustSh(ipt + " -A INPUT -i lo -j ACCEPT && " + ipt + " -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && " +
			ipt + " -A INPUT -p tcp --dport 22 -j ACCEPT && " + ipt + " -P INPUT DROP")
	}
	vps.Listen("tcp", 22)
	vps.Listen("tcp", 8080)
	save := func() string {
		return vps.MustSh(`iptables-save | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]//'; ip6tables-save | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]//'`)
	}
	before := save()

	vps, home = l.Pair()
	// INPUT has rules and policy DROP; OUTPUT (accept, empty) is left alone.
	if !vps.iptablesFirst("iptables -S INPUT", "ip6tables -S INPUT") || strings.Contains(vps.MustSh("iptables -S OUTPUT; ip6tables -S OUTPUT"), "meshly") {
		t.Fatalf("meshly rule not first in INPUT only:\n%s", vps.Sh("iptables -S; ip6tables -S").Out)
	}
	vps.MustMeshly("allow", "8080/tcp", "from", "home")
	if !home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("allowed service unreachable through iptables")
	}
	if home.Probe("tcp", "10.100.0.1", 22) {
		t.Fatal("SSH reachable through the VPN without a meshly rule")
	}
	if attacker.Probe("tcp", "198.51.100.10", 8080) || !attacker.Probe("tcp", "198.51.100.10", 22) {
		t.Fatal("public ports changed")
	}
	// A rule inserted above meshly's: the check moves meshly's back up.
	vps.MustSh("iptables -I INPUT 1 -p tcp --dport 9 -j DROP")
	vps.MustMeshly("service", "check")
	if !vps.IptablesFirst4() {
		t.Fatalf("meshly rule not moved back to the top:\n%s", vps.Sh("iptables -S INPUT").Out)
	}
	vps.MustSh("iptables -D INPUT -p tcp --dport 9 -j DROP")

	vps.MustMeshly("revoke", "home", "--yes")
	vps.MustMeshly("reset", "--yes")
	if after := save(); after != before {
		t.Fatalf("iptables rules changed:\n%s\n---\n%s", before, after)
	}
}
