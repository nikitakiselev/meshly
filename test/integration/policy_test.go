//go:build integration

package integration

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func forDistros(t *testing.T, f func(t *testing.T, distro string)) {
	for _, d := range distros {
		t.Run(d, func(t *testing.T) { f(t, d) })
	}
}

// Scenarios 1–5, 7: handshake, default deny, allow exactly one service and
// direction, TCP and UDP, revoke.
func TestPolicy(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newLab(t, distro)
		vps, home := l.Pair()
		attacker := l.Node("attacker")
		for _, n := range []*Node{vps, home} {
			n.Listen("tcp", 8080)
			n.Listen("tcp", 8081)
			n.Listen("udp", 5353)
		}

		// 1. Handshake works, application access is closed both ways.
		for _, c := range []struct {
			from *Node
			addr string
		}{{home, "10.100.0.1"}, {vps, "10.100.0.2"}} {
			if c.from.Probe("tcp", c.addr, 8080) || c.from.Probe("udp", c.addr, 5353) || c.from.Ping(c.addr) {
				t.Fatalf("%s reaches %s before any allow rule", c.from.Name, c.addr)
			}
		}
		r := vps.MustMeshly("status", "--json")
		if !strings.Contains(r.Out, `"connectivity": "handshake-recent"`) {
			t.Fatalf("status does not report a recent handshake:\n%s", r.Out)
		}

		// 2./3. allow opens exactly the given port and protocol.
		vps.MustMeshly("allow", "8080/tcp", "from", "home")
		vps.MustMeshly("allow", "5353/udp", "from", "home")
		if !home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("allowed 8080/tcp is not reachable")
		}
		if !home.Probe("udp", "10.100.0.1", 5353) {
			t.Fatal("allowed 5353/udp is not reachable")
		}
		if home.Probe("tcp", "10.100.0.1", 8081) {
			t.Fatal("8081/tcp reachable without a rule")
		}
		if home.Ping("10.100.0.1") {
			t.Fatal("ping allowed without a ping rule")
		}
		// 5. The reverse direction stays closed.
		if vps.Probe("tcp", "10.100.0.2", 8080) || vps.Probe("udp", "10.100.0.2", 5353) {
			t.Fatal("reverse direction opened by a rule on the other node")
		}
		// 4. The VPN address is not reachable from outside the tunnel,
		// even with a route pointing at the server.
		attacker.MustSh("ip route replace 10.100.0.0/24 via 198.51.100.10")
		if attacker.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("VPN service reachable from the public network")
		}
		vps.MustMeshly("allow", "ping", "from", "home")
		if !home.Ping("10.100.0.1") {
			t.Fatal("ping rule does not work")
		}
		// Rules list.
		r = vps.MustMeshly("rules", "--json")
		for _, want := range []string{`"rule": "8080/tcp from home"`, `"rule": "5353/udp from home"`, `"rule": "ping from home"`} {
			if !strings.Contains(r.Out, want) {
				t.Fatalf("rules --json misses %s:\n%s", want, r.Out)
			}
		}

		// 7. revoke ends all access of the peer.
		vps.ExpectCode(10, "revoke", "home") // non-interactive without --yes
		vps.MustMeshly("revoke", "home", "--yes")
		if home.Probe("tcp", "10.100.0.1", 8080) || home.Ping("10.100.0.1") {
			t.Fatal("access continues after revoke")
		}
		if out := vps.MustSh("wg show meshly0 peers"); strings.TrimSpace(out) != "" {
			t.Fatalf("peer key still configured after revoke: %q", out)
		}
		if out := vps.MustSh("ip route show proto 109"); strings.TrimSpace(out) != "" {
			t.Fatalf("peer route remains after revoke: %q", out)
		}
		if r := vps.MustMeshly("rules"); strings.Contains(r.Out, "from home") {
			t.Fatalf("rules of a revoked peer remain:\n%s", r.Out)
		}
	})
}

// Scenario 6: deny stops access, including an established connection.
func TestDenyStopsEstablishedFlow(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	vps.Listen("tcp", 9000)
	vps.MustMeshly("allow", "9000/tcp", "from", "home")
	home.MustSh("nohup /opt/it/fileserver -stream 10.100.0.1:9000 >/dev/null 2>&1 &")
	lines := func() int {
		n, _ := strconv.Atoi(strings.TrimSpace(vps.Sh("wc -l < /tmp/recv-tcp-9000 2>/dev/null || echo 0").Out))
		return n
	}
	deadline := time.Now().Add(10 * time.Second)
	for lines() < 5 {
		if time.Now().After(deadline) {
			t.Fatal("stream did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if out := vps.MustSh("conntrack -L -p tcp --dport 9000 2>/dev/null"); !strings.Contains(out, "ESTABLISHED") {
		t.Fatalf("no established flow: %s", out)
	}
	vps.MustMeshly("deny", "9000/tcp", "from", "home")
	time.Sleep(500 * time.Millisecond) // in-flight segments
	before := lines()
	time.Sleep(3 * time.Second)
	if after := lines(); after != before {
		t.Fatalf("established flow continues after deny: %d -> %d lines", before, after)
	}
	if home.Probe("tcp", "10.100.0.1", 9000) {
		t.Fatal("new connections possible after deny")
	}
}

// compromise simulates root on the VPS turning against home: it removes its
// own meshly protections and widens WireGuard allowed-ips and routes.
func compromise(t *testing.T, vps *Node) {
	t.Helper()
	pub := strings.TrimSpace(vps.MustSh("wg show meshly0 peers"))
	vps.MustSh("nft delete table inet meshly")
	vps.MustSh(fmt.Sprintf("wg set meshly0 peer %s allowed-ips 10.100.0.2/32,10.100.0.0/24,192.168.77.0/24 && ip route replace 192.168.77.0/24 dev meshly0", pub))
}

// Scenarios 8–10: spoofed VPN addresses, LAN access, forwarding, DNAT.
func TestCompromisedPeerContained(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	lanhost := l.Node("lanhost")
	home.MustMeshly("allow", "8080/tcp", "from", "vps")
	home.Listen("tcp", 8080)
	home.Listen("tcp", 22)
	lanhost.Listen("tcp", 80)
	if !vps.Probe("tcp", "10.100.0.2", 8080) {
		t.Fatal("baseline: allowed service unreachable")
	}

	// Home acts as a Docker host: forwarding on, a published port DNATed
	// to a "container" in the LAN, plus a local redirect.
	home.MustSh(`sysctl -qw net.ipv4.ip_forward=1 && nft -f - <<'EOF'
table ip dockerlike {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		tcp dport 8888 dnat to 192.168.77.20:80
		tcp dport 8889 redirect to :22
	}
	chain postrouting { type nat hook postrouting priority srcnat; masquerade; }
}
EOF`)
	home.MustMeshly("allow", "8888/tcp", "from", "vps")
	home.MustMeshly("allow", "8889/tcp", "from", "vps")
	if vps.Probe("tcp", "10.100.0.2", 8888) {
		t.Fatal("DNAT through the VPN reaches a LAN host")
	}
	if vps.Probe("tcp", "10.100.0.2", 8889) {
		t.Fatal("local redirect through the VPN reaches a port without a rule")
	}

	compromise(t, vps)
	if vps.Probe("tcp", "192.168.77.20", 80) {
		t.Fatal("compromised peer reaches the home LAN")
	}
	if vps.Probe("tcp", "192.168.77.10", 8080) || vps.Probe("tcp", "192.168.77.10", 22) {
		t.Fatal("compromised peer reaches home via its LAN address")
	}
	if vps.Probe("tcp", "10.100.0.2", 22) {
		t.Fatal("compromised peer reaches a port without a rule")
	}
	// Spoofed inner source address (not the peer's /32).
	vps.MustSh("ip addr add 10.100.0.9/32 dev meshly0")
	if r := vps.Sh("/opt/it/fileserver -probe -tcp-dial 10.100.0.2:8080 -timeout 2s"); r.Code == 0 {
		// The default source is still .1; force .9 with nc.
		_ = r
	}
	if vps.Sh("nc -w2 -s 10.100.0.9 10.100.0.2 8080 </dev/null | grep -q home").Code == 0 {
		t.Fatal("spoofed VPN source address accepted")
	}
	// Forwarding is blocked even if the sysctl drifts.
	home.MustSh("sysctl -qw net.ipv4.conf.meshly0.forwarding=1")
	if vps.Probe("tcp", "192.168.77.20", 80) || vps.Probe("tcp", "10.100.0.2", 8888) {
		t.Fatal("forwarding from the VPN possible after sysctl drift")
	}
	if hits := lanhost.Sh("cat /tmp/hits-tcp-80 2>/dev/null").Out; hits != "" {
		t.Fatalf("LAN host received connections from the VPN: %s", hits)
	}
	if out := home.MustSh("nft list chain inet meshly guard_fwd"); !strings.Contains(out, "packets") || strings.Contains(out, "packets 0 bytes 0 drop comment \"no forwarding from the vpn\"") {
		t.Fatalf("forward guard did not count drops:\n%s", out)
	}
	// Drift is reported and repaired by the check timer's entry point.
	r := home.MustMeshly("status")
	if !strings.Contains(r.Out, "sysctls") {
		t.Fatalf("sysctl drift not reported:\n%s", r.Out)
	}
	home.MustMeshly("service", "check")
	if v := strings.TrimSpace(home.MustSh("sysctl -n net.ipv4.conf.meshly0.forwarding")); v != "0" {
		t.Fatalf("sysctl drift not repaired: forwarding=%s", v)
	}
	// A spoofed source from the home LAN does not pass either.
	lanhost.MustSh("ip addr add 10.100.0.1/32 dev eth0 && ip route replace 10.100.0.2/32 via 192.168.77.10")
	if lanhost.Sh("nc -w2 -s 10.100.0.1 10.100.0.2 8080 </dev/null | grep -q home").Code == 0 {
		t.Fatal("spoofed VPN source from the LAN accepted")
	}
}

// Scenario 11 and "main SSH access is preserved": foreign rules, routes,
// interfaces and services are unchanged by the whole lifecycle.
func TestForeignStatePreserved(t *testing.T) {
	l := newLab(t, distros[0])
	vps, attacker := l.Node("vps"), l.Node("attacker")
	vps.MustSh(`nft -f - <<'EOF'
table inet hostfw {
	counter ssh {}
	chain input { type filter hook input priority 0; policy accept; tcp dport 22 counter name ssh accept; }
}
table ip nat_other { chain post { type nat hook postrouting priority 100; oifname "nowhere" masquerade; } }
EOF
ip link add dummy7 type dummy && ip addr add 172.31.7.1/24 dev dummy7 && ip link set dummy7 up && ip route add 172.31.8.0/24 via 172.31.7.2`)
	vps.Listen("tcp", 22)
	before := vps.Foreign()
	if !attacker.Probe("tcp", "198.51.100.10", 22) {
		t.Fatal("baseline ssh unreachable")
	}
	vps, _ = l.Pair()
	vps.MustMeshly("allow", "22/tcp", "from", "home")
	vps.MustMeshly("set", "mtu", "1380")
	vps.MustMeshly("stop")
	vps.MustMeshly("start")
	if !attacker.Probe("tcp", "198.51.100.10", 22) {
		t.Fatal("public ssh broken while meshly is active")
	}
	if after := vps.Foreign(); after != before {
		t.Fatalf("foreign state changed:\n--- before\n%s\n--- after\n%s", before, after)
	}
	vps.MustMeshly("revoke", "home", "--yes")
	vps.MustMeshly("reset", "--yes")
	if after := vps.Foreign(); after != before {
		t.Fatalf("foreign state changed by reset:\n--- before\n%s\n--- after\n%s", before, after)
	}
	if vps.Sh("ip link show meshly0").Code == 0 || vps.Sh("nft list table inet meshly").Code == 0 {
		t.Fatal("reset left meshly objects behind")
	}
	if vps.Sh("test -e /etc/meshly/meshly.json -o -e /etc/meshly/keys/wireguard.key").Code == 0 {
		t.Fatal("reset left configuration or keys behind")
	}
	if !attacker.Probe("tcp", "198.51.100.10", 22) {
		t.Fatal("public ssh broken after reset")
	}
}

// Scenario 12: NAT mappings expire and are recreated; long idle periods do
// not break the link (persistent keepalive from the NATed side).
func TestNATAndIdle(t *testing.T) {
	if os.Getenv("MESHLY_IT_SHORT") != "" {
		t.Skip("MESHLY_IT_SHORT set")
	}
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	gw := l.Node("natgw")
	home.MustMeshly("allow", "ping", "from", "vps")
	// Aggressive NAT: UDP mappings die after 30s without traffic.
	gw.MustSh("sysctl -qw net.netfilter.nf_conntrack_udp_timeout=30 net.netfilter.nf_conntrack_udp_timeout_stream=30")
	time.Sleep(70 * time.Second)
	if !vps.Ping("10.100.0.2") {
		t.Fatal("VPS cannot reach home after 70s idle behind NAT")
	}
	// The NAT gateway loses all mappings (reboot); home's keepalive
	// recreates one and the VPS follows the new endpoint.
	gw.MustSh("conntrack -F 2>/dev/null; true")
	ok := false
	for i := 0; i < 40 && !ok; i++ {
		ok = vps.Ping("10.100.0.2")
	}
	if !ok {
		t.Fatal("link did not recover after the NAT lost its mappings")
	}
}

// Scenario 13: repeating commands creates no duplicates.
func TestIdempotency(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Node("vps"), l.Node("home")
	vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	snap := vps.KernelSnapshot()
	r := vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	if !strings.Contains(r.Out, "already") || vps.KernelSnapshot() != snap {
		t.Fatalf("second init not idempotent:\n%s", r)
	}
	inv1 := vps.MustMeshly("invite", "--out", "/root/a.invite")
	inv2 := vps.MustMeshly("invite", "--out", "/root/a.invite")
	if string(vps.ReadFile("/root/a.invite")) == "" || !strings.Contains(inv2.Out+inv2.Err, "already") {
		t.Fatalf("second invite is not the same invite:\n%s\n%s", inv1, inv2)
	}
	vps.MustMeshly("invite", "--out", "/root/b.invite")
	if string(vps.ReadFile("/root/a.invite")) != string(vps.ReadFile("/root/b.invite")) {
		t.Fatal("repeated invite produced a different invite")
	}
	vps2, home2 := l.Pair2("/root/a.invite")
	_ = vps2
	home2.MustMeshly("activate", "/root/home.accept") // repeated activate
	vps.MustMeshly("allow", "8080/tcp", "from", "home")
	snap = vps.KernelSnapshot()
	for i := 0; i < 3; i++ {
		r := vps.MustMeshly("allow", "8080/tcp", "from", "home")
		if !strings.Contains(r.Out, "Already allowed") {
			t.Fatalf("repeated allow:\n%s", r)
		}
		vps.MustMeshly("start")
		home.MustMeshly("start")
	}
	if got := vps.KernelSnapshot(); got != snap {
		t.Fatalf("kernel state changed by repeated commands:\n--- before\n%s\n--- after\n%s", snap, got)
	}
	if n := strings.Count(vps.MustMeshly("rules").Out, "8080/tcp from home"); n != 1 {
		t.Fatalf("rule listed %d times", n)
	}
	if n := strings.Count(vps.MustSh("nft list ruleset"), "table inet meshly"); n != 1 {
		t.Fatalf("%d meshly tables", n)
	}
	r = vps.MustMeshly("deny", "8080/tcp", "from", "home")
	r = vps.MustMeshly("deny", "8080/tcp", "from", "home")
	if !strings.Contains(r.Out, "nothing to remove") {
		t.Fatalf("repeated deny:\n%s", r)
	}
}

// Pair2 completes the pairing with an already created invite file.
func (l *Lab) Pair2(invite string) (vps, home *Node) {
	t := l.t
	t.Helper()
	vps, home = l.Node("vps"), l.Node("home")
	home.MustSh("rm -f /root/home.request /root/home.accept")
	vps.MustSh("rm -f /root/home.request /root/home.accept")
	st := vps.MustMeshly("status")
	vpsFP := fingerprint(t, st.Out)
	Transfer(vps, invite, home, "/root/home.invite")
	r := home.MustMeshly("join", "/root/home.invite", "--name", "home", "--expect-fingerprint", vpsFP, "--out", "/root/home.request")
	again := home.MustMeshly("join", "/root/home.invite", "--name", "home", "--expect-fingerprint", vpsFP, "--out", "/root/home.request")
	if !strings.Contains(again.Out+again.Err, "already") {
		t.Fatalf("repeated join is not idempotent:\n%s", again)
	}
	homeFP := fpOf(t, r.Out, "your fingerprint: ")
	Transfer(home, "/root/home.request", vps, "/root/home.request")
	vps.MustMeshly("approve", "/root/home.request", "--expect-fingerprint", homeFP, "--out", "/root/home.accept")
	again = vps.MustMeshly("approve", "/root/home.request", "--expect-fingerprint", homeFP, "--out", "/root/home.accept")
	if !strings.Contains(again.Out+again.Err, "already") {
		t.Fatalf("repeated approve is not idempotent:\n%s", again)
	}
	Transfer(vps, "/root/home.accept", home, "/root/home.accept")
	home.MustMeshly("activate", "/root/home.accept")
	l.WaitHandshake(home, 20*time.Second)
	return vps, home
}

func fpOf(t *testing.T, out, prefix string) string {
	t.Helper()
	i := strings.Index(out, prefix)
	if i < 0 {
		t.Fatalf("no %q in:\n%s", prefix, out)
	}
	f := strings.Fields(out[i+len(prefix):])
	return f[0]
}

// Scenario 14: concurrent operations are serialised.
func TestConcurrentOperations(t *testing.T) {
	l := newLab(t, distros[0])
	vps, _ := l.Pair()
	var wg sync.WaitGroup
	results := make([]Result, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = vps.Meshly("allow", fmt.Sprintf("%d/tcp", 7000+i), "from", "home")
		}(i)
	}
	// status must work (read-only) while operations run.
	st := vps.Meshly("status", "--json")
	wg.Wait()
	for i, r := range results {
		if r.Code != 0 {
			t.Fatalf("allow #%d failed: %s", i, r)
		}
	}
	if st.Code != 0 {
		t.Fatalf("status during operations: %s", st)
	}
	rules := vps.MustMeshly("rules").Out
	for i := range results {
		if !strings.Contains(rules, fmt.Sprintf("%d/tcp from home", 7000+i)) {
			t.Fatalf("rule %d lost:\n%s", 7000+i, rules)
		}
	}
	set := vps.MustSh("nft list set inet meshly allow_in")
	if n := strings.Count(set, ". tcp . 70"); n != len(results) {
		t.Fatalf("kernel set has %d elements, want %d:\n%s", n, len(results), set)
	}
	if r := vps.MustMeshly("status"); strings.Contains(r.Out, "INTERRUPTED") || !strings.Contains(r.Out, "Drift\n  none") {
		t.Fatalf("state after concurrent operations:\n%s", r.Out)
	}
}
