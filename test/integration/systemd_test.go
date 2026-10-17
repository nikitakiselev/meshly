//go:build integration

package integration

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, timeout time.Duration, f func() bool) {
	t.Helper()
	start := time.Now()
	for !f() {
		if time.Since(start) > timeout {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("%s: after %s", what, time.Since(start).Round(100*time.Millisecond))
}

func linkUp(n *Node) bool {
	return n.Sh("ip link show meshly0 | grep -q 'state UNKNOWN\\|state UP' && nft list table inet meshly >/dev/null").Code == 0
}

// Reboot, systemd stop/start, persistent `meshly stop`, recovery at boot,
// nftables reload and the check timer.
func TestSystemdLifecycle(t *testing.T) {
	l := newSystemdLab(t)
	vps, home := l.Pair()
	for _, n := range []*Node{vps, home} {
		if out := n.MustSh("systemctl is-enabled meshly.service meshly-check.timer; systemctl is-active meshly.service meshly-check.timer"); strings.Join(strings.Fields(out), " ") != "enabled enabled active active" {
			t.Fatalf("%s: units not enabled/active after setup:\n%s", n.Name, out)
		}
	}
	vps.MustMeshly("allow", "8080/tcp", "from", "home")
	vps.Listen("tcp", 8080)

	l.Run("reboot", func(t *testing.T) {
		vps.Reboot()
		home.Reboot()
		if !linkUp(vps) || !linkUp(home) {
			t.Fatal("link not restored after reboot")
		}
		l.WaitHandshake(home, 30*time.Second)
		vps.Listen("tcp", 8080)
		if !home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("allowed service unreachable after reboot")
		}
		// Protection before the tunnel: the boot transaction installed
		// the firewall table before creating the interface.
		var logs struct {
			Records []struct {
				Event, Op string
				Plan      []string
			}
		}
		r := vps.MustMeshly("logs", "--json", "-n", "50")
		must(t, json.Unmarshal([]byte(r.Out), &logs))
		var plan []string
		for _, rec := range logs.Records {
			if rec.Event == "begin" && rec.Op == "service-start" {
				plan = rec.Plan
			}
		}
		if len(plan) < 2 || plan[0] != "firewall.apply" || !slices.Contains(plan, "link.create") {
			t.Fatalf("boot plan does not install the firewall before the interface: %v\n%s", plan, r.Out)
		}
		if out := vps.MustSh("systemctl show meshly.service -p Result --value"); strings.TrimSpace(out) != "success" {
			t.Fatalf("meshly.service result: %s", out)
		}
	})

	l.Run("systemctl-stop-start", func(t *testing.T) {
		vps.MustSh("systemctl stop meshly.service")
		if vps.Sh("ip link show meshly0").Code == 0 || vps.Sh("nft list table inet meshly").Code == 0 {
			t.Fatal("systemctl stop left the link or table")
		}
		if r := vps.MustMeshly("status"); !strings.Contains(r.Out, "admin state  up") {
			t.Fatalf("systemctl stop must not change the configuration:\n%s", r.Out)
		}
		vps.MustSh("systemctl start meshly.service")
		waitFor(t, "link up", 10*time.Second, func() bool { return linkUp(vps) })
		vps.MustSh("systemctl restart meshly.service")
		waitFor(t, "link up after restart", 10*time.Second, func() bool { return linkUp(vps) })
		waitFor(t, "service after restart", 20*time.Second, func() bool { return home.Probe("tcp", "10.100.0.1", 8080) })
	})

	l.Run("meshly-stop-persists", func(t *testing.T) {
		vps.MustMeshly("stop")
		if vps.Sh("ip link show meshly0").Code == 0 {
			t.Fatal("link up after meshly stop")
		}
		vps.Reboot()
		if vps.Sh("ip link show meshly0").Code == 0 || vps.Sh("nft list table inet meshly").Code == 0 {
			t.Fatal("meshly stop did not survive reboot")
		}
		vps.MustMeshly("start")
		waitFor(t, "link up", 10*time.Second, func() bool { return linkUp(vps) })
		if out := vps.MustSh("systemctl is-active meshly.service"); strings.TrimSpace(out) != "active" {
			t.Fatalf("service not active after meshly start: %s", out)
		}
		vps.MustMeshly("restart")
		waitFor(t, "link up after meshly restart", 10*time.Second, func() bool { return linkUp(vps) })
	})

	l.Run("recovery-at-boot", func(t *testing.T) {
		r := vps.Meshly("MESHLY_FAULT=tx:before-save=crash", "allow", "9999/tcp", "from", "home")
		if r.Code != 137 {
			t.Fatalf("want crash: %s", r)
		}
		vps.Reboot()
		s := status(t, vps)
		if s.Transaction.Incomplete || len(s.Drift) != 0 {
			t.Fatalf("not recovered at boot: %+v", s)
		}
		if strings.Contains(vps.MustMeshly("rules").Out, "9999") {
			t.Fatal("interrupted allow became effective")
		}
		if out := vps.MustMeshly("logs").Out; !strings.Contains(out, "recovered") {
			t.Fatalf("no recovery record:\n%s", out)
		}
	})

	l.Run("nftables-reload", func(t *testing.T) {
		vps.MustSh(`cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet hostfw {
	chain input {
		type filter hook input priority 0; policy accept;
	}
}
EOF
systemctl enable --now nftables.service`)
		waitFor(t, "meshly table after nftables start", 15*time.Second, func() bool { return linkUp(vps) })
		for _, action := range []string{"reload", "restart"} {
			vps.MustSh("systemctl " + action + " nftables.service")
			waitFor(t, "meshly table after nftables "+action, 15*time.Second, func() bool {
				return vps.Sh("nft list table inet meshly >/dev/null && nft list table inet hostfw >/dev/null").Code == 0 && linkUp(vps)
			})
		}
		vps.Listen("tcp", 8080) // earlier reboots killed the listener
		// After the restart the VPS has a new interface without sessions; it
		// re-initiates the handshake to home's last learned endpoint.
		waitFor(t, "service through the VPN after nftables restart", 20*time.Second, func() bool {
			return home.Probe("tcp", "10.100.0.1", 8080)
		})
		if r := vps.Meshly("doctor"); !strings.Contains(r.Out, "flush ruleset") {
			t.Fatalf("doctor does not warn about flush ruleset:\n%s", r.Out)
		}
	})

	l.Run("check-timer", func(t *testing.T) {
		if out := vps.MustSh("systemctl list-timers meshly-check.timer --no-legend"); !strings.Contains(out, "meshly-check") {
			t.Fatalf("timer not scheduled: %s", out)
		}
		vps.MustSh("nft delete table inet meshly")
		vps.MustSh("systemctl start meshly-check.service") // what the timer fires
		if vps.Sh("nft list table inet meshly").Code != 0 {
			t.Fatal("check did not restore the table")
		}
	})
	// Safe mode while the service is active: the VPN stays closed until
	// the check retries the saved (last committed) configuration, which
	// does not include the change that failed.
	l.Run("safe-mode-retried-by-check", func(t *testing.T) {
		r := vps.Meshly("MESHLY_FAULT=step:firewall.apply=error,tx:rollback=error", "allow", "8081/tcp", "from", "home")
		if r.Code != 8 {
			t.Fatalf("want exit 8 (safe mode): %s", r)
		}
		if vps.Sh("ip link show meshly0").Code == 0 {
			t.Fatal("interface still present in safe mode")
		}
		vps.MustSh("systemctl start meshly-check.service")
		if vps.Sh("ip link show meshly0").Code != 0 {
			t.Fatal("check did not retry the saved configuration")
		}
		l.WaitHandshake(home, 40*time.Second)
		if strings.Contains(vps.MustMeshly("rules").Out, "8081/tcp") {
			t.Fatal("the failed allow is in the saved configuration")
		}
		if out := vps.MustMeshly("logs", "-n", "5").Out; !strings.Contains(out, "check-repair") {
			t.Fatalf("repair not journaled:\n%s", out)
		}
	})
}

// Install from scratch with install.sh, upgrade with signature checks,
// rollback protection and uninstall.
func TestInstallUpgradeUninstall(t *testing.T) {
	l := newSystemdLab(t)
	vps := l.Node("vps")
	vps.MustSh("rm -f /usr/local/bin/meshly")
	before := vps.Foreign()

	root := t.TempDir()
	signedRelease(t, root, "0.0.1", false)
	signedRelease(t, root, "0.0.2", true)
	pub := base64.StdEncoding.EncodeToString(testKey.Public().(ed25519.PublicKey))
	sh, err := os.ReadFile(filepath.Join(repoRoot(), "scripts", "install.sh"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(root, "latest", "download", "install.sh"), []byte(strings.ReplaceAll(string(sh), "@RELEASE_KEY@", pub)), 0o644))
	// Serve the release tree on the node's loopback (stands in for GitHub).
	l.mustDocker("cp", root+"/.", vps.Container+":/srv/releases")
	vps.MustSh("nohup /opt/it/fileserver -serve-dir /srv/releases -listen 127.0.0.1:8000 >/dev/null 2>&1 & sleep 0.3")
	base := "http://127.0.0.1:8000"

	l.Run("install.sh", func(t *testing.T) {
		r := vps.Sh("MESHLY_BASE_URL=" + base + " MESHLY_VERSION=0.0.1 sh /srv/releases/latest/download/install.sh")
		if r.Code != 0 || !strings.Contains(r.Out, "Signature of SHA256SUMS verified") {
			t.Fatalf("install.sh: %s", r)
		}
		if v := strings.TrimSpace(vps.MustSh("meshly version --short")); v != "0.0.1" {
			t.Fatalf("installed version %s", v)
		}
		// A tampered binary or SHA256SUMS is refused.
		vps.MustSh("cp -a /srv/releases /srv/evil && echo 'x' >> /srv/evil/download/v0.0.1/SHA256SUMS")
		r = vps.Sh("MESHLY_BASE_URL=http://127.0.0.1:8000/../evil MESHLY_VERSION=0.0.1 sh /srv/releases/latest/download/install.sh")
		if r.Code == 0 {
			// the file server does not resolve "..": serve the copy instead
			t.Log("note: path traversal not served")
		}
		vps.MustSh("nohup /opt/it/fileserver -serve-dir /srv/evil -listen 127.0.0.1:8001 >/dev/null 2>&1 & sleep 0.3")
		r = vps.Sh("MESHLY_BASE_URL=http://127.0.0.1:8001 MESHLY_VERSION=0.0.1 sh /srv/releases/latest/download/install.sh")
		if r.Code == 0 || !strings.Contains(r.Err, "SIGNATURE VERIFICATION FAILED") {
			t.Fatalf("tampered SHA256SUMS accepted: %s", r)
		}
		vps.MustSh("printf 'garbage' >> /srv/evil/download/v0.0.1/meshly-0.0.1-linux-" + goarch + " && cp /srv/releases/download/v0.0.1/SHA256SUMS /srv/evil/download/v0.0.1/SHA256SUMS")
		r = vps.Sh("MESHLY_BASE_URL=http://127.0.0.1:8001 MESHLY_VERSION=0.0.1 sh /srv/releases/latest/download/install.sh")
		if r.Code == 0 || !strings.Contains(r.Err, "SHA-256") {
			t.Fatalf("tampered binary accepted: %s", r)
		}
		if v := strings.TrimSpace(vps.MustSh("meshly version --short")); v != "0.0.1" {
			t.Fatalf("a refused install changed the binary: %s", v)
		}
	})

	vps, home := l.Pair()
	vps.MustMeshly("allow", "8080/tcp", "from", "home")
	vps.Listen("tcp", 8080)

	l.Run("upgrade", func(t *testing.T) {
		env := "MESHLY_TEST_RELEASE_URL=" + base
		r := vps.MustMeshly(env, "upgrade", "--check")
		if !strings.Contains(r.Out, "0.0.1 → 0.0.2") {
			t.Fatalf("upgrade --check: %s", r)
		}
		vps.ExpectCode(10, env, "upgrade") // non-interactive needs --yes
		r = vps.MustMeshly(env, "upgrade", "--yes")
		if !strings.Contains(r.Out, "restarted on 0.0.2") {
			t.Fatalf("upgrade: %s", r)
		}
		if v := strings.TrimSpace(vps.MustSh("meshly version --short")); v != "0.0.2" {
			t.Fatalf("version after upgrade: %s", v)
		}
		if v := strings.TrimSpace(vps.MustSh("/usr/local/bin/meshly.prev version --short")); v != "0.0.1" {
			t.Fatalf("previous binary not kept: %s", v)
		}
		waitFor(t, "link after upgrade", 15*time.Second, func() bool { return linkUp(vps) })
		waitFor(t, "service after upgrade", 20*time.Second, func() bool { return home.Probe("tcp", "10.100.0.1", 8080) })
		r = vps.MustMeshly(env, "upgrade", "--yes")
		if !strings.Contains(r.Out, "already installed") {
			t.Fatalf("repeated upgrade: %s", r)
		}
		// Downgrade needs --force; a forged release is refused.
		vps.ExpectCode(5, env, "upgrade", "--version", "0.0.1", "--yes")
		vps.MustSh("cd /srv/releases/download/v0.0.1 && sed -i 's/^./0/' SHA256SUMS")
		vps.ExpectCode(4, env, "upgrade", "--version", "0.0.1", "--force", "--yes")
		if v := strings.TrimSpace(vps.MustSh("meshly version --short")); v != "0.0.2" {
			t.Fatalf("refused upgrade changed the binary: %s", v)
		}
	})

	l.Run("uninstall", func(t *testing.T) {
		vps.MustMeshly("revoke", "home", "--yes")
		vps.MustMeshly("reset", "--yes")
		vps.MustSh("rm -f /usr/local/bin/meshly /usr/local/bin/meshly.prev")
		for _, f := range []string{"/etc/systemd/system/meshly.service", "/etc/systemd/system/meshly-check.timer", "/etc/meshly/meshly.json", "/etc/meshly/keys/wireguard.key"} {
			if vps.Sh("test -e "+f).Code == 0 {
				t.Fatalf("%s left after uninstall", f)
			}
		}
		if vps.Sh("systemctl is-active meshly.service").Code == 0 {
			t.Fatal("service still active")
		}
		if vps.Sh("ip link show meshly0").Code == 0 || vps.Sh("nft list table inet meshly").Code == 0 {
			t.Fatal("kernel objects left after uninstall")
		}
		vps.MustSh("pkill -f '^/opt/it/fileserver -serve-dir' || true")
		if after := vps.Foreign(); after != before {
			t.Fatalf("foreign state changed:\n%s\n---\n%s", before, after)
		}
	})
}
