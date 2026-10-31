//go:build integration

package integration

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A signed release can pass version/signature validation yet fail to start
// its service. Recovery must restart the old binary even though systemd is
// now failed, then verify both the service and the allowed packet path.
func TestUpgradeRollbackRestoresRunningService(t *testing.T) {
	l := newSystemdLab(t)
	vps, home := l.Pair()
	vps.MustMeshly("allow", "8080/tcp", "from", "home")
	vps.Listen("tcp", 8080)
	if !home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("allowed service unreachable before upgrade")
	}
	root := t.TempDir()
	signedFailingServiceRelease(t, root, "0.0.3")
	signedRelease(t, root, "0.0.4", false)
	l.mustDocker("cp", root+"/.", vps.Container+":/srv/releases")
	vps.MustSh("nohup /opt/it/fileserver -serve-dir /srv/releases -listen 127.0.0.1:8000 >/dev/null 2>&1 & sleep 0.3")
	env := "MESHLY_TEST_RELEASE_URL=http://127.0.0.1:8000"
	r := vps.ExpectCode(7, env, "upgrade", "--version", "0.0.3", "--yes")
	if !strings.Contains(r.Err, "0.0.1 is running") {
		t.Fatalf("rollback result: %s", r)
	}
	if got := strings.TrimSpace(vps.MustMeshly("version", "--short").Out); got != "0.0.1" {
		t.Fatalf("restored binary version = %q", got)
	}
	if got := strings.TrimSpace(vps.MustSh("systemctl is-active meshly.service")); got != "active" {
		t.Fatalf("restored service = %q", got)
	}
	if !strings.Contains(vps.MustSh("journalctl -u meshly.service --no-pager"), "integration release refuses service start") {
		t.Fatal("new release did not exercise a failed service start")
	}
	waitFor(t, "allowed TCP after upgrade rollback", 25*time.Second, func() bool { return home.Probe("tcp", "10.100.0.1", 8080) })

	// An explicit systemctl stop leaves admin state up; upgrade must still
	// preserve that stop instead of starting the new release from the config.
	vps.MustSh("systemctl stop meshly.service")
	vps.MustSh("printf '\\n# stale-upgrade-unit-marker\\n' >> /etc/systemd/system/meshly.service")
	vps.MustMeshly(env, "upgrade", "--version", "0.0.4", "--yes")
	if strings.Contains(string(vps.ReadFile("/etc/systemd/system/meshly.service")), "stale-upgrade-unit-marker") {
		t.Fatal("upgrade left stale unit files while service was stopped")
	}
	if got := strings.TrimSpace(vps.MustMeshly("version", "--short").Out); got != "0.0.4" {
		t.Fatalf("stopped upgrade version = %q", got)
	}
	if got := strings.TrimSpace(vps.Sh("systemctl is-active meshly.service").Out); got != "inactive" {
		t.Fatalf("upgrade started intentionally stopped service: %q", got)
	}
	if linkUp(vps) {
		t.Fatal("upgrade restored an intentionally stopped VPN")
	}
}

// Build a genuine meshly release with only its service-start entry point
// broken. A Go overlay keeps this test fixture out of the production tree.
func signedFailingServiceRelease(t *testing.T, root, ver string) {
	t.Helper()
	tmp := t.TempDir()
	source := filepath.Join(repoRoot(), "internal", "cli", "cmd_lifecycle.go")
	original, err := os.ReadFile(source)
	must(t, err)
	entry := "func (a *App) cmdService(ctx context.Context, args []string) error {"
	if strings.Count(string(original), entry) != 1 {
		t.Fatal("cannot locate service entry point for failing release")
	}
	broken := strings.Replace(string(original), entry, entry+`
 if len(args) > 0 && args[0] == "start" { return fmt.Errorf("integration release refuses service start") }
`, 1)
	replacement := filepath.Join(tmp, "cmd_lifecycle.go")
	must(t, os.WriteFile(replacement, []byte(broken), 0o600))
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Clean(source): replacement}})
	must(t, err)
	overlayFile := filepath.Join(tmp, "overlay.json")
	must(t, os.WriteFile(overlayFile, overlay, 0o600))
	pub := base64.StdEncoding.EncodeToString(testKey.Public().(ed25519.PublicKey))
	ld := fmt.Sprintf("-X github.com/nikitakiselev/meshly/internal/version.Version=%s -X github.com/nikitakiselev/meshly/internal/upgrade.ReleaseKey=%s", ver, pub)
	binary := filepath.Join(tmp, "meshly")
	cmd := exec.Command("go", "build", "-tags", "meshly_faultinject", "-overlay", overlayFile, "-ldflags", ld, "-o", binary, "./cmd/meshly")
	cmd.Dir = repoRoot()
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failing service release: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(binary)
	must(t, err)
	asset := fmt.Sprintf("meshly-%s-linux-%s", ver, goarch)
	sums := []byte(fmt.Sprintf("%s  %s\n", sha256hex(bin), asset))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(testKey, append([]byte("meshly-release/1\x00"), sums...)))
	dir := filepath.Join(root, "download", "v"+ver)
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, asset), bin, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte(sig+"\n"), 0o644))
}
