package systemd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testExe = "/usr/local/bin/meshly"

func TestUnitFiles(t *testing.T) {
	files, err := UnitFiles(testExe, "meshly0")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	want := []string{
		"10-meshly-unmanaged.network", "meshly-check.service", "meshly-check.timer",
		"meshly.service", "networkmanager-meshly.conf", "nftables-meshly.conf",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("unit files = %v, want %v", names, want)
	}
	for name, b := range files {
		if bytes.Contains(b, []byte("@EXE@")) || bytes.Contains(b, []byte("@IFACE@")) {
			t.Errorf("%s: placeholder left unsubstituted", name)
		}
		if !bytes.HasPrefix(b, []byte("# Managed by meshly")) {
			t.Errorf("%s: missing the managed-by header", name)
		}
	}
	svc := string(files["meshly.service"])
	for _, line := range []string{
		"ExecStart=/usr/local/bin/meshly service start",
		"ExecReload=/usr/local/bin/meshly service reload",
		"ExecStop=/usr/local/bin/meshly service stop",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"NoNewPrivileges=yes",
		"After=nftables.service network-pre.target",
		"Also=meshly-check.timer",
	} {
		if !strings.Contains(svc, line+"\n") {
			t.Errorf("meshly.service lacks %q", line)
		}
	}
	if !strings.Contains(string(files["meshly-check.service"]), "ExecStart=/usr/local/bin/meshly service check\n") {
		t.Error("meshly-check.service ExecStart not substituted")
	}
	if !strings.Contains(string(files["10-meshly-unmanaged.network"]), "Name=meshly0\n") {
		t.Error("networkd file does not match the interface")
	}
	if !strings.Contains(string(files["networkmanager-meshly.conf"]), "unmanaged-devices=interface-name:meshly0\n") {
		t.Error("NetworkManager file does not match the interface")
	}
	if !strings.Contains(string(files["nftables-meshly.conf"]), "ExecStartPost=-/usr/bin/systemctl --no-block try-reload-or-restart meshly.service") {
		t.Error("nftables drop-in content unexpected")
	}

	other, err := UnitFiles("/opt/meshly/bin/meshly-1.2", "wg7")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(other["meshly.service"]), "ExecStart=/opt/meshly/bin/meshly-1.2 service start\n") ||
		!strings.Contains(string(other["10-meshly-unmanaged.network"]), "Name=wg7\n") {
		t.Error("substitution does not follow the arguments")
	}
}

func TestUnitFilesRejectsUnsafeExe(t *testing.T) {
	for _, exe := range []string{
		"",
		"meshly",
		"./meshly",
		"bin/meshly",
		"/usr/local/bin/mesh ly",
		"/usr/local/bin/meshly\n",
		"/usr/local/bin/meshly\nExecStartPre=/bin/sh",
		"/usr/local/../bin/meshly",
		"/usr/local/bin/..",
		"/opt/a..b/meshly", // any ".." is refused, not only path traversal
		"/usr/bin/meshly;reboot",
		"/usr/bin/$meshly",
		"/usr/bin/meshly%i", // systemd specifier
		"/usr/bin/\"meshly\"",
		"/usr/bin/me\\shly",
		"/usr/bin/méshly",
		"/usr/bin/meshly\t",
	} {
		if _, err := UnitFiles(exe, "meshly0"); err == nil || !strings.Contains(err.Error(), "cannot be used in a unit file") {
			t.Errorf("UnitFiles(%q) = %v, want refusal", exe, err)
		}
	}
	for _, exe := range []string{"/m", "/usr/sbin/meshly", "/opt/meshly-1.0_rc/bin/meshly.bin", "/a/./b"} {
		if _, err := UnitFiles(exe, "meshly0"); err != nil {
			t.Errorf("UnitFiles(%q) = %v", exe, err)
		}
	}
}

type fakeRun struct {
	calls [][]string
	out   []byte
	err   error
}

func (f *fakeRun) run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	return f.out, f.err
}

func newManager(t *testing.T) (*Manager, *fakeRun) {
	t.Helper()
	root := t.TempDir()
	f := &fakeRun{}
	return &Manager{Available: true, Root: root, UnitDir: filepath.Join(root, "etc/systemd/system"), Run: f.run}, f
}

func (m *Manager) nftDropIn() string {
	return filepath.Join(m.UnitDir, "nftables.service.d", "50-meshly.conf")
}
func (m *Manager) networkdFile() string {
	return filepath.Join(m.Root, "etc/systemd/network/10-meshly-unmanaged.network")
}
func (m *Manager) nmFile() string {
	return filepath.Join(m.Root, "etc/NetworkManager/conf.d/meshly.conf")
}

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

func TestInstall(t *testing.T) {
	ctx := context.Background()
	m, f := newManager(t)
	files, _ := UnitFiles(testExe, "meshly0")

	changed, err := m.Install(ctx, testExe, "meshly0")
	if err != nil || !changed {
		t.Fatalf("Install = %v, %v", changed, err)
	}
	for name, path := range map[string]string{
		"meshly.service":       filepath.Join(m.UnitDir, Unit),
		"meshly-check.service": filepath.Join(m.UnitDir, CheckUnit),
		"meshly-check.timer":   filepath.Join(m.UnitDir, TimerUnit),
		"nftables-meshly.conf": m.nftDropIn(),
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s not installed: %v", path, err)
			continue
		}
		if !bytes.Equal(b, files[name]) {
			t.Errorf("%s content differs from %s", path, name)
		}
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v, want 0644", path, st.Mode())
		}
	}
	if exists(m.networkdFile()) || exists(m.nmFile()) {
		t.Error("networkd/NetworkManager files installed although those directories do not exist")
	}
	if !slices.EqualFunc(f.calls, [][]string{{"daemon-reload"}}, slices.Equal) {
		t.Errorf("systemctl calls = %v", f.calls)
	}
	if !m.Installed() {
		t.Error("Installed = false after Install")
	}

	// Unchanged content: nothing written, no daemon-reload.
	f.calls = nil
	before, _ := os.Stat(filepath.Join(m.UnitDir, Unit))
	changed, err = m.Install(ctx, testExe, "meshly0")
	if err != nil || changed {
		t.Errorf("second Install = %v, %v; want unchanged", changed, err)
	}
	if len(f.calls) != 0 {
		t.Errorf("systemctl called for unchanged units: %v", f.calls)
	}
	if after, _ := os.Stat(filepath.Join(m.UnitDir, Unit)); !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, after) {
		t.Error("unchanged unit file was rewritten")
	}

	// A new executable path rewrites the units and reloads.
	changed, err = m.Install(ctx, "/usr/bin/meshly", "meshly0")
	if err != nil || !changed || len(f.calls) != 1 {
		t.Errorf("Install with a new exe = %v, %v, calls %v", changed, err, f.calls)
	}
	if b, _ := os.ReadFile(filepath.Join(m.UnitDir, Unit)); !bytes.Contains(b, []byte("ExecStart=/usr/bin/meshly service start")) {
		t.Error("unit not updated for the new executable")
	}

	// A locally modified unit is restored.
	f.calls = nil
	if err := os.WriteFile(filepath.Join(m.UnitDir, TimerUnit), []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err = m.Install(ctx, "/usr/bin/meshly", "meshly0")
	if err != nil || !changed || len(f.calls) != 1 {
		t.Errorf("Install after local edit = %v, %v, calls %v", changed, err, f.calls)
	}
	if b, _ := os.ReadFile(filepath.Join(m.UnitDir, TimerUnit)); bytes.Equal(b, []byte("edited")) {
		t.Error("edited unit not restored")
	}
}

func TestInstallNetworkManagers(t *testing.T) {
	ctx := context.Background()
	m, _ := newManager(t)
	for _, d := range []string{"etc/systemd/network", "etc/NetworkManager/conf.d"} {
		if err := os.MkdirAll(filepath.Join(m.Root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Install(ctx, testExe, "wg5"); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(m.networkdFile()); err != nil || !bytes.Contains(b, []byte("Name=wg5\n")) {
		t.Errorf("networkd file: %q, %v", b, err)
	}
	if b, err := os.ReadFile(m.nmFile()); err != nil || !bytes.Contains(b, []byte("interface-name:wg5\n")) {
		t.Errorf("NetworkManager file: %q, %v", b, err)
	}

	// Only networkd present.
	m2, _ := newManager(t)
	if err := os.MkdirAll(filepath.Join(m2.Root, "etc/systemd/network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Install(ctx, testExe, "meshly0"); err != nil {
		t.Fatal(err)
	}
	if !exists(m2.networkdFile()) || exists(m2.nmFile()) || exists(filepath.Join(m2.Root, "etc/NetworkManager")) {
		t.Error("NetworkManager config installed without NetworkManager")
	}
}

func TestInstallUnavailable(t *testing.T) {
	m, f := newManager(t)
	m.Available = false
	changed, err := m.Install(context.Background(), testExe, "meshly0")
	if err != nil || !changed {
		t.Fatalf("Install = %v, %v", changed, err)
	}
	if len(f.calls) != 0 {
		t.Errorf("systemctl called without systemd: %v", f.calls)
	}
	if err := m.Uninstall(context.Background()); err != nil || len(f.calls) != 0 {
		t.Errorf("Uninstall = %v, calls %v", err, f.calls)
	}
}

func TestInstallErrors(t *testing.T) {
	ctx := context.Background()

	m, f := newManager(t)
	if _, err := m.Install(ctx, "relative/meshly", "meshly0"); err == nil {
		t.Error("unsafe exe accepted")
	}
	if exists(m.UnitDir) || len(f.calls) != 0 {
		t.Error("files written or systemctl called for an unsafe exe")
	}

	// A symlink planted at a target is refused, and its target untouched.
	m, _ = newManager(t)
	if err := os.MkdirAll(m.UnitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(m.Root, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(m.UnitDir, Unit)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Install(ctx, testExe, "meshly0"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Install over a symlink = %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Errorf("symlink target modified: %q", b)
	}

	// A directory at a target is refused.
	m, _ = newManager(t)
	if err := os.MkdirAll(filepath.Join(m.UnitDir, TimerUnit), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Install(ctx, testExe, "meshly0"); err == nil {
		t.Error("Install over a directory succeeded")
	}

	// daemon-reload failure is reported with changed=true.
	m, f = newManager(t)
	f.err = errors.New("reload failed")
	changed, err := m.Install(ctx, testExe, "meshly0")
	if !changed || !errors.Is(err, f.err) {
		t.Errorf("Install with failing reload = %v, %v", changed, err)
	}
}

func TestUninstall(t *testing.T) {
	ctx := context.Background()
	m, f := newManager(t)
	for _, d := range []string{"etc/systemd/network", "etc/NetworkManager/conf.d"} {
		if err := os.MkdirAll(filepath.Join(m.Root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Install(ctx, testExe, "meshly0"); err != nil {
		t.Fatal(err)
	}
	// An unrelated unit and the admin's own drop-in survive.
	unrelated := filepath.Join(m.UnitDir, "ssh.service")
	if err := os.WriteFile(unrelated, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(m.UnitDir, Unit), filepath.Join(m.UnitDir, CheckUnit), filepath.Join(m.UnitDir, TimerUnit),
		m.nftDropIn(), filepath.Join(m.UnitDir, "nftables.service.d"), m.networkdFile(), m.nmFile(),
	} {
		if exists(p) {
			t.Errorf("%s still exists", p)
		}
	}
	if !exists(unrelated) || !exists(filepath.Join(m.Root, "etc/systemd/network")) || !exists(filepath.Join(m.Root, "etc/NetworkManager/conf.d")) {
		t.Error("Uninstall removed files it does not own")
	}
	if !slices.EqualFunc(f.calls, [][]string{{"daemon-reload"}}, slices.Equal) {
		t.Errorf("systemctl calls = %v", f.calls)
	}
	if m.Installed() {
		t.Error("Installed = true after Uninstall")
	}

	// Idempotent; a non-empty nftables.service.d is kept.
	if _, err := m.Install(ctx, testExe, "meshly0"); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(m.UnitDir, "nftables.service.d", "10-admin.conf")
	if err := os.WriteFile(own, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := m.Uninstall(ctx); err != nil {
			t.Fatalf("Uninstall #%d: %v", i, err)
		}
	}
	if !exists(own) || exists(m.nftDropIn()) {
		t.Error("Uninstall touched the administrator's drop-in or left ours")
	}

	// daemon-reload errors are reported.
	f.err = errors.New("reload failed")
	if err := m.Uninstall(ctx); !errors.Is(err, f.err) {
		t.Errorf("Uninstall with failing reload = %v", err)
	}
}

func TestControlArgv(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		call func(*Manager, context.Context) error
		want []string
	}{
		{"Enable", (*Manager).Enable, []string{"enable", "--quiet", "meshly.service", "meshly-check.timer"}},
		{"Disable", (*Manager).Disable, []string{"disable", "--quiet", "meshly.service", "meshly-check.timer"}},
		{"Start", (*Manager).Start, []string{"start", "meshly.service", "meshly-check.timer"}},
		{"Stop", (*Manager).Stop, []string{"stop", "meshly-check.timer", "meshly.service"}},
		{"Restart", (*Manager).Restart, []string{"restart", "meshly.service"}},
	}
	for _, tt := range tests {
		m, f := newManager(t)
		if err := tt.call(m, ctx); err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
		if len(f.calls) != 1 || !slices.Equal(f.calls[0], tt.want) {
			t.Errorf("%s: systemctl %v, want %v", tt.name, f.calls, tt.want)
		}
		boom := errors.New("unit failed")
		f.err = boom
		if err := tt.call(m, ctx); !errors.Is(err, boom) {
			t.Errorf("%s: error not propagated: %v", tt.name, err)
		}
	}
}

func TestState(t *testing.T) {
	ctx := context.Background()
	m, f := newManager(t)
	f.out = []byte("ActiveState=active\nUnitFileState=enabled\nResult=success\n")
	active, enabled := m.State(ctx, Unit)
	if active != "active" || enabled != "enabled" {
		t.Errorf("State = %q, %q", active, enabled)
	}
	if len(f.calls) != 1 || !slices.Equal(f.calls[0], []string{"show", "--property=ActiveState,UnitFileState,Result", "meshly.service"}) {
		t.Errorf("systemctl %v", f.calls)
	}

	f.out = []byte("  ActiveState=failed  \r\n")
	if active, enabled := m.State(ctx, TimerUnit); active != "failed" || enabled != "unknown" {
		t.Errorf("State(partial) = %q, %q", active, enabled)
	}
	f.out, f.err = nil, errors.New("no such unit")
	if active, enabled := m.State(ctx, Unit); active != "unknown" || enabled != "unknown" {
		t.Errorf("State(error) = %q, %q", active, enabled)
	}
	m.Available = false
	f.calls = nil
	if active, enabled := m.State(ctx, Unit); active != "unavailable" || enabled != "unavailable" || len(f.calls) != 0 {
		t.Errorf("State(unavailable) = %q, %q, calls %v", active, enabled, f.calls)
	}
}
