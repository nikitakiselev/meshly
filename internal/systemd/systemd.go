// Package systemd installs Meshly's unit files (embedded in the binary)
// and controls them through systemctl with fixed argument vectors.
package systemd

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/store"
)

//go:embed units/*
var unitFS embed.FS

const (
	Unit      = "meshly.service"
	CheckUnit = "meshly-check.service"
	TimerUnit = "meshly-check.timer"
	systemctl = "/usr/bin/systemctl"
)

// Manager controls Meshly's units.
type Manager struct {
	// Available: PID 1 is systemd and systemctl exists.
	Available bool
	UnitDir   string // /etc/systemd/system
	Root      string // "/" (tests: temp dir)
	Run       func(ctx context.Context, args ...string) ([]byte, error)
}

// New returns the production manager.
func New() *Manager {
	_, e1 := os.Stat("/run/systemd/system")
	_, e2 := os.Stat(systemctl)
	return &Manager{Available: e1 == nil && e2 == nil, UnitDir: "/etc/systemd/system", Root: "/", Run: run}
}

func run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, systemctl, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return out.Bytes(), fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

var safePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// UnitFiles renders the unit files for the given executable and interface.
func UnitFiles(exe, iface string) (map[string][]byte, error) {
	if !safePath.MatchString(exe) || strings.Contains(exe, "..") {
		return nil, fmt.Errorf("executable path %q cannot be used in a unit file", exe)
	}
	// The name is validated by the config already; checked again here
	// because it is pasted into unit files (a newline would add directives).
	if err := model.ValidateInterfaceName(iface); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	entries, err := fs.ReadDir(unitFS, "units")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		b, err := unitFS.ReadFile("units/" + e.Name())
		if err != nil {
			return nil, err
		}
		b = bytes.ReplaceAll(b, []byte("@EXE@"), []byte(exe))
		b = bytes.ReplaceAll(b, []byte("@IFACE@"), []byte(iface))
		out[e.Name()] = b
	}
	return out, nil
}

// Executable returns the resolved path of the running binary.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// Install writes the unit files (only when content differs) and reloads
// systemd. It also tells systemd-networkd and NetworkManager, when
// installed, to leave the interface alone. Returns whether anything
// changed.
func (m *Manager) Install(ctx context.Context, exe, iface string) (bool, error) {
	files, err := UnitFiles(exe, iface)
	if err != nil {
		return false, err
	}
	targets := map[string]string{
		"meshly.service":       filepath.Join(m.UnitDir, Unit),
		"meshly-check.service": filepath.Join(m.UnitDir, CheckUnit),
		"meshly-check.timer":   filepath.Join(m.UnitDir, TimerUnit),
	}
	if dirExists(filepath.Join(m.Root, "etc/systemd/network")) {
		targets["10-meshly-unmanaged.network"] = filepath.Join(m.Root, "etc/systemd/network/10-meshly-unmanaged.network")
	}
	targets["nftables-meshly.conf"] = filepath.Join(m.UnitDir, "nftables.service.d", "50-meshly.conf")
	if dirExists(filepath.Join(m.Root, "etc/NetworkManager/conf.d")) {
		targets["networkmanager-meshly.conf"] = filepath.Join(m.Root, "etc/NetworkManager/conf.d/meshly.conf")
	}
	changed := false
	for name, dst := range targets {
		want := files[name]
		if have, err := os.ReadFile(dst); err == nil && bytes.Equal(have, want) {
			continue
		}
		if st, err := os.Lstat(dst); err == nil && !st.Mode().IsRegular() {
			return false, fmt.Errorf("%s exists and is not a regular file", dst)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return false, err
		}
		if err := store.WriteAtomic(dst, want, 0o644); err != nil {
			return false, fmt.Errorf("install %s: %w", dst, err)
		}
		changed = true
	}
	if changed && m.Available {
		if _, err := m.Run(ctx, "daemon-reload"); err != nil {
			return true, err
		}
	}
	return changed, nil
}

// Uninstall removes Meshly's unit files.
func (m *Manager) Uninstall(ctx context.Context) error {
	var errs []error
	for _, p := range []string{
		filepath.Join(m.UnitDir, Unit), filepath.Join(m.UnitDir, CheckUnit), filepath.Join(m.UnitDir, TimerUnit),
		filepath.Join(m.Root, "etc/systemd/network/10-meshly-unmanaged.network"),
		filepath.Join(m.Root, "etc/NetworkManager/conf.d/meshly.conf"),
		filepath.Join(m.UnitDir, "nftables.service.d", "50-meshly.conf"),
	} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(filepath.Join(m.UnitDir, "nftables.service.d")) // only if empty
	if m.Available {
		if _, err := m.Run(ctx, "daemon-reload"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Installed reports whether the main unit file exists.
func (m *Manager) Installed() bool {
	_, err := os.Stat(filepath.Join(m.UnitDir, Unit))
	return err == nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// Enable enables the service and the check timer at boot.
func (m *Manager) Enable(ctx context.Context) error {
	_, err := m.Run(ctx, "enable", "--quiet", Unit, TimerUnit)
	return err
}

// Disable disables autostart.
func (m *Manager) Disable(ctx context.Context) error {
	_, err := m.Run(ctx, "disable", "--quiet", Unit, TimerUnit)
	return err
}

// Start starts the service and timer (no-op when active).
func (m *Manager) Start(ctx context.Context) error {
	_, err := m.Run(ctx, "start", Unit, TimerUnit)
	return err
}

// Stop stops the service (its ExecStop tears the link down) and timer.
func (m *Manager) Stop(ctx context.Context) error {
	_, err := m.Run(ctx, "stop", TimerUnit, Unit)
	return err
}

// Restart restarts the service.
func (m *Manager) Restart(ctx context.Context) error {
	_, err := m.Run(ctx, "restart", Unit)
	return err
}

// State returns ActiveState and UnitFileState of a unit.
func (m *Manager) State(ctx context.Context, unit string) (active, enabled string) {
	if !m.Available {
		return "unavailable", "unavailable"
	}
	out, _ := m.Run(ctx, "show", "--property=ActiveState,UnitFileState,Result", unit)
	for _, l := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "ActiveState":
			active = v
		case "UnitFileState":
			enabled = v
		}
	}
	if active == "" {
		active = "unknown"
	}
	if enabled == "" {
		enabled = "unknown"
	}
	return active, enabled
}
