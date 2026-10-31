package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/fault"
	"github.com/nikitakiselev/meshly/internal/lock"
	"github.com/nikitakiselev/meshly/internal/systemd"
	"github.com/nikitakiselev/meshly/internal/upgrade"
	"github.com/nikitakiselev/meshly/internal/version"
)

func (a *App) upgradeClient() *upgrade.Client {
	c := upgrade.NewClient(a.Arch)
	if u := fault.TestEnv("MESHLY_TEST_RELEASE_URL"); u != "" {
		c.BaseURL = u
	}
	return c
}

func (a *App) cmdUpgrade(ctx context.Context, args []string) error {
	fs := a.flagSet("upgrade")
	check := fs.Bool("check", false, "")
	want := fs.String("version", "", "")
	force := fs.Bool("force", false, "")
	yes := fs.Bool("yes", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if !*check {
		if err := a.requireRoot(); err != nil {
			return err
		}
	}
	cur := version.Version
	c := a.upgradeClient()
	rel, err := c.Resolve(ctx, *want)
	if err != nil {
		return err
	}
	cmp := upgrade.Compare(rel.Version, cur)
	switch {
	case *check:
		switch {
		case cmp > 0:
			a.printf("Update available: %s → %s (signature verified). Install with: sudo meshly upgrade\n", cur, rel.Version)
		case cmp == 0:
			a.printf("meshly %s is the latest release.\n", cur)
		default:
			a.printf("Running %s, newer than the published release %s.\n", cur, rel.Version)
		}
		return nil
	case cmp == 0 && !*force:
		a.printf("meshly %s is already installed.\n", cur)
		return nil
	case cmp < 0 && !*force:
		return errorf(ExitConflict, "release %s is older than the running %s; downgrade needs --force", rel.Version, cur)
	}
	if !*yes {
		if !a.Interactive {
			return errorf(ExitDeclined, "upgrade needs --yes when not running interactively")
		}
		if !a.confirm(fmt.Sprintf("Upgrade meshly %s → %s and restart the service? Type 'yes':", cur, rel.Version)) {
			return errorf(ExitDeclined, "upgrade cancelled")
		}
	}
	exe, err := systemd.Executable()
	if err != nil {
		return err
	}
	a.printf("Downloading %s ...\n", rel.Asset)
	bin, err := c.Download(ctx, rel)
	if err != nil {
		return err
	}
	a.printf("Verified: SHA256SUMS signed by the meshly release key, SHA-256 %s.\n", rel.SHA256[:16])

	// Replace the binary while holding the lock so that no operation (nor
	// the check timer) runs half on the old and half on the new binary.
	if err := a.Paths.EnsureRuntimeDir(); err != nil {
		return err
	}
	l, err := lock.Acquire(a.Paths.LockFile(), a.LockTimeout)
	if err != nil {
		return err
	}
	// Remember the running intent before either binary can change the unit
	// state. A failed restart must not make rollback look intentionally stopped.
	installed := a.Systemd != nil && a.Systemd.Available && a.Systemd.Installed()
	running := false
	if installed {
		state, serr := a.upgradeServiceState(ctx)
		if serr != nil {
			l.Release()
			return serr
		}
		running = state == "active" || state == "activating" || state == "reloading" || state == "refreshing"
	}
	err = upgrade.Install(ctx, exe, bin, rel.Version)
	l.Release()
	if err != nil {
		return err
	}
	a.audit("upgrade", cur+" -> "+rel.Version, "binary replaced, previous kept at "+exe+".prev")
	a.printf("Installed %s (previous binary kept as %s.prev).\n", exe, exe)

	if !installed {
		a.printf("meshly.service is not installed; nothing to restart.\n")
		return nil
	}
	return a.restartUpgrade(ctx, exe, cur, rel.Version, running)
}

// restartUpgrade restores both the binary and the prior running intent when
// installing units or restarting the newly installed version fails.
func (a *App) restartUpgrade(ctx context.Context, exe, cur, next string, running bool) error {
	if err := a.restartWith(ctx, exe, running); err != nil {
		fmt.Fprintf(a.Stderr, "meshly: the new version failed to start (%v); rolling back to %s\n", err, cur)
		if rerr := upgrade.Rollback(exe); rerr != nil {
			return fmt.Errorf("upgrade failed (%w) and binary rollback failed: %w; previous binary is at %s.prev", err, rerr, exe)
		}
		a.audit("upgrade-rollback", next+" -> "+cur, err.Error())
		if rerr := a.restartWith(ctx, exe, running); rerr != nil {
			return fmt.Errorf("upgrade failed (%w), restored %s but the service still fails: %w (see: journalctl -u meshly)", err, cur, rerr)
		}
		if !running {
			return withCode(ExitRolledBack, fmt.Errorf("upgrade to %s failed and was rolled back to %s; meshly.service remains stopped", next, cur))
		}
		return withCode(ExitRolledBack, fmt.Errorf("upgrade to %s failed and was rolled back; %s is running", next, cur))
	}
	if !running {
		a.printf("meshly.service was stopped; leaving it stopped.\n")
		return nil
	}
	a.printf("meshly.service restarted on %s.\n", next)
	return nil
}

// restartWith lets exe rewrite the unit files (they may change between
// versions), then restores the pre-upgrade running intent. A requested restart
// is verified even when a failed new version has left the service inactive.
func (a *App) restartWith(ctx context.Context, exe string, running bool) error {
	cmd := exec.CommandContext(ctx, exe, "service", "install")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("service install: %w: %s", err, out)
	}
	if !running {
		return nil
	}
	if err := a.Systemd.Restart(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		active, err := a.upgradeServiceState(ctx)
		if err != nil {
			return err
		}
		switch active {
		case "active":
			return nil
		case "failed", "inactive":
			return fmt.Errorf("meshly.service is %s", active)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("meshly.service did not become active")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Upgrade must distinguish a stopped service from a failed state read before
// replacing the executable, and must not claim recovery without verification.
func (a *App) upgradeServiceState(ctx context.Context) (string, error) {
	out, err := a.Systemd.Run(ctx, "show", "--property=ActiveState,UnitFileState,Result", systemd.Unit)
	if err != nil {
		return "", fmt.Errorf("read meshly.service state: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		if key == "ActiveState" {
			switch value {
			case "active", "activating", "reloading", "refreshing", "inactive", "deactivating", "failed", "maintenance":
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("read meshly.service state: missing or unknown ActiveState")
}
