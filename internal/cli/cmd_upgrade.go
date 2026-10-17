package cli

import (
	"context"
	"fmt"
	"os/exec"
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
	l, err := lock.Acquire(a.Paths.LockFile(), a.LockTimeout)
	if err != nil {
		return err
	}
	err = upgrade.Install(ctx, exe, bin, rel.Version)
	l.Release()
	if err != nil {
		return err
	}
	a.audit("upgrade", cur+" -> "+rel.Version, "binary replaced, previous kept at "+exe+".prev")
	a.printf("Installed %s (previous binary kept as %s.prev).\n", exe, exe)

	if a.Systemd == nil || !a.Systemd.Available || !a.Systemd.Installed() {
		a.printf("meshly.service is not installed; nothing to restart.\n")
		return nil
	}
	if err := a.restartWith(ctx, exe); err != nil {
		fmt.Fprintf(a.Stderr, "meshly: the new version failed to start (%v); rolling back to %s\n", err, cur)
		if rerr := upgrade.Rollback(exe); rerr != nil {
			return fmt.Errorf("upgrade failed and rollback failed: %v; previous binary is at %s.prev", rerr, exe)
		}
		a.audit("upgrade-rollback", rel.Version+" -> "+cur, err.Error())
		if rerr := a.restartWith(ctx, exe); rerr != nil {
			return fmt.Errorf("upgrade rolled back to %s but the service still fails: %v (see: journalctl -u meshly)", cur, rerr)
		}
		return withCode(ExitRolledBack, fmt.Errorf("upgrade to %s failed and was rolled back; %s is running", rel.Version, cur))
	}
	a.printf("meshly.service restarted on %s.\n", rel.Version)
	return nil
}

// restartWith lets exe rewrite the unit files (they may change between
// versions), restarts the service and waits for it to be active.
func (a *App) restartWith(ctx context.Context, exe string) error {
	cmd := exec.CommandContext(ctx, exe, "service", "install")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("service install: %v: %s", err, out)
	}
	active, _ := a.Systemd.State(ctx, systemd.Unit)
	if active != "active" && active != "activating" {
		// Not running (e.g. never started on this node): leave it so.
		return nil
	}
	if err := a.Systemd.Restart(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		active, _ := a.Systemd.State(ctx, systemd.Unit)
		switch active {
		case "active":
			return nil
		case "failed", "inactive":
			return fmt.Errorf("meshly.service is %s", active)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("meshly.service did not become active")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
