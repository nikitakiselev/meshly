package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/preflight"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/systemd"
)

type pfOpts struct {
	// conflicts checks CIDR, interface name and listen port.
	conflicts bool
	// strict makes firewall incompatibility fatal (operations that open
	// access). Access-reducing operations are never blocked.
	strict bool
}

// preflight runs environment checks for cfg; nothing has been changed when
// it fails.
func (a *App) preflight(ctx context.Context, cfg *model.Config, o pfOpts) error {
	r := &preflight.Report{}
	a.Sys.Base(ctx, r)
	if cfg != nil && cfg.AdminState == model.AdminUp {
		if o.conflicts {
			a.Sys.Conflicts(r, cfg.Network.CIDR, cfg.Interface.Name, cfg.Self.ListenPort)
		}
		if len(r.Failures()) == 0 {
			a.Sys.Firewall(ctx, r, cfg, o.strict)
		}
	}
	for _, c := range r.Checks {
		// The missing-systemd warning is printed once by ensureService.
		if c.Status == preflight.Warn && c.ID != "systemd" {
			fmt.Fprintf(a.Stderr, "meshly: warning: %s: %s\n", c.ID, c.Detail)
			if c.Fix != "" {
				fmt.Fprintf(a.Stderr, "         fix: %s\n", c.Fix)
			}
		}
	}
	return r.Error()
}

// resolveProfile turns "auto" into a concrete profile.
func (a *App) resolveProfile(ctx context.Context, profile string, cfg *model.Config) (string, error) {
	switch profile {
	case model.ProfileNone, model.ProfileNftables:
		return profile, nil
	case "auto", "":
	default:
		return "", errorf(ExitUsage, "--firewall must be auto, none or nftables")
	}
	rs, err := a.Sys.NFT.ListRuleset(ctx)
	if err != nil {
		return "", withCode(ExitPreflight, fmt.Errorf("cannot read nftables ruleset: %w", err))
	}
	return preflight.AutoProfile(nft.Analyze(rs, a.Sys.AnalysisContext(cfg))), nil
}

// apply executes or previews op.
func (a *App) apply(ctx context.Context, op engine.Op, dryRun bool) (*engine.Result, error) {
	if op.Actor == "" {
		op.Actor = actor(a.Euid)
	}
	if dryRun {
		d, steps, err := a.Engine.Preview(ctx, op)
		if err != nil {
			return nil, err
		}
		a.printPlan(d, steps, !engine.SameConfig(op.Base, op.Target))
		return nil, nil
	}
	a.printf("Applying %s:\n", op.Name)
	res, err := a.Engine.Execute(ctx, a.Journal, op)
	if err != nil {
		return nil, err
	}
	if len(res.Steps) == 0 {
		a.printf("  (kernel state already matches; nothing to change)\n")
	}
	return res, nil
}

func (a *App) printPlan(d *engine.Desired, steps []engine.Step, cfgChanged bool) {
	a.printf("Dry run — nothing is changed.\n")
	if cfgChanged {
		a.printf("The saved configuration would be updated.\n")
	}
	if len(steps) == 0 {
		a.printf("Kernel state already matches; no system changes.\n")
		return
	}
	a.printf("Planned system changes, in order:\n")
	fw := false
	for i, s := range steps {
		a.printf("  %d. %s\n", i+1, s.Desc)
		if s.Name == "firewall.apply" {
			fw = true
		}
	}
	if fw && d.Present {
		a.printf("\nFirewall table that would be installed (atomically replaces only table inet meshly):\n\n%s\n", d.Firewall.Definition)
	}
}

// ensureService installs/enables/starts the systemd units after a
// successful change. It must be called without holding the lock.
func (a *App) ensureService(ctx context.Context, iface string) {
	if a.Systemd == nil || !a.Systemd.Available {
		fmt.Fprintln(a.Stderr, "meshly: warning: systemd is not running; the link will not be restored after reboot")
		return
	}
	exe, err := systemd.Executable()
	if err == nil {
		_, err = a.Systemd.Install(ctx, exe, iface)
	}
	if err == nil {
		err = a.Systemd.Enable(ctx)
	}
	if err == nil {
		err = a.Systemd.Start(ctx)
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "meshly: warning: autostart could not be configured: %v\n", err)
	}
}

func (a *App) loadConfig() (*model.Config, error) {
	c, err := a.Paths.LoadConfig()
	if errors.Is(err, store.ErrNotInitialized) {
		return nil, withCode(ExitNotInit, errors.New("meshly is not initialized on this node: run `meshly init` (first node) or `meshly join` (second node)"))
	}
	return c, err
}

func newID() (string, error) { return model.NewRandomID(rand.Read) }

func peerNames(c *model.Config) string {
	var n []string
	for _, p := range c.Peers {
		n = append(n, p.Name)
	}
	if len(n) == 0 {
		return "(none)"
	}
	return strings.Join(n, ", ")
}

func (a *App) unknownPeer(c *model.Config, name string) error {
	return errorf(ExitConflict, "unknown peer %q; peers of this node: %s", name, peerNames(c))
}

type opArgs = engine.Op

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
