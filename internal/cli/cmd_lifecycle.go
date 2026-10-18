package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/lock"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/systemd"
)

func (a *App) cmdStart(ctx context.Context, args []string) error {
	fs := a.flagSet("start")
	dry := fs.Bool("dry-run", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	target := cfg.Clone()
	target.AdminState = model.AdminUp
	if err := a.preflight(ctx, target, pfOpts{conflicts: true, strict: true}); err != nil {
		return err
	}
	if _, err := a.apply(ctx, opFor("start", "", journal.Backward, cfg, target), *dry); err != nil || *dry {
		return err
	}
	s.end()
	a.ensureService(ctx, cfg.Interface.Name)
	a.printf("Link %s is up (protected by table inet meshly). Autostart is enabled.\n", cfg.Interface.Name)
	return nil
}

func (a *App) cmdStop(ctx context.Context, args []string) error {
	fs := a.flagSet("stop")
	dry := fs.Bool("dry-run", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	target := cfg.Clone()
	target.AdminState = model.AdminDown
	if _, err := a.apply(ctx, opFor("stop", "", journal.Forward, cfg, target), *dry); err != nil || *dry {
		return err
	}
	s.end()
	if a.Systemd != nil && a.Systemd.Available && a.Systemd.Installed() {
		if err := a.Systemd.Stop(ctx); err != nil {
			fmt.Fprintf(a.Stderr, "meshly: warning: %v\n", err)
		}
	}
	a.printf("Link %s stopped: traffic path removed first, then the firewall table. It stays stopped after reboot; run `meshly start` to bring it back.\n", cfg.Interface.Name)
	return nil
}

func (a *App) cmdRestart(ctx context.Context, args []string) error {
	fs := a.flagSet("restart")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := a.requireRoot(); err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if cfg.AdminState != model.AdminUp {
		return errorf(ExitConflict, "the link is stopped (meshly stop); use `meshly start`")
	}
	if a.Systemd != nil && a.Systemd.Available && a.Systemd.Installed() {
		a.printf("Restarting %s ...\n", systemd.Unit)
		if err := a.Systemd.Restart(ctx); err != nil {
			return fmt.Errorf("%w (see: journalctl -u meshly)", err)
		}
		a.printf("Restarted.\n")
		return nil
	}
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	if err := a.preflight(ctx, cfg, pfOpts{conflicts: true, strict: true}); err != nil {
		return err
	}
	down := cfg.Clone()
	down.AdminState = model.AdminDown
	a.printf("Stopping:\n")
	if _, err := a.Engine.Reconcile(ctx, down, cfg.Interface.Name, nil); err != nil {
		return err
	}
	a.audit("restart", "", "link torn down")
	_, err = a.apply(ctx, opFor("restart", "", journal.Backward, cfg, cfg.Clone()), false)
	return err
}

func (a *App) cmdSet(ctx context.Context, args []string) error {
	fs := a.flagSet("set")
	dry := fs.Bool("dry-run", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return errorf(ExitUsage, "usage: meshly set <mtu|keepalive|endpoint|peer-endpoint|cidr> <value>")
	}
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	t := cfg.Clone()
	conflicts := false
	key := pos[0]
	switch {
	case key == "mtu" && len(pos) == 2:
		n, err := strconv.Atoi(pos[1])
		if err != nil || model.ValidateMTU(n) != nil {
			return errorf(ExitUsage, "mtu must be a number between 1280 and 8920")
		}
		t.Interface.MTU = n
	case key == "keepalive" && len(pos) == 2:
		n, err := strconv.Atoi(pos[1])
		if err != nil || model.ValidateKeepalive(n) != nil {
			return errorf(ExitUsage, "keepalive must be 0-3600 seconds")
		}
		for i := range t.Peers {
			t.Peers[i].Keepalive = n
		}
	case key == "endpoint" && len(pos) == 2:
		ep, auto, err := parseEndpointArg(pos[1], t.Self.ListenPort)
		if err != nil {
			return withCode(ExitUsage, err)
		}
		if auto {
			found := a.detectEndpoint(t.Self.ListenPort)
			if !found.ep.IsValid() {
				return errorf(ExitUsage, "%s; set the address explicitly: meshly set endpoint IP", found.why)
			}
			ep = found.ep
			a.printf("Detected %s on %s.\n", ep, found.link)
		}
		t.Self.Endpoint = ep
	case key == "peer-endpoint" && len(pos) == 3:
		p, ok := t.Peer(pos[1])
		if !ok {
			return a.unknownPeer(cfg, pos[1])
		}
		port := uint16(model.DefaultListenPort)
		if p.Endpoint.IsValid() {
			port = p.Endpoint.Port()
		}
		ep, auto, err := parseEndpointArg(pos[2], port)
		if err != nil {
			return withCode(ExitUsage, err)
		}
		if auto {
			return errorf(ExitUsage, "the peer's endpoint cannot be detected here: use IP, IP:PORT or none")
		}
		p.Endpoint = ep
	case key == "cidr" && len(pos) == 2:
		cidr, err := model.ParseCIDR(pos[1])
		if err != nil {
			return withCode(ExitUsage, err)
		}
		if len(cfg.Peers) > 0 {
			return errorf(ExitConflict, "the network can only be renumbered before a peer joins (revoke the peer first)")
		}
		t.Network.CIDR = cidr
		t.Self.Address, _, _ = model.AllocateAddresses(cidr)
		conflicts = true
	default:
		return errorf(ExitUsage, "unknown setting; see `meshly help set`")
	}
	if err := t.Validate(); err != nil {
		return withCode(ExitUsage, err)
	}
	if err := a.preflight(ctx, t, pfOpts{conflicts: conflicts, strict: true}); err != nil {
		return err
	}
	if _, err := a.apply(ctx, opFor("set", key+" "+fmt.Sprint(pos[1:]), journal.Backward, cfg, t), *dry); err != nil || *dry {
		return err
	}
	a.printf("Setting %s updated.\n", key)
	if key == "mtu" {
		a.printf("Set the same MTU on the peer as well.\n")
	}
	return nil
}

func (a *App) cmdReset(ctx context.Context, args []string) error {
	fs := a.flagSet("reset")
	yes := fs.Bool("yes", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if !*yes {
		if !a.Interactive {
			return errorf(ExitDeclined, "reset needs --yes when not running interactively")
		}
		if !a.confirm("Remove the meshly link, configuration and keys from this node? Type 'yes':") {
			return errorf(ExitDeclined, "reset cancelled")
		}
	}
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.Paths.LoadConfig()
	if err != nil && !errors.Is(err, store.ErrNotInitialized) {
		fmt.Fprintf(a.Stderr, "meshly: warning: config unreadable (%v); removing meshly objects by their ownership markers\n", err)
		cfg = nil
	}
	if cfg != nil {
		if _, err := a.apply(ctx, opFor("reset", "", journal.Forward, cfg, nil), false); err != nil {
			return err
		}
	} else {
		a.printf("Removing leftover meshly objects:\n")
		if _, err := a.Engine.Reconcile(ctx, nil, model.DefaultInterface, nil); err != nil {
			return err
		}
		_ = a.Paths.RemoveConfig()
	}
	var errs []error
	errs = append(errs, a.Paths.RemoveKeys())
	if err := os.Remove(a.Paths.RuntimeFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if entries, err := os.ReadDir(a.Paths.HistoryDir()); err == nil {
		for _, e := range entries {
			_ = os.Remove(a.Paths.HistoryDir() + "/" + e.Name())
		}
	}
	a.audit("reset", "", "configuration and keys removed")
	s.end()
	if a.Systemd != nil && a.Systemd.Installed() {
		if a.Systemd.Available {
			_ = a.Systemd.Stop(ctx)
			_ = a.Systemd.Disable(ctx)
		}
		errs = append(errs, a.Systemd.Uninstall(ctx))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	a.printf("meshly was removed from this node (the binary and the journal %s remain).\n", a.Paths.JournalFile())
	if saved := a.Sys.SavedIptablesRules(); len(saved) > 0 {
		fmt.Fprintf(a.Stderr, "meshly: warning: meshly's iptables rule is still saved in %s (netfilter-persistent) and would come back at the next boot\n", strings.Join(saved, " and "))
		fmt.Fprintf(a.Stderr, "         fix: sudo netfilter-persistent save   (saves the rules without it)\n")
	}
	return nil
}

func (a *App) cmdRecover(ctx context.Context, args []string) error {
	if _, err := parse(a.flagSet("recover"), args); err != nil {
		return err
	}
	inc, _ := a.Journal.Incomplete()
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	s.end()
	if inc == nil {
		a.printf("No interrupted operation.\n")
	}
	return nil
}

// cmdService implements the systemd entry points.
func (a *App) cmdService(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errorf(ExitUsage, "usage: meshly service start|stop|reload|check|install")
	}
	switch args[0] {
	case "start", "reload":
		return a.serviceUp(ctx, args[0])
	case "stop":
		return a.serviceStop(ctx)
	case "check":
		return a.serviceCheck(ctx)
	case "install":
		if err := a.requireRoot(); err != nil {
			return err
		}
		cfg, err := a.Paths.LoadConfig()
		iface := model.DefaultInterface
		if err == nil {
			iface = cfg.Interface.Name
		}
		exe, err := systemd.Executable()
		if err != nil {
			return err
		}
		_, err = a.Systemd.Install(ctx, exe, iface)
		return err
	}
	return errorf(ExitUsage, "unknown service action %q", args[0])
}

func (a *App) serviceUp(ctx context.Context, action string) error {
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.Paths.LoadConfig()
	if errors.Is(err, store.ErrNotInitialized) {
		a.printf("meshly is not initialized; nothing to do\n")
		return nil
	}
	if err != nil {
		return err
	}
	if cfg.AdminState != model.AdminUp {
		a.printf("link is administratively stopped (meshly stop); ensuring it is down\n")
		_, err := a.Engine.Reconcile(ctx, cfg, cfg.Interface.Name, nil)
		return err
	}
	if err := a.preflight(ctx, cfg, pfOpts{conflicts: action == "start", strict: true}); err != nil {
		return err
	}
	_, err = a.apply(ctx, opFor("service-"+action, "", journal.Backward, cfg, cfg.Clone()), false)
	return err
}

func (a *App) serviceStop(ctx context.Context) error {
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.Paths.LoadConfig()
	if err != nil && !errors.Is(err, store.ErrNotInitialized) {
		_, rerr := a.Engine.Reconcile(ctx, nil, model.DefaultInterface, nil)
		return errors.Join(err, rerr)
	}
	ifname := model.DefaultInterface
	var down *model.Config
	if cfg != nil {
		ifname = cfg.Interface.Name
		down = cfg.Clone()
		down.AdminState = model.AdminDown
	}
	a.printf("Stopping meshly link %s:\n", ifname)
	if _, err := a.Engine.Reconcile(ctx, down, ifname, nil); err != nil {
		return err
	}
	a.audit("service-stop", "", "link torn down (configuration unchanged)")
	return nil
}

// serviceCheck is run by meshly-check.timer: it repairs drift (above all a
// removed or modified firewall table). It never waits for a busy lock.
func (a *App) serviceCheck(ctx context.Context) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	if held, _ := lock.Probe(a.Paths.LockFile()); held {
		return nil
	}
	prev := a.LockTimeout
	a.LockTimeout = time.Second
	s, err := a.begin(ctx)
	a.LockTimeout = prev
	if errors.Is(err, lock.ErrBusy) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.Paths.LoadConfig()
	if errors.Is(err, store.ErrNotInitialized) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfg.AdminState == model.AdminUp {
		a.Engine.RememberEndpoints(cfg.Interface.Name)
	}
	drift, err := a.Engine.Drift(ctx, cfg)
	if err != nil {
		return err
	}
	if len(drift) == 0 {
		return nil
	}
	for _, d := range drift {
		fmt.Fprintf(a.Stderr, "meshly: drift detected, repairing: %s\n", d)
	}
	op := opFor("check-repair", fmt.Sprint(drift), journal.Backward, cfg, cfg.Clone())
	_, err = a.apply(ctx, op, false)
	return err
}
