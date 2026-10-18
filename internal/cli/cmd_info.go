package cli

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/diag"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/version"
)

func (a *App) deps() diag.Deps {
	return diag.Deps{Paths: a.Paths, Engine: a.Engine, Journal: a.Journal, Systemd: a.Systemd, Privileged: a.Euid == 0, Now: a.Now}
}

func (a *App) cmdStatus(ctx context.Context, args []string) error {
	fs := a.flagSet("status")
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	st := diag.Collect(ctx, a.deps())
	if *asJSON {
		return a.json(st)
	}
	a.renderStatus(st)
	return nil
}

func yesno(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func (a *App) renderStatus(st *diag.Status) {
	p := a.printf
	if st.Busy {
		p("! another meshly operation is in progress\n")
	}
	if !st.Initialized {
		p("meshly is not initialized on this node.\n")
		for _, e := range st.Errors {
			p("! %s\n", e)
		}
		return
	}
	c := st.Config
	p("Configuration (saved, revision %d, %s)\n", c.Revision, c.UpdatedAt.Format(time.RFC3339))
	p("  network      %s  %s  (id %s)\n", c.NetworkName, c.CIDR, c.NetworkID[:12])
	p("  this node    %s  %s  udp/%d", c.Name, c.Address, c.ListenPort)
	if c.Endpoint != "" {
		p("  endpoint %s", c.Endpoint)
	}
	p("\n  public key   %s\n", c.WGPublicKey)
	p("  admin state  %s   firewall profile %s   %d allow rule(s)\n", c.AdminState, c.Profile, len(c.Rules))
	if s := st.Service; s != nil {
		p("Service\n  meshly.service %s/%s, check timer %s   (systemd state says nothing about connectivity)\n", s.Active, s.Enabled, s.TimerActive)
	}
	if i := st.Interface; i != nil {
		p("Interface\n  %s  ", i.Name)
		switch {
		case !i.Exists:
			p("absent\n")
		case !i.Owned:
			p("EXISTS BUT NOT OWNED BY MESHLY\n")
		default:
			p("%s, mtu %d, addresses %s, listen udp/%d, key %s\n", yesno(i.Up, "up", "DOWN"), i.MTU, strings.Join(i.Addresses, " "), i.ListenPort, yesno(i.KeyMatchesCfg, "ok", "MISMATCH"))
		}
	}
	if f := st.Firewall; f != nil {
		p("Firewall\n  table inet meshly  ")
		switch {
		case !f.TablePresent:
			p("ABSENT\n")
		case !f.Owned:
			p("NOT OWNED BY MESHLY\n")
		case !f.MatchesConfig && st.Invite != nil:
			// Not an alarm: the invite adds its temporary rules on top of
			// the saved configuration (--json stays literal: matches_config
			// false, explained by the invite object).
			p("present, with the open invite's temporary rules%s\n", yesno(f.ModifiedOutside, ", MODIFIED OUTSIDE MESHLY", ""))
		default:
			p("present, %s%s\n", yesno(f.MatchesConfig, "matches config", "OUTDATED"), yesno(f.ModifiedOutside, ", MODIFIED OUTSIDE MESHLY", ""))
		}
		if len(f.Iptables) > 0 {
			var cs []string
			for _, c := range f.Iptables {
				state := "MISSING"
				switch {
				case c.RuleFirst:
					state = "ok"
				case c.RulePresent:
					state = "NOT FIRST"
				}
				cs = append(cs, c.Chain+" "+state)
			}
			p("  iptables chains   meshly rule first: %s\n", strings.Join(cs, ", "))
		}
	}
	for _, pi := range st.Peers {
		p("Peer %s\n", pi.Name)
		p("  address %s   public key %s\n", pi.Address, pi.WGPublicKey)
		p("  wireguard %s, allowed-ips %s, route %s, keepalive %ds\n", yesno(pi.InWireGuard, "configured", "MISSING"), yesno(pi.AllowedIPsOK, pi.Address+"/32", "WRONG"), yesno(pi.RouteOK, "ok", "MISSING"), pi.Keepalive)
		ep := pi.CurrentEndpoint
		if ep == "" {
			ep = "unknown yet"
		}
		p("  endpoint %s", ep)
		if pi.ConfiguredEndpoint != "" && pi.ConfiguredEndpoint != pi.CurrentEndpoint {
			p(" (configured %s)", pi.ConfiguredEndpoint)
		}
		p("\n")
		switch pi.Connectivity {
		case "handshake-recent":
			p("  connectivity: last handshake %s ago, rx %s, tx %s\n", age(pi.HandshakeAge), bytesH(pi.RxBytes), bytesH(pi.TxBytes))
		case "handshake-stale":
			p("  connectivity: last handshake %s ago (idle or unreachable), rx %s, tx %s\n", age(pi.HandshakeAge), bytesH(pi.RxBytes), bytesH(pi.TxBytes))
		case "no-handshake":
			p("  connectivity: no handshake yet (tx %s, rx %s) — see `meshly doctor`\n", bytesH(pi.TxBytes), bytesH(pi.RxBytes))
		default:
			p("  connectivity: unknown\n")
		}
		if len(pi.AllowedFrom) > 0 {
			p("  may use here: %s\n", strings.Join(pi.AllowedFrom, ", "))
		} else {
			p("  may use here: nothing (default deny)\n")
		}
	}
	t := st.Transaction
	switch {
	case t.Incomplete:
		p("Transaction\n  INTERRUPTED: %q (%s) — it will be recovered by the next meshly command (or `meshly recover`)\n", t.IncompleteOp, t.IncompleteTime.Format(time.RFC3339))
	case t.LastOp != "":
		p("Transaction\n  none pending; last: %s %s at %s\n", t.LastOp, t.LastEvent, t.LastTime.Format(time.RFC3339))
	}
	if st.Invite != nil {
		p("Invite open until %s: waiting for a node to join (run `sudo meshly join` on the other node).\n", st.Invite.ExpiresAt.Local().Format(time.RFC3339))
	} else if st.Privileged {
		if len(st.Drift) == 0 {
			p("Drift\n  none: kernel state matches the configuration\n")
		} else {
			p("Drift\n")
			for _, d := range st.Drift {
				p("  - %s\n", d)
			}
			p("  repair with: meshly start\n")
		}
	}
	for _, e := range st.Errors {
		p("! %s\n", e)
	}
}

func age(s *int64) string {
	if s == nil {
		return "?"
	}
	return (time.Duration(*s) * time.Second).String()
}

func bytesH(n int64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(k*k))
	}
}

func (a *App) cmdDoctor(ctx context.Context, args []string) error {
	fs := a.flagSet("doctor")
	asJSON := fs.Bool("json", false, "")
	probe := fs.String("probe", "", "")
	peer := fs.String("peer", "", "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	var pr *diag.Probe
	if *probe != "" {
		cfg, err := a.loadConfig()
		if err != nil {
			return err
		}
		name := *peer
		if name == "" && len(cfg.Peers) > 0 {
			name = cfg.Peers[0].Name
		}
		r, err := model.ParseRule([]string{*probe, "from", name})
		if err != nil || r.Proto == model.ProtoPing {
			return errorf(ExitUsage, "--probe expects <port>/<tcp|udp>")
		}
		pr = &diag.Probe{Peer: name, Proto: r.Proto, Port: r.Port}
	}
	doc := diag.RunDoctor(ctx, a.deps(), a.Sys, pr)
	if *asJSON {
		if err := a.json(doc); err != nil {
			return err
		}
	} else {
		icon := map[string]string{"ok": "✓", "info": "·", "warn": "!", "fail": "✗"}
		for _, f := range doc.Findings {
			cert := ""
			if f.Certainty != "" && f.Status != "ok" && f.Certainty != diag.Fact {
				cert = " [" + f.Certainty + "]"
			}
			a.printf("%s %-20s %s%s\n", icon[f.Status], f.ID, f.Detail, cert)
			if f.Fix != "" && f.Status != "ok" {
				a.printf("  %-20s → %s\n", "", f.Fix)
			}
		}
		a.printf("\n%s\n", doc.Summary)
	}
	switch doc.Worst() {
	case "fail":
		return withCode(ExitProblems, fmt.Errorf("problems found"))
	case "warn":
		return withCode(ExitWarnings, fmt.Errorf("warnings"))
	}
	return nil
}

func (a *App) cmdLogs(_ context.Context, args []string) error {
	fs := a.flagSet("logs")
	n := fs.Int("n", 30, "")
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *n < 1 {
		return errorf(ExitUsage, "-n must be a positive number of records")
	}
	if err := a.requireRoot(); err != nil {
		return err
	}
	recs, err := a.Journal.Last(*n)
	if err != nil {
		return err
	}
	if *asJSON {
		for i := range recs {
			recs[i].Target = nil // keep output compact; configs are in history/
		}
		return a.json(map[string]any{"schema": "meshly.logs/v1", "records": recs})
	}
	if len(recs) == 0 {
		a.printf("The operation journal is empty.\n")
	}
	for _, r := range recs {
		line := fmt.Sprintf("%s  %-12s %-14s", r.Time.Local().Format("2006-01-02 15:04:05"), r.Event, r.Op)
		if r.Args != "" {
			line += " " + r.Args
		}
		if r.Actor != "" {
			line += "  (" + r.Actor + ")"
		}
		if r.Detail != "" {
			line += "  — " + r.Detail
		}
		a.printf("%s\n", line)
	}
	a.printf("\nService output: journalctl -u meshly -u meshly-check\n")
	return nil
}

func (a *App) cmdVersion(_ context.Context, args []string) error {
	fs := a.flagSet("version")
	short := fs.Bool("short", false, "")
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	switch {
	case *short:
		a.printf("%s\n", version.Version)
	case *asJSON:
		return a.json(map[string]string{"version": version.Version, "commit": version.Commit, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
	default:
		a.printf("meshly %s (commit %s, %s, %s/%s)\n", version.Version, version.Commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	}
	return nil
}
