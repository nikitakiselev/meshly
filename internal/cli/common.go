package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
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

// printIptables names the iptables chains that carry meshly's rule (after
// init or join), on a line that starts with label.
func (a *App) printIptables(ctx context.Context, cfg *model.Config, label string) {
	rs, err := a.Sys.NFT.ListRuleset(ctx)
	if err != nil {
		return
	}
	var first []nft.IptablesChain
	for _, c := range rs.IptablesChains(cfg.Firewall.Mark, false) {
		if c.First {
			first = append(first, c)
		}
	}
	if len(first) == 0 {
		return
	}
	note := ""
	if a.Sys.UFWEnabled() {
		note = "; UFW is enabled and decides all other traffic"
	}
	a.printf("%smeshly rule first in %s%s\n", label, nft.IptablesNames(first), note)
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
	res, err := a.execute(ctx, op)
	if err != nil {
		return nil, err
	}
	if len(res.Steps) == 0 {
		a.printf("  (kernel state already matches; nothing to change)\n")
	}
	return res, nil
}

// execute runs op as a transaction and warns when it was completed only
// without the Docker networks.
func (a *App) execute(ctx context.Context, op engine.Op) (*engine.Result, error) {
	res, err := a.Engine.Execute(ctx, a.Journal, op)
	if err == nil && res.WithoutDocker != nil {
		a.warnWithoutDocker(res.WithoutDocker)
	}
	return res, err
}

// warnWithoutDocker says that the configuration is applied without the
// Docker networks after cause.
func (a *App) warnWithoutDocker(cause error) {
	fmt.Fprintf(a.Stderr, "meshly: warning: applied without the Docker networks, which failed: %v\n", cause)
	fmt.Fprintf(a.Stderr, "         the tunnel between the hosts works; published container ports and container connections do not until a retry succeeds (meshly-check.timer, every minute; see meshly doctor)\n")
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
	fw, ipt := false, false
	for i, s := range steps {
		a.printf("  %d. %s\n", i+1, s.Desc)
		switch s.Name {
		case "firewall.apply":
			fw = true
		case "iptables.integrate":
			ipt = true
		}
	}
	if fw && d.Present {
		a.printf("\nFirewall table that would be installed (atomically replaces only table inet meshly):\n\n%s\n", d.Firewall.Definition)
	}
	if ipt && d.Present {
		a.printf("\nRule that would be put at the top of those iptables chains:\n\n  %s\n", nft.IptablesRule(d.Config.Firewall.Mark))
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
		return nil, withCode(ExitNotInit, errors.New("meshly is not initialized on this node: run `sudo meshly init` (first node) or `sudo meshly join` (second node)"))
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

// parseEndpointArg parses an endpoint argument: IP, IP:PORT, "auto" (look
// for this host's public address) or "none". A bare IP gets defPort.
func parseEndpointArg(s string, defPort uint16) (ep netip.AddrPort, auto bool, err error) {
	switch s {
	case "auto":
		return netip.AddrPort{}, true, nil
	case "none":
		return netip.AddrPort{}, false, nil
	}
	ep, err = model.ParseEndpointOrAddr(s, defPort)
	return ep, false, err
}

// detectedEndpoint is the result of detectEndpoint.
type detectedEndpoint struct {
	ep   netip.AddrPort
	link string
	why  string // why there is no endpoint, when ep is not valid
}

// detectEndpoint looks for the address other nodes reach this host at: the
// only public IPv4 address on the interfaces with the default route. It
// reads local state only and never asks a service on the internet, so a
// cloud server behind 1:1 NAT (AWS, GCP) has no detectable address.
func (a *App) detectEndpoint(port uint16) detectedEndpoint {
	addrs, err := a.Sys.Links.DefaultRouteAddrs()
	if err != nil {
		return detectedEndpoint{why: fmt.Sprintf("the network interfaces could not be read (%v)", err)}
	}
	pub := model.PublicIPv4(addrs)
	switch len(pub) {
	case 0:
		return detectedEndpoint{why: "this server has no public IPv4 address on its network interfaces"}
	case 1:
		return detectedEndpoint{ep: netip.AddrPortFrom(pub[0].Addr, port), link: pub[0].Link}
	}
	list := make([]string, len(pub))
	for i, p := range pub {
		list[i] = p.Addr.String() + " on " + p.Link
	}
	return detectedEndpoint{why: "this server has several public IPv4 addresses (" + strings.Join(list, ", ") + ")"}
}
