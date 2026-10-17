package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/store"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (a *App) cmdInit(ctx context.Context, args []string) error {
	fs := a.flagSet("init")
	name := fs.String("name", "", "")
	endpoint := fs.String("endpoint", "auto", "")
	listenPort := fs.Int("listen-port", 0, "")
	cidrFlag := fs.String("cidr", model.DefaultCIDR, "")
	mtu := fs.Int("mtu", model.DefaultMTU, "")
	ifname := fs.String("interface", model.DefaultInterface, "")
	profile := fs.String("firewall", "auto", "")
	dry := fs.Bool("dry-run", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errorf(ExitUsage, "usage: meshly init <network> --name <node> [--endpoint IP[:PORT]|auto|none]")
	}
	netName := pos[0]
	if err := model.ValidateName(netName); err != nil {
		return withCode(ExitUsage, fmt.Errorf("network name: %w", err))
	}
	if *name == "" {
		return errorf(ExitUsage, "--name is required (the name of this node, e.g. --name vps)")
	}
	if err := model.ValidateName(*name); err != nil {
		return withCode(ExitUsage, fmt.Errorf("--name: %w", err))
	}
	lp := uint16(model.DefaultListenPort)
	if *listenPort != 0 {
		if err := model.ValidatePort(*listenPort); err != nil {
			return withCode(ExitUsage, fmt.Errorf("--listen-port: %w", err))
		}
		lp = uint16(*listenPort)
	}
	ep, auto, err := parseEndpointArg(*endpoint, lp)
	if err != nil {
		return withCode(ExitUsage, fmt.Errorf("--endpoint: %w", err))
	}
	if *listenPort == 0 && ep.IsValid() {
		lp = ep.Port()
	}
	cidr, err := model.ParseCIDR(*cidrFlag)
	if err != nil {
		return withCode(ExitUsage, fmt.Errorf("--cidr: %w", err))
	}
	if err := model.ValidateMTU(*mtu); err != nil {
		return withCode(ExitUsage, err)
	}
	if err := model.ValidateInterfaceName(*ifname); err != nil {
		return withCode(ExitUsage, err)
	}

	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	if cur, err := a.Paths.LoadConfig(); err == nil {
		if cur.Network.Name == netName && cur.Self.Name == *name {
			a.printf("This node is already initialized as %q in network %q.\n", cur.Self.Name, cur.Network.Name)
			a.printf("Use `meshly set` to change settings, or `meshly reset` to start over.\n")
			return nil
		}
		return errorf(ExitConflict, "this node is already initialized as %q in network %q; run `meshly reset` first to create another network", cur.Self.Name, cur.Network.Name)
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return err
	}

	wgPub, err := a.publicKey(*dry)
	if err != nil {
		return err
	}
	netID, err := newID()
	if err != nil {
		return err
	}
	selfAddr, _, err := model.AllocateAddresses(cidr)
	if err != nil {
		return withCode(ExitUsage, err)
	}
	var found detectedEndpoint
	if auto {
		found = a.detectEndpoint(lp)
		ep = found.ep
	}
	cfg := &model.Config{
		SchemaVersion: model.ConfigSchemaVersion,
		AdminState:    model.AdminUp,
		Network:       model.Network{ID: netID, Name: netName, CIDR: cidr},
		Self:          model.Self{Name: *name, Address: selfAddr, ListenPort: lp, Endpoint: ep, WGPublicKey: wgPub},
		Interface:     model.Interface{Name: *ifname, MTU: *mtu},
		Firewall:      model.Firewall{Mark: model.DefaultFirewallMark},
		Peers:         []model.Peer{},
		Rules:         []model.Rule{},
	}
	if cfg.Firewall.Profile, err = a.resolveProfile(ctx, *profile, cfg); err != nil {
		return err
	}
	if err := a.preflight(ctx, cfg, pfOpts{conflicts: true, strict: true}); err != nil {
		return err
	}
	op := opFor("init", fmt.Sprintf("network=%s name=%s endpoint=%s cidr=%s", netName, *name, endpointArg(ep), cidr), journal.Backward, nil, cfg)
	if _, err := a.apply(ctx, op, *dry); err != nil || *dry {
		if err == nil {
			a.printEndpoint(ep, lp, auto, found)
		}
		return err
	}
	s.end()
	a.ensureService(ctx, cfg.Interface.Name)

	a.printf("\nNetwork %q created.\n", netName)
	a.printf("  this node:    %s  %s on %s\n", *name, selfAddr, *ifname)
	a.printEndpoint(ep, lp, auto, found)
	a.printf("  firewall:     profile %s; all inbound VPN traffic is denied until `meshly allow`\n", cfg.Firewall.Profile)
	a.printf("  public key:   %s\n", cfg.Self.WGPublicKey)
	return nil
}

// publicKey loads or generates the node's WireGuard key; in dry-run mode the
// key is generated in memory only and discarded.
func (a *App) publicKey(dry bool) (string, error) {
	if dry && !a.Paths.KeysExist() {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return "", err
		}
		return (&store.Keys{WG: k}).WGPublic(), nil
	}
	keys, created, err := a.Paths.LoadOrCreateKeys()
	if err != nil {
		return "", err
	}
	defer keys.Wipe()
	if created {
		a.printf("Generated a new WireGuard key in %s (the private key never leaves this node).\n", a.Paths.KeysDir)
	}
	return keys.WGPublic(), nil
}

func opFor(name, args, recovery string, base, target *model.Config) opArgs {
	return opArgs{Name: name, Args: args, Recovery: recovery, Base: base, Target: target}
}

// printEndpoint shows the endpoint init chose and how to change it.
func (a *App) printEndpoint(ep netip.AddrPort, lp uint16, auto bool, found detectedEndpoint) {
	const pad = "                "
	switch {
	case ep.IsValid() && auto:
		a.printf("  endpoint:     %s, detected on %s (to change: meshly set endpoint IP)\n", ep, found.link)
		a.printf(pad+"UDP %d must be reachable; cloud firewalls are not managed by meshly\n", lp)
	case ep.IsValid():
		a.printf("  endpoint:     %s (UDP %d must be reachable; cloud firewalls are not managed by meshly)\n", ep, lp)
	case auto:
		a.printf("  endpoint:     none: %s\n", found.why)
		a.printf(pad + "if the internet reaches this server at a public IP (e.g. 1:1 NAT in AWS or GCP): meshly set endpoint IP\n")
		a.printf(pad + "otherwise the joining node needs a public address of its own\n")
	default:
		a.printf("  endpoint:     none (the joining node needs a public address of its own)\n")
	}
}

// endpointArg formats ep the way the endpoint arguments accept it.
func endpointArg(ep netip.AddrPort) string {
	if ep.IsValid() {
		return ep.String()
	}
	return "none"
}
