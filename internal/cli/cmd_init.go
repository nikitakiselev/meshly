package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"

	"github.com/nikitakiselev/meshly/internal/bootstrap"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/store"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (a *App) cmdInit(ctx context.Context, args []string) error {
	fs := a.flagSet("init")
	name := fs.String("name", "", "")
	endpoint := fs.String("endpoint", "", "")
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
		return errorf(ExitUsage, "usage: meshly init <network> --name <node> [--endpoint IP:PORT]")
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
	var ep netip.AddrPort
	if *endpoint != "" {
		if ep, err = model.ParseEndpoint(*endpoint); err != nil {
			return withCode(ExitUsage, fmt.Errorf("--endpoint: %w", err))
		}
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
	lp := *listenPort
	if lp == 0 {
		lp = model.DefaultListenPort
		if ep.IsValid() {
			lp = int(ep.Port())
		}
	}
	if err := model.ValidatePort(lp); err != nil {
		return withCode(ExitUsage, fmt.Errorf("--listen-port: %w", err))
	}

	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	if cur, err := a.Paths.LoadConfig(); err == nil {
		if cur.Network.Name == netName && cur.Self.Name == *name {
			a.printf("This node is already initialized as %q in network %q (fingerprint %s).\n", cur.Self.Name, cur.Network.Name, bootstrap.Fingerprint(cur.Self.IdentityKey, cur.Self.WGPublicKey))
			a.printf("Use `meshly set` to change settings, or `meshly reset` to start over.\n")
			return nil
		}
		return errorf(ExitConflict, "this node is already initialized as %q in network %q; run `meshly reset` first to create another network", cur.Self.Name, cur.Network.Name)
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return err
	}
	bs, err := a.Paths.LoadBootstrap()
	if err != nil {
		return err
	}
	if bs.Pending != nil {
		return errorf(ExitConflict, "this node has a pending join request; finish it with `meshly activate` or run `meshly reset`")
	}

	wgPub, idPub, err := a.publicKeys(*dry)
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
	cfg := &model.Config{
		SchemaVersion: model.ConfigSchemaVersion,
		AdminState:    model.AdminUp,
		Network:       model.Network{ID: netID, Name: netName, CIDR: cidr},
		Self:          model.Self{Name: *name, Address: selfAddr, ListenPort: uint16(lp), Endpoint: ep, WGPublicKey: wgPub, IdentityKey: idPub},
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
	op := opFor("init", fmt.Sprintf("network=%s name=%s endpoint=%s cidr=%s", netName, *name, *endpoint, cidr), journal.Backward, nil, cfg)
	if _, err := a.apply(ctx, op, *dry); err != nil || *dry {
		return err
	}
	s.end()
	a.ensureService(ctx, cfg.Interface.Name)

	fp := bootstrap.Fingerprint(cfg.Self.IdentityKey, cfg.Self.WGPublicKey)
	a.printf("\nNetwork %q created.\n", netName)
	a.printf("  this node:    %s  %s on %s\n", *name, selfAddr, *ifname)
	if ep.IsValid() {
		a.printf("  endpoint:     %s (UDP %d must be reachable; cloud firewalls are not managed by meshly)\n", ep, lp)
	} else {
		a.printf("  endpoint:     none (the joining node must provide --endpoint)\n")
	}
	a.printf("  firewall:     profile %s; all inbound VPN traffic is denied until `meshly allow`\n", cfg.Firewall.Profile)
	a.printf("  fingerprint:  %s\n", fp)
	a.printf("\nNext: meshly invite --out <peer>.invite\n")
	return nil
}

// publicKeys loads or generates the node keys; in dry-run mode keys are
// generated in memory only and discarded.
func (a *App) publicKeys(dry bool) (wgPub, idPub string, err error) {
	if dry && !a.Paths.KeysExist() {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return "", "", err
		}
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", err
		}
		k2 := (&store.Keys{WG: k}).WGPublic()
		return k2, b64(pub), nil
	}
	keys, created, err := a.Paths.LoadOrCreateKeys()
	if err != nil {
		return "", "", err
	}
	defer keys.Wipe()
	if created {
		a.printf("Generated new WireGuard and identity keys in %s (private keys never leave this node).\n", a.Paths.KeysDir)
	}
	return keys.WGPublic(), keys.IdentityPublic(), nil
}

func opFor(name, args, recovery string, base, target *model.Config) opArgs {
	return opArgs{Name: name, Args: args, Recovery: recovery, Base: base, Target: target}
}
