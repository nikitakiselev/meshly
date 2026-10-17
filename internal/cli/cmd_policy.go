package cli

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/nikitakiselev/meshly/internal/diag"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
)

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func (a *App) cmdAllow(ctx context.Context, args []string) error {
	return a.changeRule(ctx, "allow", args, true)
}

func (a *App) cmdDeny(ctx context.Context, args []string) error {
	return a.changeRule(ctx, "deny", args, false)
}

func (a *App) changeRule(ctx context.Context, verb string, args []string, add bool) error {
	fs := a.flagSet(verb)
	dry := fs.Bool("dry-run", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	rule, err := model.ParseRule(pos)
	if err != nil {
		return withCode(ExitUsage, fmt.Errorf("%v\nusage: meshly %s <port>/<tcp|udp> from <peer>", err, verb))
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
	if _, ok := cfg.Peer(rule.Peer); !ok {
		return a.unknownPeer(cfg, rule.Peer)
	}
	target := cfg.Clone()
	has := slices.Contains(target.Rules, rule)
	switch {
	case add && has:
		a.printf("Already allowed: %s.\n", rule)
	case add:
		target.Rules = append(target.Rules, rule)
		model.SortRules(target.Rules)
	case !has:
		a.printf("No such rule: %s (nothing to remove).\n", rule)
	default:
		target.Rules = slices.DeleteFunc(target.Rules, func(r model.Rule) bool { return r == rule })
	}
	recovery := journal.Forward
	if add {
		recovery = journal.Backward
	}
	if err := a.preflight(ctx, target, pfOpts{strict: add}); err != nil {
		return err
	}
	op := opFor(verb, rule.String(), recovery, cfg, target)
	if _, err := a.apply(ctx, op, *dry); err != nil || *dry {
		return err
	}
	if add {
		a.printf("Allowed: %s.\n", diag.RuleMeaning(cfg, rule))
		a.printf("The rule applies only to traffic arriving through %s; public interfaces and the reverse direction are unchanged.\n", cfg.Interface.Name)
	} else if has {
		a.printf("Removed: %s. Packets of existing connections to this service are dropped from now on.\n", rule)
	}
	return nil
}

func (a *App) cmdRules(_ context.Context, args []string) error {
	fs := a.flagSet("rules")
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	type out struct {
		Schema  string          `json:"schema"`
		Default string          `json:"default"`
		Rules   []diag.RuleInfo `json:"rules"`
	}
	o := out{Schema: "meshly.rules/v1", Default: "deny", Rules: []diag.RuleInfo{}}
	for _, r := range cfg.Rules {
		o.Rules = append(o.Rules, diag.RuleInfo{Peer: r.Peer, Proto: string(r.Proto), Port: int(r.Port), Rule: r.String(), Meaning: diag.RuleMeaning(cfg, r)})
	}
	if *asJSON {
		return a.json(o)
	}
	a.printf("Inbound VPN policy of %s (%s on %s): default deny\n", cfg.Self.Name, cfg.Self.Address, cfg.Interface.Name)
	if len(o.Rules) == 0 {
		a.printf("  no allow rules: peers cannot reach any service on this node\n")
	}
	for _, r := range o.Rules {
		a.printf("  allow %-24s  %s\n", r.Rule, r.Meaning)
	}
	return nil
}

func (a *App) cmdRevoke(ctx context.Context, args []string) error {
	fs := a.flagSet("revoke")
	yes := fs.Bool("yes", false, "")
	dry := fs.Bool("dry-run", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errorf(ExitUsage, "usage: meshly revoke <peer> [--yes]")
	}
	name := pos[0]
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if _, ok := cfg.Peer(name); !ok {
		if err := model.ValidateName(name); err == nil {
			a.printf("Peer %q is not configured (nothing to revoke).\n", name)
			return nil
		}
		return a.unknownPeer(cfg, name)
	}
	if !*yes && !*dry {
		if !a.Interactive {
			return errorf(ExitDeclined, "revoke needs --yes when not running interactively")
		}
		if !a.confirm(fmt.Sprintf("Revoke peer %q? All its access is closed and its key removed. Type 'yes':", name)) {
			return errorf(ExitDeclined, "revoke cancelled")
		}
	}
	target := cfg.Clone()
	target.Peers = slices.DeleteFunc(target.Peers, func(p model.Peer) bool { return p.Name == name })
	target.Rules = slices.DeleteFunc(target.Rules, func(r model.Rule) bool { return r.Peer == name })
	if err := a.preflight(ctx, target, pfOpts{strict: false}); err != nil {
		return err
	}
	op := opFor("revoke", "peer="+name, journal.Forward, cfg, target)
	if _, err := a.apply(ctx, op, *dry); err != nil || *dry {
		return err
	}
	a.printf("Peer %q revoked: firewall access closed first, then its WireGuard key and route were removed.\n", name)
	a.printf("Re-adding it requires a new invite.\n")
	return nil
}
