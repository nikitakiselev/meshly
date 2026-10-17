package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/nikitakiselev/meshly/internal/bootstrap"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/store"
)

func (a *App) cmdInvite(ctx context.Context, args []string) error {
	fs := a.flagSet("invite")
	out := fs.String("out", "", "")
	ttl := fs.Duration("ttl", bootstrap.DefaultInviteTTL, "")
	renew := fs.Bool("new", false, "")
	force := fs.Bool("force", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *ttl < time.Minute || *ttl > bootstrap.MaxInviteTTL {
		return errorf(ExitUsage, "--ttl must be between 1m and %s", bootstrap.MaxInviteTTL)
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
	if len(cfg.Peers) >= model.MaxPeers {
		return errorf(ExitConflict, "this version connects exactly two nodes and network %q already has peer %s; a third node is not supported (run `meshly revoke %s` to replace it)", cfg.Network.Name, peerNames(cfg), cfg.Peers[0].Name)
	}
	bs, err := a.Paths.LoadBootstrap()
	if err != nil {
		return err
	}
	now := a.Now()
	if *out == "" {
		*out = "peer.invite"
	}
	if act := bs.ActiveInvite(now); act != nil && !*renew {
		if err := a.writeOutput(*out, []byte(act.Envelope), 0o600, *force); err != nil {
			return err
		}
		if act.Status == store.InviteReserved {
			a.printf("The current invite (id %s, expires %s) is already bound to a join request waiting for `meshly approve`; wrote it again to %s.\n", act.InviteID, act.ExpiresAt.Format(time.RFC3339), *out)
		} else {
			a.printf("An unused invite already exists (id %s, expires %s); wrote it again to %s.\n", act.InviteID, act.ExpiresAt.Format(time.RFC3339), *out)
		}
		a.printf("Use --new to replace it.\n")
		return nil
	}
	if act := bs.ActiveInvite(now); act != nil {
		act.Status = store.InviteCancelled
		act.DecidedAt = now
	}
	keys, err := a.Paths.LoadKeys()
	if err != nil {
		return err
	}
	defer keys.Wipe()
	id, err := newID()
	if err != nil {
		return err
	}
	_, assigned, _ := model.AllocateAddresses(cfg.Network.CIDR)
	inv := &bootstrap.Invite{
		Network:   bootstrap.NetworkInfo{ID: cfg.Network.ID, Name: cfg.Network.Name, CIDR: cfg.Network.CIDR, MTU: cfg.Interface.MTU},
		InviteID:  id,
		CreatedAt: now,
		ExpiresAt: now.Add(*ttl),
		Issuer: bootstrap.NodeInfo{
			Name: cfg.Self.Name, IdentityKey: cfg.Self.IdentityKey, WGPublicKey: cfg.Self.WGPublicKey,
			Address: cfg.Self.Address, Endpoint: cfg.Self.Endpoint,
		},
		AssignedAddress: assigned,
	}
	signed, err := bootstrap.SealInvite(inv, keys.Identity)
	if err != nil {
		return err
	}
	bs.Invites = append(bs.Invites, store.InviteRecord{
		InviteID: id, Digest: signed.Digest(), CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt,
		AssignedAddress: assigned, Envelope: string(signed.Raw), Status: store.InviteIssued,
	})
	if err := a.Paths.SaveBootstrap(bs); err != nil {
		return err
	}
	if err := a.writeOutput(*out, signed.Raw, 0o600, *force); err != nil {
		return err
	}
	a.audit("invite", "id="+id, "expires "+inv.ExpiresAt.Format(time.RFC3339))
	a.printf("Invite written to %s (one-time, expires %s).\n", *out, inv.ExpiresAt.Format(time.RFC3339))
	a.printf("  network:      %s (%s)\n", cfg.Network.Name, cfg.Network.CIDR)
	a.printf("  assigned:     %s for the joining node\n", assigned)
	a.printf("  fingerprint:  %s   <- the joining admin must see exactly this\n", bootstrap.Fingerprint(cfg.Self.IdentityKey, cfg.Self.WGPublicKey))
	if !cfg.Self.Endpoint.IsValid() {
		a.printf("  note: this node has no endpoint, so the joining node needs a public address of its own\n")
	}
	a.printf("\nThe file is sensitive until it expires: anyone holding it can submit a join request.\n")
	a.printf("Copy it over a trusted channel, e.g.:  scp %s admin@home:\n", *out)
	a.printf("Then on the other node:  meshly join %s --name <node> --out <node>.request\n", *out)
	return nil
}

func (a *App) cmdJoin(ctx context.Context, args []string) error {
	fs := a.flagSet("join")
	name := fs.String("name", "", "")
	out := fs.String("out", "", "")
	expect := fs.String("expect-fingerprint", "", "")
	endpoint := fs.String("endpoint", "", "")
	listenPort := fs.Int("listen-port", 0, "")
	keepalive := fs.Int("keepalive", model.DefaultKeepalive, "")
	ifname := fs.String("interface", model.DefaultInterface, "")
	profile := fs.String("firewall", "auto", "")
	force := fs.Bool("force", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errorf(ExitUsage, "usage: meshly join <invite-file> --name <node> [--out FILE] [--endpoint IP[:PORT]|auto]")
	}
	if err := model.ValidateName(*name); err != nil {
		return withCode(ExitUsage, fmt.Errorf("--name: %w", err))
	}
	if err := model.ValidateKeepalive(*keepalive); err != nil {
		return withCode(ExitUsage, err)
	}
	if err := model.ValidateInterfaceName(*ifname); err != nil {
		return withCode(ExitUsage, err)
	}
	defPort := uint16(model.DefaultListenPort)
	if *listenPort != 0 {
		if err := model.ValidatePort(*listenPort); err != nil {
			return withCode(ExitUsage, fmt.Errorf("--listen-port: %w", err))
		}
		defPort = uint16(*listenPort)
	}
	var ep netip.AddrPort
	auto := false
	if *endpoint != "" {
		if ep, auto, err = parseEndpointArg(*endpoint, defPort); err != nil {
			return withCode(ExitUsage, fmt.Errorf("--endpoint: %w", err))
		}
	}
	if *out == "" {
		*out = *name + ".request"
	}
	data, err := store.ReadUntrusted(pos[0], bootstrap.MaxFileSize)
	if err != nil {
		return withCode(ExitInvalidFile, err)
	}
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	if cur, err := a.Paths.LoadConfig(); err == nil {
		return errorf(ExitConflict, "this node is already a member of network %q as %q; run `meshly reset` first", cur.Network.Name, cur.Self.Name)
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return err
	}
	now := a.Now()
	inv, signed, err := bootstrap.ParseInvite(data, now)
	if errors.Is(err, bootstrap.ErrExpired) {
		return withCode(ExitInvalidFile, fmt.Errorf("%w; ask the inviting admin for a new invite (meshly invite --new)", err))
	}
	if err != nil {
		return err
	}
	bs, err := a.Paths.LoadBootstrap()
	if err != nil {
		return err
	}
	if p := bs.Pending; p != nil {
		if p.InviteDigest != signed.Digest() {
			return errorf(ExitConflict, "this node already has a pending join request for another invite (network %s); finish it with `meshly activate` or run `meshly reset`", p.NetworkID)
		}
		if err := a.writeOutput(*out, []byte(p.Request), 0o644, *force); err != nil {
			return err
		}
		a.printf("A join request for this invite already exists; wrote it again to %s.\n", *out)
		return nil
	}
	if *name == inv.Issuer.Name {
		return errorf(ExitUsage, "--name %q is already used by the inviting node", *name)
	}
	// Without --endpoint, a public address is looked for only when the
	// inviting node has none: a node behind NAT should not advertise one.
	var found detectedEndpoint
	if auto || (*endpoint == "" && !inv.Issuer.Endpoint.IsValid()) {
		found = a.detectEndpoint(defPort)
		ep = found.ep
	}
	if !inv.Issuer.Endpoint.IsValid() && !ep.IsValid() {
		if found.why == "" {
			return errorf(ExitUsage, "the inviting node has no public endpoint, so this node needs one: --endpoint IP")
		}
		return errorf(ExitUsage, "the inviting node has no public endpoint, so this node needs one, but %s; if the internet reaches it at a public IP, pass --endpoint IP", found.why)
	}
	fp := inv.Issuer.Fingerprint()
	a.printf("Invite from node %q for network %q:\n", inv.Issuer.Name, inv.Network.Name)
	a.printf("  network:          %s, MTU %d\n", inv.Network.CIDR, inv.Network.MTU)
	a.printf("  inviter address:  %s, endpoint %s\n", inv.Issuer.Address, endpointOrNone(inv.Issuer.Endpoint))
	a.printf("  your address:     %s\n", inv.AssignedAddress)
	if ep.IsValid() && found.link != "" {
		a.printf("  your endpoint:    %s, detected on %s\n", ep, found.link)
	}
	a.printf("  expires:          %s\n", inv.ExpiresAt.Format(time.RFC3339))
	a.printf("  inviter fingerprint: %s\n", fp)
	switch {
	case *expect != "":
		if !bootstrap.FingerprintsEqual(*expect, fp) {
			return errorf(ExitDeclined, "inviter fingerprint does not match --expect-fingerprint; do not join (the invite may have been replaced in transit)")
		}
		a.printf("Fingerprint matches --expect-fingerprint.\n")
	case a.Interactive:
		if !a.confirm("Does this fingerprint match the one printed by `meshly invite` on " + inv.Issuer.Name + "? Type 'yes' to continue:") {
			return errorf(ExitDeclined, "join cancelled")
		}
	default:
		return errorf(ExitDeclined, "non-interactive join requires --expect-fingerprint <inviter fingerprint>")
	}
	lp := defPort
	if *listenPort == 0 {
		if ep.IsValid() {
			lp = ep.Port()
		} else {
			lp = a.Sys.PickListenPort(randUint32)
		}
	}
	// Check the environment before generating keys: a conflict must be
	// reported before anything is created.
	probe := &model.Config{
		SchemaVersion: model.ConfigSchemaVersion, AdminState: model.AdminUp,
		Network:   model.Network{ID: inv.Network.ID, Name: inv.Network.Name, CIDR: inv.Network.CIDR},
		Self:      model.Self{Name: *name, Address: inv.AssignedAddress, ListenPort: lp},
		Interface: model.Interface{Name: *ifname, MTU: inv.Network.MTU},
		Firewall:  model.Firewall{Mark: model.DefaultFirewallMark},
		Peers:     []model.Peer{{Name: inv.Issuer.Name, Address: inv.Issuer.Address}},
	}
	if probe.Firewall.Profile, err = a.resolveProfile(ctx, *profile, probe); err != nil {
		return err
	}
	if err := a.preflight(ctx, probe, pfOpts{conflicts: true, strict: true}); err != nil {
		return err
	}
	keys, created, err := a.Paths.LoadOrCreateKeys()
	if err != nil {
		return err
	}
	defer keys.Wipe()
	if keys.WGPublic() == inv.Issuer.WGPublicKey || keys.IdentityPublic() == inv.Issuer.IdentityKey {
		return errorf(ExitInvalidFile, "the invite was created by this node itself")
	}
	if created {
		a.printf("Generated new WireGuard and identity keys in %s.\n", a.Paths.KeysDir)
	}
	reqID, err := newID()
	if err != nil {
		return err
	}
	req := &bootstrap.JoinRequest{
		NetworkID: inv.Network.ID, InviteID: inv.InviteID, InviteDigest: signed.Digest(), RequestID: reqID,
		CreatedAt: now, ExpiresAt: inv.ExpiresAt,
		Candidate: bootstrap.NodeInfo{Name: *name, IdentityKey: keys.IdentityPublic(), WGPublicKey: keys.WGPublic(), Address: inv.AssignedAddress, Endpoint: ep},
	}
	rs, err := bootstrap.SealJoinRequest(req, keys.Identity)
	if err != nil {
		return err
	}
	bs.Pending = &store.PendingJoin{
		NetworkID: inv.Network.ID, InviteID: inv.InviteID, InviteDigest: signed.Digest(), Invite: string(signed.Raw),
		Request: string(rs.Raw), RequestID: reqID, RequestDigest: rs.Digest(), ExpiresAt: req.ExpiresAt, CreatedAt: now,
		Name: *name, ListenPort: lp, Keepalive: *keepalive, Endpoint: ep, Interface: *ifname, Profile: probe.Firewall.Profile,
		IssuerIdentity: inv.Issuer.IdentityKey,
	}
	if err := a.Paths.SaveBootstrap(bs); err != nil {
		return err
	}
	if err := a.writeOutput(*out, rs.Raw, 0o644, *force); err != nil {
		return err
	}
	a.audit("join", "network="+inv.Network.Name+" request="+reqID, "pending approval by "+inv.Issuer.Name)
	myFP := bootstrap.Fingerprint(keys.IdentityPublic(), keys.WGPublic())
	a.printf("\nJoin request written to %s. Nothing is trusted yet.\n", *out)
	a.printf("  your fingerprint: %s   <- the admin of %s must see exactly this at approve\n", myFP, inv.Issuer.Name)
	a.printf("Copy the request back over a trusted channel; on %s run:\n", inv.Issuer.Name)
	a.printf("  meshly approve %s --out %s.accept\n", *out, *name)
	return nil
}

func (a *App) cmdApprove(ctx context.Context, args []string) error {
	fs := a.flagSet("approve")
	out := fs.String("out", "", "")
	expect := fs.String("expect-fingerprint", "", "")
	dry := fs.Bool("dry-run", false, "")
	force := fs.Bool("force", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errorf(ExitUsage, "usage: meshly approve <request-file> [--out FILE]")
	}
	data, err := store.ReadUntrusted(pos[0], bootstrap.MaxFileSize)
	if err != nil {
		return withCode(ExitInvalidFile, err)
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
	now := a.Now()
	req, rsigned, err := bootstrap.ParseJoinRequest(data, now)
	if errors.Is(err, bootstrap.ErrExpired) {
		return withCode(ExitInvalidFile, fmt.Errorf("%w; the invite has expired, create a new one (meshly invite --new)", err))
	}
	if err != nil {
		return err
	}
	bs, err := a.Paths.LoadBootstrap()
	if err != nil {
		return err
	}
	rec, err := checkRequestBinding(cfg, bs, req, rsigned, now)
	if err != nil {
		return err
	}
	if *out == "" {
		*out = req.Candidate.Name + ".accept"
	}
	fp := req.Candidate.Fingerprint()
	already := rec.Status == store.InviteReserved || rec.Status == store.InviteApproved
	a.printf("Join request from node %q:\n", req.Candidate.Name)
	a.printf("  fingerprint:     %s\n", fp)
	a.printf("  identity key:    %s\n", req.Candidate.IdentityKey)
	a.printf("  WireGuard key:   %s\n", req.Candidate.WGPublicKey)
	a.printf("  VPN address:     %s (assigned by this node's invite %s)\n", rec.AssignedAddress, rec.InviteID)
	a.printf("  endpoint:        %s\n", endpointOrNone(req.Candidate.Endpoint))
	a.printf("  request id:      %s\n", req.RequestID)
	if !already {
		switch {
		case *expect != "":
			if !bootstrap.FingerprintsEqual(*expect, fp) {
				return errorf(ExitDeclined, "candidate fingerprint does not match --expect-fingerprint; NOT approved")
			}
			a.printf("Fingerprint matches --expect-fingerprint.\n")
		case *dry:
		case a.Interactive:
			if !a.confirm("Compare the fingerprint with the one printed by `meshly join` on " + req.Candidate.Name + ". Approve this node? Type 'yes' to approve:") {
				return errorf(ExitDeclined, "not approved")
			}
		default:
			return errorf(ExitDeclined, "non-interactive approval requires --expect-fingerprint <candidate fingerprint>")
		}
	} else {
		a.printf("This request was already approved; continuing idempotently.\n")
	}

	// Keepalive on both sides: it keeps the NAT mapping of the peer open
	// from this side too, and after a restart the kernel sends one as soon
	// as the link is up, re-establishing the session via the remembered
	// endpoint without waiting for the peer.
	keepalive := model.DefaultKeepalive
	target := cfg.Clone()
	if _, exists := target.Peer(req.Candidate.Name); !exists {
		target.Peers = append(target.Peers, model.Peer{
			Name: req.Candidate.Name, Address: rec.AssignedAddress, WGPublicKey: req.Candidate.WGPublicKey,
			IdentityKey: req.Candidate.IdentityKey, Endpoint: req.Candidate.Endpoint, Keepalive: keepalive,
			AddedAt: now, TrustedVia: "approve", TrustDigest: rsigned.Digest(),
		})
	}
	if err := a.preflight(ctx, target, pfOpts{strict: true}); err != nil {
		return err
	}
	op := opFor("approve", "peer="+req.Candidate.Name+" request="+req.RequestID+" fingerprint="+fp, journal.Backward, cfg, target)
	if *dry {
		_, err := a.apply(ctx, op, true)
		return err
	}
	if !already {
		keys, err := a.Paths.LoadKeys()
		if err != nil {
			return err
		}
		acc := &bootstrap.JoinAccept{
			Network:  bootstrap.NetworkInfo{ID: cfg.Network.ID, Name: cfg.Network.Name, CIDR: cfg.Network.CIDR, MTU: cfg.Interface.MTU},
			InviteID: rec.InviteID, InviteDigest: rec.Digest, RequestID: req.RequestID, RequestDigest: rsigned.Digest(),
			CreatedAt: now, ExpiresAt: now.Add(bootstrap.AcceptTTL),
			Issuer: bootstrap.NodeInfo{Name: cfg.Self.Name, IdentityKey: cfg.Self.IdentityKey, WGPublicKey: cfg.Self.WGPublicKey, Address: cfg.Self.Address, Endpoint: cfg.Self.Endpoint},
			Member: bootstrap.NodeInfo{Name: req.Candidate.Name, IdentityKey: req.Candidate.IdentityKey, WGPublicKey: req.Candidate.WGPublicKey, Address: rec.AssignedAddress, Endpoint: req.Candidate.Endpoint},
		}
		asigned, err := bootstrap.SealJoinAccept(acc, keys.Identity)
		keys.Wipe()
		if err != nil {
			return err
		}
		// Reserve the invite for this exact request before touching the
		// kernel: from now on no other request can use it.
		rec.Status = store.InviteReserved
		rec.RequestID, rec.RequestDigest = req.RequestID, rsigned.Digest()
		rec.CandidateName, rec.Fingerprint = req.Candidate.Name, fp
		rec.Accept, rec.DecidedAt = string(asigned.Raw), now
		if err := a.Paths.SaveBootstrap(bs); err != nil {
			return err
		}
	}
	if _, err := a.apply(ctx, op, false); err != nil {
		return err
	}
	rec.Status = store.InviteApproved
	if err := a.Paths.SaveBootstrap(bs); err != nil {
		return err
	}
	if err := a.writeOutput(*out, []byte(rec.Accept), 0o644, *force); err != nil {
		return fmt.Errorf("approved, but writing %s failed: %w (run `meshly approve` with the same request again before %s to rewrite it)", *out, err, req.ExpiresAt.Format(time.RFC3339))
	}
	s.end()
	a.ensureService(ctx, cfg.Interface.Name)
	a.printf("\nNode %q approved; its key is on %s with allowed IP %s/32 only.\n", req.Candidate.Name, cfg.Interface.Name, rec.AssignedAddress)
	a.printf("No service is reachable for it yet (default deny).\n")
	a.printf("Accept written to %s. Copy it to %s and run:  meshly activate %s\n", *out, req.Candidate.Name, *out)
	a.printf("Then allow services here, e.g.:  meshly allow 22/tcp from %s\n", req.Candidate.Name)
	return nil
}

// checkRequestBinding verifies that the request answers an invite issued
// by this node and was not used by another request.
func checkRequestBinding(cfg *model.Config, bs *store.BootstrapState, req *bootstrap.JoinRequest, rs *bootstrap.Signed, now time.Time) (*store.InviteRecord, error) {
	if req.NetworkID != cfg.Network.ID {
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: the request is for another network", bootstrap.ErrInvalid))
	}
	rec := bs.Invite(req.InviteID)
	if rec == nil {
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: the request refers to an invite this node never issued", bootstrap.ErrInvalid))
	}
	if req.InviteDigest != rec.Digest {
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: the request was made for a modified copy of the invite", bootstrap.ErrInvalid))
	}
	switch rec.Status {
	case store.InviteCancelled:
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: invite %s was cancelled", bootstrap.ErrInvalid, rec.InviteID))
	case store.InviteReserved, store.InviteApproved:
		if rec.RequestDigest != rs.Digest() {
			return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: invite %s was already used by another join request (%s); invites are one-time", bootstrap.ErrInvalid, rec.InviteID, rec.RequestID))
		}
		if _, ok := cfg.Peer(req.Candidate.Name); !ok && rec.Status == store.InviteApproved {
			return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: this request was approved earlier and the peer has since been revoked; a new invite is required", bootstrap.ErrInvalid))
		}
		return rec, nil
	case store.InviteIssued:
		if !now.Before(rec.ExpiresAt) {
			return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: invite %s expired at %s", bootstrap.ErrExpired, rec.InviteID, rec.ExpiresAt.Format(time.RFC3339)))
		}
	}
	if req.Candidate.Address != rec.AssignedAddress {
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: the request claims address %s but the invite assigned %s", bootstrap.ErrInvalid, req.Candidate.Address, rec.AssignedAddress))
	}
	if req.Candidate.Name == cfg.Self.Name {
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: the candidate uses this node's name %q", bootstrap.ErrInvalid, cfg.Self.Name))
	}
	if req.Candidate.WGPublicKey == cfg.Self.WGPublicKey || req.Candidate.IdentityKey == cfg.Self.IdentityKey {
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: the candidate presents this node's own keys", bootstrap.ErrInvalid))
	}
	if len(cfg.Peers) >= model.MaxPeers {
		return nil, errorf(ExitConflict, "network already has peer %s; this version supports exactly two nodes", peerNames(cfg))
	}
	if !req.Candidate.Endpoint.IsValid() && !cfg.Self.Endpoint.IsValid() {
		return nil, withCode(ExitInvalidFile, fmt.Errorf("%w: neither node has a public endpoint; at least one must be reachable over UDP", bootstrap.ErrInvalid))
	}
	return rec, nil
}

func (a *App) cmdActivate(ctx context.Context, args []string) error {
	fs := a.flagSet("activate")
	dry := fs.Bool("dry-run", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errorf(ExitUsage, "usage: meshly activate <accept-file>")
	}
	data, err := store.ReadUntrusted(pos[0], bootstrap.MaxFileSize)
	if err != nil {
		return withCode(ExitInvalidFile, err)
	}
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	bs, err := a.Paths.LoadBootstrap()
	if err != nil {
		return err
	}
	cur, err := a.Paths.LoadConfig()
	if err != nil && !errors.Is(err, store.ErrNotInitialized) {
		return err
	}
	now := a.Now()
	if cur != nil {
		// Idempotent re-run: the same accept was already activated.
		if b, err := bootstrap.Open(data, bootstrap.TypeJoinAccept); err == nil {
			for _, act := range bs.Activations {
				if act.AcceptDigest == b.Digest() && act.NetworkID == cur.Network.ID && len(cur.Peers) > 0 && cur.Peers[0].TrustDigest == b.Digest() {
					a.printf("This accept was already activated; membership in network %q is active.\n", cur.Network.Name)
					return nil
				}
			}
		}
		return errorf(ExitConflict, "this node is already a member of network %q; the accept does not belong to its current membership", cur.Network.Name)
	}
	p := bs.Pending
	if p == nil {
		return errorf(ExitConflict, "this node has no pending join request; an accept can only activate a request created here by `meshly join`")
	}
	acc, asigned, err := bootstrap.ParseJoinAccept(data, p.IssuerIdentity, now)
	if errors.Is(err, bootstrap.ErrExpired) {
		return withCode(ExitInvalidFile, fmt.Errorf("%w; ask the inviting admin to revoke this node and start over with a new invite", err))
	}
	if err != nil {
		return err
	}
	inv, _, err := bootstrap.ParseInvite([]byte(p.Invite), inv0(p))
	if err != nil {
		return fmt.Errorf("stored invite is unreadable: %w", err)
	}
	keys, err := a.Paths.LoadKeys()
	if err != nil {
		return err
	}
	wgPub, idPub := keys.WGPublic(), keys.IdentityPublic()
	keys.Wipe()
	if err := checkAcceptBinding(acc, p, inv, wgPub, idPub); err != nil {
		return err
	}
	cfg := &model.Config{
		SchemaVersion: model.ConfigSchemaVersion, AdminState: model.AdminUp,
		Network:   model.Network{ID: inv.Network.ID, Name: inv.Network.Name, CIDR: inv.Network.CIDR},
		Self:      model.Self{Name: p.Name, Address: inv.AssignedAddress, ListenPort: p.ListenPort, Endpoint: p.Endpoint, WGPublicKey: wgPub, IdentityKey: idPub},
		Interface: model.Interface{Name: p.Interface, MTU: inv.Network.MTU},
		Firewall:  model.Firewall{Profile: p.Profile, Mark: model.DefaultFirewallMark},
		Peers: []model.Peer{{
			Name: inv.Issuer.Name, Address: inv.Issuer.Address, WGPublicKey: inv.Issuer.WGPublicKey, IdentityKey: inv.Issuer.IdentityKey,
			Endpoint: inv.Issuer.Endpoint, Keepalive: p.Keepalive, AddedAt: now, TrustedVia: "activate", TrustDigest: asigned.Digest(),
		}},
		Rules: []model.Rule{},
	}
	if err := a.preflight(ctx, cfg, pfOpts{conflicts: true, strict: true}); err != nil {
		return err
	}
	op := opFor("activate", "network="+inv.Network.Name+" peer="+inv.Issuer.Name+" request="+p.RequestID, journal.Backward, nil, cfg)
	if _, err := a.apply(ctx, op, *dry); err != nil || *dry {
		return err
	}
	bs.Activations = append(bs.Activations, store.Activation{NetworkID: inv.Network.ID, AcceptDigest: asigned.Digest(), RequestDigest: p.RequestDigest, ActivatedAt: now})
	bs.Pending = nil
	if err := a.Paths.SaveBootstrap(bs); err != nil {
		return err
	}
	s.end()
	a.ensureService(ctx, cfg.Interface.Name)
	a.printf("\nMembership in network %q is active.\n", inv.Network.Name)
	a.printf("  this node:  %s %s\n", cfg.Self.Name, cfg.Self.Address)
	a.printf("  peer:       %s %s via %s\n", inv.Issuer.Name, inv.Issuer.Address, endpointOrNone(inv.Issuer.Endpoint))
	a.printf("Inbound VPN traffic to this node is denied until you run `meshly allow` here.\n")
	a.printf("Check connectivity with: meshly status\n")
	return nil
}

// inv0 returns a time at which the stored invite is still valid, so the
// pinned invite can be re-parsed after its expiry (it was verified at join).
func inv0(p *store.PendingJoin) time.Time { return p.CreatedAt }

func checkAcceptBinding(acc *bootstrap.JoinAccept, p *store.PendingJoin, inv *bootstrap.Invite, wgPub, idPub string) error {
	bad := func(format string, args ...any) error {
		return withCode(ExitInvalidFile, fmt.Errorf("%w: %s", bootstrap.ErrInvalid, fmt.Sprintf(format, args...)))
	}
	switch {
	case acc.RequestDigest != p.RequestDigest || acc.RequestID != p.RequestID:
		return bad("the accept answers another join request (not the one pending on this node)")
	case acc.InviteDigest != p.InviteDigest || acc.InviteID != p.InviteID:
		return bad("the accept refers to another invite")
	case acc.Network != inv.Network:
		return bad("network parameters differ from the invite")
	case acc.Issuer != inv.Issuer:
		return bad("the inviting node's keys, address or endpoint differ from the invite; changing keys requires a new trust procedure")
	case acc.Member.WGPublicKey != wgPub || acc.Member.IdentityKey != idPub:
		return bad("the accept approves different keys than this node's keys")
	case acc.Member.Name != p.Name:
		return bad("the accept approves name %q, this node requested %q", acc.Member.Name, p.Name)
	case acc.Member.Address != inv.AssignedAddress:
		return bad("the accept assigns address %s, the invite assigned %s", acc.Member.Address, inv.AssignedAddress)
	case acc.Member.Endpoint != p.Endpoint:
		return bad("the accept carries a different endpoint for this node")
	}
	return nil
}

func endpointOrNone(ap netip.AddrPort) string {
	if ap.IsValid() {
		return ap.String()
	}
	return "none (learned from authenticated packets)"
}
