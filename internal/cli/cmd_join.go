package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/pairing"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/wg"
)

// maxCodeInput bounds the input the invite code is read from.
const maxCodeInput = 1 << 10

func (a *App) cmdJoin(ctx context.Context, args []string) error {
	fs := a.flagSet("join")
	nameFlag := fs.String("name", "", "")
	endpoint := fs.String("endpoint", "none", "")
	listenPort := fs.Int("listen-port", 0, "")
	keepalive := fs.Int("keepalive", model.DefaultKeepalive, "")
	ifname := fs.String("interface", model.DefaultInterface, "")
	profile := fs.String("firewall", "auto", "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errorf(ExitUsage, "the invite code is not accepted as an argument: other users could see it in the process list, and it would stay in the shell history; run `sudo meshly join` and paste the code when asked, or pass it on stdin")
	}
	// The name is settled before the code is asked for: a bad host name must
	// not make the user paste the code for nothing.
	name, err := a.joinName(*nameFlag)
	if err != nil {
		return err
	}
	if err := model.ValidateKeepalive(*keepalive); err != nil {
		return withCode(ExitUsage, fmt.Errorf("--keepalive: %w", err))
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
	ep, auto, err := parseEndpointArg(*endpoint, defPort)
	if err != nil {
		return withCode(ExitUsage, fmt.Errorf("--endpoint: %w", err))
	}
	if err := a.requireRoot(); err != nil {
		return err
	}
	line, err := a.readCode()
	if err != nil {
		return err
	}
	code, err := pairing.ParseCode(line, a.Now())
	if errors.Is(err, pairing.ErrExpired) {
		return fmt.Errorf("%w; run `sudo meshly invite` on the inviting node again, and if the new code is refused as expired too, check the clock of this node", err)
	}
	if err != nil {
		return err
	}
	defer code.Wipe()
	sec, err := code.Secrets()
	if err != nil {
		return err
	}
	defer sec.Wipe()

	defer a.progressToStderr()()
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	if cur, err := a.Paths.LoadConfig(); err == nil {
		return errorf(ExitConflict, "this node is already a member of network %q as %q; run `sudo meshly reset` first to join another network", cur.Network.Name, cur.Self.Name)
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return err
	}
	if err := a.removeLeftovers(ctx, *ifname); err != nil {
		return err
	}
	if auto {
		found := a.detectEndpoint(defPort)
		if ep = found.ep; !ep.IsValid() {
			fmt.Fprintf(a.Stderr, "meshly: note: --endpoint auto: %s; joining without an endpoint\n", found.why)
		}
	}
	lp := defPort
	if *listenPort == 0 {
		if ep.IsValid() {
			lp = ep.Port()
		} else if lp = a.Sys.PickListenPort(randUint32); lp == 0 {
			return errorf(ExitPreflight, "no free UDP port for WireGuard was found; choose one with --listen-port")
		}
	}
	pcfg, err := pairingConfig(code, sec, name, *ifname, lp, ep)
	if err != nil {
		return err
	}
	if pcfg.Firewall.Profile, err = a.resolveProfile(ctx, *profile, pcfg); err != nil {
		return err
	}
	// Nothing has been sent yet, and nothing changed but the leftovers
	// removed above.
	if err := a.preflight(ctx, pcfg, pfOpts{conflicts: true, strict: true}); err != nil {
		return err
	}
	member, err := a.runJoin(ctx, pcfg, code, sec, *keepalive)
	if member == nil {
		return err
	}
	s.end()
	a.ensureService(ctx, *ifname)
	if err != nil {
		return err // joined, but unconfirmed: the configuration stays
	}
	peer := member.Peers[0]
	a.printf("Joined network %q as %q (%s).\n", member.Network.Name, member.Self.Name, member.Self.Address)
	a.printf("  peer:  %s %s via %s\n", peer.Name, peer.Address, peer.Endpoint)
	a.printf("Inbound VPN traffic to this node is denied until you run `meshly allow` here.\n")
	return nil
}

// runJoin pairs through the temporary tunnel, switches to the real
// configuration and confirms it. It returns the saved configuration when
// one stays, with an error when the join could not be confirmed.
func (a *App) runJoin(ctx context.Context, pcfg *model.Config, code *pairing.Code, sec *pairing.Secrets, keepalive int) (*model.Config, error) {
	ifname := pcfg.Interface.Name
	t := a.pairTimeouts()
	inviter, _ := code.Addresses()
	keys, created, err := a.Paths.LoadOrCreateKeys()
	if err != nil {
		return nil, err
	}
	pub := keys.WGPublic()
	keys.Wipe()
	keep := false // a saved configuration uses the keys
	defer func() {
		if created && !keep {
			if err := a.Paths.RemoveKeys(); err != nil {
				fmt.Fprintf(a.Stderr, "meshly: warning: %v\n", err)
			}
		}
	}()
	if pub == code.InviterKey {
		return nil, errorf(ExitInvalidCode, "the invite code was created by this node")
	}
	wctx, stop := a.waitContext(ctx)
	defer stop()

	if err := a.applyOverlay(ctx, pcfg, joinerOverlay(code, sec)); err != nil {
		a.dropPairing(ctx, ifname)
		return nil, err
	}
	fmt.Fprintf(a.Stderr, "Connecting to %s...\n", code.Endpoint)
	dctx, cancel := context.WithTimeout(wctx, t.Connect)
	conn, err := a.Pairing.Dial(dctx, netip.AddrPortFrom(inviter, pairing.Port))
	cancel()
	if err != nil {
		a.dropPairing(ctx, ifname)
		if wctx.Err() != nil {
			return nil, errorf(ExitDeclined, "join cancelled; nothing was changed on this node")
		}
		return nil, errorf(ExitUnreachable, "the inviting node %s did not answer. Either its invite is closed (expired, cancelled or already used): run `sudo meshly invite` there again; or UDP port %d does not get through to it: check the firewall in front of that server, such as its cloud provider's. Nothing was changed on this node.", code.Endpoint, code.Endpoint.Port())
	}
	interrupt := context.AfterFunc(wctx, func() { _ = conn.Close() })
	w, err := pairing.RequestJoin(conn, time.Now().Add(t.Exchange), pairing.Hello{
		Protocol: pairing.Protocol, Name: pcfg.Self.Name, WGPublicKey: pub, Endpoint: pcfg.Self.Endpoint,
	})
	interrupt()
	_ = conn.Close()
	if err == nil {
		err = checkWelcome(w, code, pcfg.Self.Name)
	}
	if err != nil {
		a.dropPairing(ctx, ifname)
		return nil, refusal(wctx, err)
	}

	member := &model.Config{
		SchemaVersion: model.ConfigSchemaVersion,
		AdminState:    model.AdminUp,
		Network:       model.Network{ID: w.NetworkID, Name: w.NetworkName, CIDR: w.CIDR},
		Self:          model.Self{Name: pcfg.Self.Name, Address: w.Address, ListenPort: pcfg.Self.ListenPort, Endpoint: pcfg.Self.Endpoint, WGPublicKey: pub},
		Interface:     model.Interface{Name: ifname, MTU: w.MTU},
		Firewall:      pcfg.Firewall,
		Peers: []model.Peer{{
			Name: w.Inviter.Name, Address: w.Inviter.Address, WGPublicKey: w.Inviter.WGPublicKey,
			Endpoint: w.Inviter.Endpoint, Keepalive: keepalive, AddedAt: a.Now(),
		}},
		Rules: []model.Rule{},
	}
	// The plan moves the kernel from the temporary tunnel to the real one;
	// a rollback goes back to nothing.
	op := engine.Op{
		Name: "join", Args: fmt.Sprintf("network=%s peer=%s", w.NetworkName, w.Inviter.Name), Actor: actor(a.Euid),
		Recovery: journal.Backward, Target: member,
	}
	// The inviter's peer is updated in place, so the kernel keeps the
	// temporary tunnel's handshake; only a later one proves the real tunnel.
	switched := time.Now()
	if _, err := a.Engine.Execute(ctx, a.Journal, op); err != nil {
		var ae *engine.ApplyError
		if errors.As(err, &ae) && ae.SafeMode {
			keep = true // the configuration may be saved
		} else {
			a.dropPairing(ctx, ifname) // rolled back, or refused before any change
		}
		return nil, err
	}
	keep = true
	if a.confirmJoin(wctx, inviter, pub, t) == nil {
		return member, nil
	}
	if a.handshook(ifname, w.Inviter.WGPublicKey, switched) {
		return member, errorf(ExitError, "joined, but the inviting node did not acknowledge the connection; check `meshly status` on both nodes")
	}
	undo := engine.Op{
		Name: "join-undo", Args: fmt.Sprintf("network=%s peer=%s", w.NetworkName, w.Inviter.Name), Actor: actor(a.Euid),
		Recovery: journal.Forward, Base: member,
	}
	if _, err := a.Engine.Execute(ctx, a.Journal, undo); err != nil {
		return nil, err
	}
	keep = false
	if wctx.Err() != nil {
		return nil, errorf(ExitDeclined, "join cancelled; the changes on this node were rolled back")
	}
	return nil, errorf(ExitRolledBack, "no connection to the inviting node through the new tunnel, so this node was rolled back; run `sudo meshly join` again while the invite is open (until %s)", clockTime(code.ExpiresAt))
}

// confirmJoin tells the inviting node the join worked, through the new
// tunnel. It retries every second for 3/4 of the inviter's confirmation
// window, so it gives up before the inviter undoes the join.
func (a *App) confirmJoin(wctx context.Context, inviter netip.Addr, pub string, t pairing.Timeouts) error {
	end := time.Now().Add(t.Confirm * 3 / 4)
	for {
		err := a.sendConfirm(wctx, inviter, pub, t, end)
		var rej *pairing.RejectError
		if err == nil || errors.As(err, &rej) || wctx.Err() != nil {
			return err
		}
		left := time.Until(end)
		if left <= 0 {
			return err
		}
		pause := time.NewTimer(min(time.Second, left))
		select {
		case <-wctx.Done():
			pause.Stop()
			return wctx.Err()
		case <-pause.C:
		}
		if !time.Now().Before(end) {
			return err
		}
	}
}

func (a *App) sendConfirm(wctx context.Context, inviter netip.Addr, pub string, t pairing.Timeouts, end time.Time) error {
	dctx, cancel := context.WithDeadline(wctx, earliest(time.Now().Add(t.Connect), end))
	defer cancel()
	conn, err := a.Pairing.Dial(dctx, netip.AddrPortFrom(inviter, pairing.Port))
	if err != nil {
		return err
	}
	defer conn.Close()
	defer context.AfterFunc(wctx, func() { _ = conn.Close() })()
	return pairing.SendConfirm(conn, earliest(time.Now().Add(t.Exchange), end), pairing.Confirm{WGPublicKey: pub})
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// handshook reports whether the kernel completed a WireGuard handshake with
// the peer after since: then the tunnel works even though no "ok" arrived.
func (a *App) handshook(ifname, peer string, since time.Time) bool {
	d, err := a.Engine.WG.Observe(ifname)
	if err != nil || d == nil {
		return false
	}
	p, ok := d.Peer(peer)
	return ok && p.LastHandshake.After(since)
}

// refusal turns a failed exchange into the command's error.
func refusal(wctx context.Context, err error) error {
	var rej *pairing.RejectError
	if errors.As(err, &rej) {
		code := ExitError
		switch rej.Reject.Reason {
		case pairing.ReasonNameTaken:
			code = ExitConflict
		case pairing.ReasonUsed:
			code = ExitInvalidCode
		}
		return errorf(code, "the inviting node refused: %s", rej.Reject.Message)
	}
	if wctx.Err() != nil {
		return errorf(ExitDeclined, "join cancelled; nothing was changed on this node")
	}
	return fmt.Errorf("the exchange with the inviting node failed, nothing was changed on this node: %w", err)
}

// checkWelcome holds the inviter's answer against the code: the code is
// what the user trusts.
func checkWelcome(w *pairing.Welcome, code *pairing.Code, name string) error {
	inviter, joiner := code.Addresses()
	var what string
	switch {
	case w.CIDR != code.CIDR:
		what = "network"
	case w.Inviter.Address != inviter || w.Address != joiner:
		what = "addresses"
	case w.Inviter.WGPublicKey != code.InviterKey:
		what = "public key"
	case w.Inviter.Endpoint != code.Endpoint:
		what = "endpoint"
	case w.Inviter.Name == name:
		what = "name: it is this node's"
	default:
		return nil
	}
	return fmt.Errorf("%w: the inviting node's answer does not match the invite code (%s)", pairing.ErrProtocol, what)
}

// pairingConfig is what the joining node runs the temporary tunnel on. It
// is never saved; the overlay brings the inviter's peer and the temporary
// key.
func pairingConfig(code *pairing.Code, sec *pairing.Secrets, name, ifname string, lp uint16, ep netip.AddrPort) (*model.Config, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	_, joiner := code.Addresses()
	return &model.Config{
		SchemaVersion: model.ConfigSchemaVersion,
		AdminState:    model.AdminUp, // the engine ignores an overlay on a stopped config
		Network:       model.Network{ID: id, Name: "pairing", CIDR: code.CIDR},
		Self:          model.Self{Name: name, Address: joiner, ListenPort: lp, Endpoint: ep, WGPublicKey: sec.TempPublicKey()},
		Interface:     model.Interface{Name: ifname, MTU: model.DefaultMTU},
		Firewall:      model.Firewall{Mark: model.DefaultFirewallMark},
		Peers:         []model.Peer{},
		Rules:         []model.Rule{},
	}, nil
}

// joinerOverlay is the temporary tunnel: the temporary key, and the inviter
// as a peer with the preshared key.
func joinerOverlay(code *pairing.Code, sec *pairing.Secrets) *engine.Overlay {
	inviter, _ := code.Addresses()
	return &engine.Overlay{
		Peer: &wg.DesiredPeer{
			PublicKey: code.InviterKey, PresharedKey: sec.PresharedKey, Endpoint: code.Endpoint,
			AllowedIP: netip.PrefixFrom(inviter, 32), Keepalive: model.DefaultKeepalive,
		},
		PrivateKey: &sec.PrivateKey,
	}
}

// dropPairing removes the temporary tunnel: nothing of meshly stays.
func (a *App) dropPairing(ctx context.Context, ifname string) {
	if _, err := a.Engine.Reconcile(ctx, nil, ifname, nil); err != nil {
		fmt.Fprintf(a.Stderr, "meshly: warning: the temporary tunnel could not be removed (%v); run `sudo meshly reset`\n", err)
	}
}

// removeLeftovers removes an interface or table of meshly that no saved
// configuration explains: what an interrupted join leaves behind.
func (a *App) removeLeftovers(ctx context.Context, ifname string) error {
	o, err := a.Engine.Observe(ctx, ifname)
	if err != nil || !o.Link.Owned() && !(o.TablePresent && o.TableOwned) {
		return nil // the preflight reports an unreadable kernel state
	}
	if _, err := a.Engine.Reconcile(ctx, nil, ifname, nil); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "meshly: removed the leftovers of an interrupted join (interface %s, table inet meshly)\n", ifname)
	return nil
}

// readCode reads the invite code: after a prompt on a terminal, otherwise
// from stdin, the first line. A code that a console, a terminal or a mail
// client broke across lines is read on while the input is the start of a
// code (pairing.Partial): until it is complete, a blank line, the end of
// the input or maxCodeInput bytes.
func (a *App) readCode() (string, error) {
	if a.Interactive {
		fmt.Fprint(a.Stderr, "Invite code: ")
	}
	r := bufio.NewReader(io.LimitReader(a.Stdin, maxCodeInput+1))
	var in string
	for {
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("cannot read the invite code: %w", err)
		}
		in += line
		if len(in) > maxCodeInput {
			return "", fmt.Errorf("%w (longer than %d bytes)", pairing.ErrMalformed, maxCodeInput)
		}
		if strings.TrimSpace(in) == "" {
			return "", errorf(ExitUsage, "no invite code given: paste the code printed by `sudo meshly invite` when asked, or pass it on stdin")
		}
		if err != nil || strings.TrimSpace(line) == "" || !pairing.Partial(in) {
			return in, nil
		}
		if a.Interactive {
			fmt.Fprint(a.Stderr, "> ")
		}
	}
}

// joinName returns --name, or else a name made from the host name.
func (a *App) joinName(flag string) (string, error) {
	if flag != "" {
		if err := model.ValidateName(flag); err != nil {
			return "", withCode(ExitUsage, fmt.Errorf("--name: %w", err))
		}
		return flag, nil
	}
	h, err := a.hostname()
	if err != nil {
		return "", errorf(ExitUsage, "the host name cannot be read (%v); choose a name for this node with --name", err)
	}
	name, err := nodeNameFromHostname(h)
	if err != nil {
		if len(h) > 64 {
			h = h[:64] + "..."
		}
		return "", errorf(ExitUsage, "no node name can be made from the host name %q; choose one with --name", h)
	}
	return name, nil
}

// nodeNameFromHostname makes a node name from a host name: the first label,
// lowercased, every run of characters other than a-z and 0-9 turned into one
// '-' (none at the ends), at most 32 characters.
func nodeNameFromHostname(h string) (string, error) {
	h, _, _ = strings.Cut(strings.ToLower(h), ".")
	var b strings.Builder
	dash := false
	for _, r := range h {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 32 {
		s = strings.TrimRight(s[:32], "-")
	}
	if err := model.ValidateName(s); err != nil {
		return "", err
	}
	return s, nil
}
