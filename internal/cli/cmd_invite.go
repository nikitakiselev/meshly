package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/pairing"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/wg"
)

// The invite code holds key material: it is printed once, to stdout, and
// never formatted into an error, a progress line or the journal.

func (a *App) cmdInvite(ctx context.Context, args []string) error {
	fs := a.flagSet("invite")
	ttl := fs.Duration("ttl", pairing.DefaultTTL, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errorf(ExitUsage, "usage: meshly invite [--ttl DURATION]")
	}
	if *ttl < pairing.MinTTL || *ttl > pairing.MaxTTL {
		return errorf(ExitUsage, "--ttl must be between %s and %s", humanDuration(pairing.MinTTL), humanDuration(pairing.MaxTTL))
	}
	defer a.quiet()()
	// The lock is held until the invite is closed: the check timer must not
	// "repair" the temporary peer away, and no other change may interleave.
	s, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer s.end()
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	switch {
	case len(cfg.Peers) > 0:
		return errorf(ExitConflict, "network %q already has peer %s and this version connects exactly two nodes; run `sudo meshly revoke %s` first to replace it", cfg.Network.Name, peerNames(cfg), cfg.Peers[0].Name)
	case cfg.AdminState != model.AdminUp:
		return errorf(ExitConflict, "the link is stopped (meshly stop); run `sudo meshly start` first")
	case !cfg.Self.Endpoint.IsValid():
		return errorf(ExitUsage, "this node has no public endpoint, so the other node cannot reach it; run the invite on a node the other one reaches over UDP, or set this node's public address: sudo meshly set endpoint IP")
	}
	if err := a.preflight(ctx, cfg, pfOpts{strict: true}); err != nil {
		return err
	}
	code, err := pairing.NewCode(cfg.Self.Endpoint, cfg.Self.WGPublicKey, cfg.Network.CIDR, a.Now().Add(*ttl))
	if err != nil {
		return err
	}
	defer code.Wipe()
	sec, err := code.Secrets()
	if err != nil {
		return err
	}
	defer sec.Wipe()
	peer, err := a.runInvite(ctx, cfg, code, sec, *ttl)
	if err != nil {
		return err
	}
	s.end()
	a.ensureService(ctx, cfg.Interface.Name)
	a.printf("Node %q (%s) joined. The invite is closed.\n", peer.Name, peer.Address)
	return nil
}

// runInvite opens the invite and serves it until a node has joined and
// confirmed, the code expires or Ctrl+C. Every path closes it again.
func (a *App) runInvite(ctx context.Context, cfg *model.Config, code *pairing.Code, sec *pairing.Secrets, ttl time.Duration) (*model.Peer, error) {
	inviter, joiner := code.Addresses()
	st := &inviteSession{a: a, ctx: ctx, code: code, sec: sec, t: a.pairTimeouts(), joiner: joiner, base: cfg}
	wctx, stop := a.waitContext(ctx)
	defer stop()
	if err := st.arm(); err != nil {
		return nil, err
	}
	opened, outcome := false, "failed"
	var srv *pairServer
	defer func() {
		st.stopTimer()
		if srv != nil {
			srv.close()
		}
		a.closeInvite(ctx, cfg.Interface.Name, opened, outcome)
	}()
	if err := a.Paths.SaveInviteMarker(store.InviteMarker{ExpiresAt: code.ExpiresAt}); err != nil {
		return nil, err
	}
	a.audit("invite", "", "opened, expires "+code.ExpiresAt.Format(time.RFC3339))
	opened = true
	// The VPN address only: from outside, the port is behind WireGuard, and
	// the firewall lets in just the joining node's address.
	l, err := a.Pairing.Listen(netip.AddrPortFrom(inviter, pairing.Port))
	if err != nil {
		return nil, fmt.Errorf("cannot listen for the joining node: %w", err)
	}
	srv = servePairing(l, st.t.Exchange)
	expired := a.after(code.ExpiresAt.Sub(a.Now()))

	fmt.Fprintf(a.Stderr, "Waiting for a node to join network %q until %s (%s). Ctrl+C cancels.\n", cfg.Network.Name, clockTime(code.ExpiresAt), humanDuration(ttl))
	fmt.Fprintf(a.Stderr, "On the other node run `sudo meshly join` and paste this code:\n\n")
	fmt.Fprintln(a.Stdout, code.String())
	fmt.Fprintln(a.Stderr)

	for {
		// A node that joined in time may still confirm after the expiry.
		armedExpiry := expired
		if st.member != nil {
			armedExpiry = nil
		}
		select {
		case <-wctx.Done():
			if st.member != nil {
				if err := st.undo(); err != nil {
					return nil, err
				}
			}
			outcome = "cancelled"
			return nil, errorf(ExitDeclined, "invite cancelled")
		case <-armedExpiry:
			outcome = "expired"
			return nil, errorf(ExitUnreachable, "the invite expired and no node joined")
		case <-st.confirmDue():
			if err := st.undo(); err != nil {
				return nil, err
			}
			select {
			case <-expired:
				outcome = "expired"
				return nil, errorf(ExitUnreachable, "the invite expired and no node joined")
			default:
			}
			if err := st.arm(); err != nil {
				return nil, err
			}
			fmt.Fprintf(a.Stderr, "The code stays valid until %s.\n", clockTime(code.ExpiresAt))
		case in := <-srv.requests:
			if in.err != nil {
				srv.drop(in.conn)
				continue
			}
			confirmed, err := st.answer(in.conn, in.req)
			srv.drop(in.conn)
			if err != nil {
				return nil, err
			}
			if confirmed {
				peer := st.member.Peers[len(st.member.Peers)-1]
				outcome = "joined " + peer.Name
				return &peer, nil
			}
		}
	}
}

// inviteSession is the state of a running invite: armed (the temporary peer
// waits for a node) or, while member is set, committed (the node was added
// and has to confirm).
type inviteSession struct {
	a      *App
	ctx    context.Context // for transactions: Ctrl+C never cancels it
	code   *pairing.Code
	sec    *pairing.Secrets
	t      pairing.Timeouts
	joiner netip.Addr
	base   *model.Config // the saved configuration without the new node
	member *model.Config // the saved configuration with it, while committed
	timer  *time.Timer   // confirmation deadline, while committed
}

// arm puts the temporary peer in place on top of the saved configuration.
func (s *inviteSession) arm() error {
	return s.a.applyOverlay(s.ctx, s.base, inviterOverlay(s.code, s.sec, true))
}

// answer replies to one request and reports whether the new node confirmed.
func (s *inviteSession) answer(c net.Conn, req *pairing.Request) (bool, error) {
	deadline := time.Now().Add(s.t.Exchange)
	reject := func(reason, format string, args ...any) {
		_ = pairing.WriteReject(c, deadline, pairing.Reject{Reason: reason, Message: fmt.Sprintf(format, args...)})
	}
	self := s.base.Self
	switch h := req.Hello; {
	case s.member == nil && h == nil:
		reject(pairing.ReasonInvalid, "no join is waiting for a confirmation")
	case s.member == nil && h.Name == self.Name:
		reject(pairing.ReasonNameTaken, "the name %q is already used by the inviting node; choose another one with --name", h.Name)
	case s.member == nil && (h.WGPublicKey == self.WGPublicKey || h.WGPublicKey == s.sec.TempPublicKey()):
		reject(pairing.ReasonInvalid, "the joining node presents a key of the inviting node or of the invite itself")
	case s.member == nil:
		return false, s.admit(c, h)
	case h != nil:
		reject(pairing.ReasonUsed, "this invite was already used by another node")
	case req.Confirm.WGPublicKey != s.member.Peers[len(s.member.Peers)-1].WGPublicKey:
		reject(pairing.ReasonInvalid, "the confirmation carries another key than the node that joined")
	default:
		// The confirmation came through the new tunnel: it works both ways.
		// A lost "ok" leaves the joining node with a handshake, so it keeps
		// its configuration too.
		_ = pairing.WriteOK(c, deadline)
		return true, nil
	}
	return false, nil
}

// admit welcomes the node and adds it in a transaction. If the transaction
// fails, the invite reports it and waits again; the node, never confirmed,
// rolls itself back.
func (s *inviteSession) admit(c net.Conn, h *pairing.Hello) error {
	a, cfg := s.a, s.base
	w := pairing.Welcome{
		NetworkID: cfg.Network.ID, NetworkName: cfg.Network.Name, CIDR: cfg.Network.CIDR, MTU: cfg.Interface.MTU,
		Inviter: pairing.Node{Name: cfg.Self.Name, Address: cfg.Self.Address, WGPublicKey: cfg.Self.WGPublicKey, Endpoint: cfg.Self.Endpoint},
		Address: s.joiner,
	}
	if err := pairing.WriteWelcome(c, time.Now().Add(s.t.Exchange), w); err != nil {
		return nil // the node went away
	}
	_ = c.Close()
	target := cfg.Clone()
	target.Peers = append(target.Peers, model.Peer{
		Name: h.Name, Address: s.joiner, WGPublicKey: h.WGPublicKey, Endpoint: h.Endpoint,
		Keepalive: model.DefaultKeepalive, AddedAt: a.Now(),
	})
	op := engine.Op{
		Name: "invite", Args: "peer=" + h.Name, Actor: actor(a.Euid), Recovery: journal.Backward,
		Base: cfg, Target: target, Overlay: inviterOverlay(s.code, s.sec, false),
	}
	if _, err := a.Engine.Execute(s.ctx, a.Journal, op); err != nil {
		fmt.Fprintf(a.Stderr, "meshly: error: node %q could not be added: %v\n", h.Name, err)
		if err := s.arm(); err != nil {
			return err
		}
		fmt.Fprintf(a.Stderr, "The code stays valid until %s.\n", clockTime(s.code.ExpiresAt))
		return nil
	}
	s.member = target
	s.timer = time.NewTimer(s.t.Confirm)
	return nil
}

// undo removes the node that did not confirm.
func (s *inviteSession) undo() error {
	s.stopTimer()
	a, peer := s.a, s.member.Peers[len(s.member.Peers)-1]
	target := s.base.Clone()
	op := engine.Op{Name: "invite-undo", Args: "peer=" + peer.Name, Actor: actor(a.Euid), Recovery: journal.Forward, Base: s.member, Target: target}
	if _, err := a.Engine.Execute(s.ctx, a.Journal, op); err != nil {
		return err
	}
	s.base, s.member = target, nil
	fmt.Fprintf(a.Stderr, "Node %q did not confirm the connection; its membership was undone.\n", peer.Name)
	return nil
}

func (s *inviteSession) confirmDue() <-chan time.Time {
	if s.timer == nil {
		return nil
	}
	return s.timer.C
}

func (s *inviteSession) stopTimer() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
}

// closeInvite removes what the invite added on top of the saved
// configuration (a reconcile to it drops the overlay) and its marker.
func (a *App) closeInvite(ctx context.Context, ifname string, opened bool, outcome string) {
	cfg, err := a.Paths.LoadConfig()
	if err == nil {
		_, err = a.Engine.Reconcile(ctx, cfg, cfg.Interface.Name, nil)
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "meshly: warning: the temporary state of the invite could not be removed from %s (%v); meshly-check.timer removes it within a minute\n", ifname, err)
	}
	if err := a.Paths.RemoveInviteMarker(); err != nil {
		fmt.Fprintf(a.Stderr, "meshly: warning: %v\n", err)
	}
	if opened {
		a.audit("invite", "", "closed: "+outcome)
	}
}

// inviterOverlay is the invite's temporary state on top of the saved
// configuration: the joining node's address may reach the pairing port and,
// while armed, the temporary peer derived from the code has that address.
func inviterOverlay(code *pairing.Code, sec *pairing.Secrets, armed bool) *engine.Overlay {
	_, joiner := code.Addresses()
	ov := &engine.Overlay{Allow: []nft.AllowEntry{{Peer: joiner, Proto: model.ProtoTCP, Port: pairing.Port}}}
	if armed {
		ov.Peer = &wg.DesiredPeer{PublicKey: sec.TempPublicKey(), PresharedKey: sec.PresharedKey, AllowedIP: netip.PrefixFrom(joiner, 32)}
	}
	return ov
}

// applyOverlay applies cfg with ov on interface cfg.Interface.Name and wipes
// the overlay's copy of the preshared key.
func (a *App) applyOverlay(ctx context.Context, cfg *model.Config, ov *engine.Overlay) error {
	defer func() {
		if ov.Peer != nil {
			clear(ov.Peer.PresharedKey[:])
		}
	}()
	return a.Engine.ApplyOverlay(ctx, cfg, cfg.Interface.Name, ov)
}

// quiet silences the engine's step list for the rest of a command whose
// output is a few fixed lines (invite, join); the journal still has it.
func (a *App) quiet() (restore func()) {
	prev := a.Engine.Progress
	a.Engine.Progress = nil
	return func() { a.Engine.Progress = prev }
}

// inbound is one request read from a pairing connection.
type inbound struct {
	conn net.Conn
	req  *pairing.Request
	err  error
}

// pairServer accepts pairing connections for the whole invite and reads one
// request from each in its own goroutine, so that a silent client never
// holds up the invite.
type pairServer struct {
	l        net.Listener
	exchange time.Duration
	requests chan inbound
	done     chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    map[net.Conn]struct{} // nil once closed
}

func servePairing(l net.Listener, exchange time.Duration) *pairServer {
	s := &pairServer{l: l, exchange: exchange, requests: make(chan inbound), done: make(chan struct{}), conns: map[net.Conn]struct{}{}}
	s.wg.Add(1)
	go s.accept()
	return s
}

func (s *pairServer) accept() {
	defer s.wg.Done()
	for {
		c, err := s.l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil { // transient, e.g. out of file descriptors
			select {
			case <-s.done:
				return
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		s.mu.Lock()
		open := s.conns != nil
		if open {
			s.conns[c] = struct{}{}
			s.wg.Add(1)
		}
		s.mu.Unlock()
		if !open {
			_ = c.Close()
			return
		}
		go s.read(c)
	}
}

func (s *pairServer) read(c net.Conn) {
	defer s.wg.Done()
	req, err := pairing.ReadRequest(c, time.Now().Add(s.exchange))
	select {
	case s.requests <- inbound{conn: c, req: req, err: err}:
	case <-s.done:
		s.drop(c)
	}
}

// drop closes a connection the invite is done with.
func (s *pairServer) drop(c net.Conn) {
	_ = c.Close()
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// close stops accepting, closes every connection and waits until all
// goroutines of the server have returned.
func (s *pairServer) close() {
	close(s.done)
	_ = s.l.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
	s.wg.Wait()
}

// clockTime formats an expiry for people: a code lives an hour at most.
func clockTime(t time.Time) string { return t.Local().Format("15:04 MST") }

func humanDuration(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "1 hour"
	case d == time.Minute:
		return "1 minute"
	case d%time.Minute == 0:
		return fmt.Sprintf("%d minutes", d/time.Minute)
	}
	return d.String()
}
