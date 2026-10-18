package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nikitakiselev/meshly/internal/diag"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/ping"
)

func (a *App) cmdNodes(ctx context.Context, args []string) error {
	fs := a.flagSet("nodes")
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if _, err := a.loadConfig(); err != nil {
		return err
	}
	st := diag.Collect(ctx, a.deps())
	if !st.Initialized {
		return fmt.Errorf("cannot read the configuration: %s", strings.Join(st.Errors, "; "))
	}
	ns := diag.NodesOf(st)
	if *asJSON {
		return a.json(ns)
	}
	a.renderNodes(ns)
	for _, e := range st.Errors {
		a.printf("! %s\n", e)
	}
	return nil
}

func (a *App) renderNodes(ns *diag.Nodes) {
	a.printf("Network %s  %s\n\n", ns.Network, ns.CIDR)
	tw := tabwriter.NewWriter(a.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "NODE\tVPN ADDRESS\tPUBLIC ADDRESS\tCONNECTION\tMAY USE THIS NODE")
	for _, n := range ns.Nodes {
		name, uses, pub := n.Name, "-", n.PublicAddress
		if n.ThisNode {
			name += " (this node)"
		} else {
			uses = "nothing"
			if len(n.MayUseHere) > 0 {
				uses = strings.Join(n.MayUseHere, ", ")
			}
		}
		if pub == "" {
			pub = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, n.VPNAddress, pub, a.connectionText(n), uses)
	}
	tw.Flush()

	var hints []string
	peers := ns.Nodes[1:]
	if len(peers) == 0 {
		hints = append(hints, "No other node has joined yet. Add one: `sudo meshly invite` here, then `sudo meshly join` on the other node.")
	}
	for _, n := range peers {
		switch n.Connection {
		case "online", "idle":
			hints = append(hints, fmt.Sprintf("Check the link to %s: sudo meshly ping %s", n.Name, n.Name))
		case "offline", "never-connected":
			hints = append(hints, fmt.Sprintf("%s is not connected. Find out why: sudo meshly doctor", n.Name))
		case "link-stopped":
			hints = append(hints, "The link of this node is stopped. Start it: sudo meshly start")
		}
		if len(n.MayUseHere) == 0 {
			hints = append(hints, fmt.Sprintf("%s may use nothing on this node yet. Allow a service: sudo meshly allow <port>/tcp from %s", n.Name, n.Name))
		}
	}
	if len(hints) > 0 {
		a.printf("\n%s\n", strings.Join(hints, "\n"))
	}
}

func (a *App) connectionText(n diag.NodeInfo) string {
	seen := ""
	if n.LastSeenAgo != nil {
		seen = ", last seen " + humanAge(*n.LastSeenAgo) + " ago"
	}
	switch n.Connection {
	case "this-node":
		return "-"
	case "online", "offline":
		return n.Connection + seen
	case "idle":
		return "idle or offline" + seen
	case "never-connected":
		return "never connected"
	case "link-stopped":
		return "link stopped"
	}
	if a.Euid != 0 {
		return "unknown (run with sudo)"
	}
	return "unknown (see meshly status)"
}

// humanAge renders a number of seconds as 36s, 5m, 3h or 2d.
func humanAge(s int64) string {
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm", s/60)
	case s < 86400:
		return fmt.Sprintf("%dh", s/3600)
	}
	return fmt.Sprintf("%dd", s/86400)
}

const (
	pingTimeout  = 2 * time.Second
	pingInterval = time.Second
)

// pingReport is the result of meshly ping --json.
type pingReport struct {
	Schema      string       `json:"schema"`
	Node        string       `json:"node"`
	Address     string       `json:"address"`
	From        string       `json:"from"`
	FromAddress string       `json:"from_address"`
	Sent        int          `json:"sent"`
	Received    int          `json:"received"`
	Packets     []pingPacket `json:"packets"`
	MinMS       *float64     `json:"min_ms,omitempty"`
	AvgMS       *float64     `json:"avg_ms,omitempty"`
	MaxMS       *float64     `json:"max_ms,omitempty"`
	// Diagnosis explains why no reply came.
	Diagnosis string `json:"diagnosis,omitempty"`
}

type pingPacket struct {
	Seq   int      `json:"seq"`
	Reply bool     `json:"reply"`
	RTTMS *float64 `json:"rtt_ms,omitempty"`
}

func (a *App) cmdPing(ctx context.Context, args []string) error {
	fs := a.flagSet("ping")
	count := fs.Int("c", 4, "")
	fs.IntVar(count, "count", 4, "")
	asJSON := fs.Bool("json", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *count < 1 {
		return errorf(ExitUsage, "-c must be a positive number of pings")
	}
	if len(pos) > 1 {
		return errorf(ExitUsage, "meshly ping takes one node: meshly ping [<node>] [-c N] [--json]")
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	peer, err := pingTarget(cfg, pos)
	if err != nil {
		return err
	}
	if a.Euid != 0 {
		return errorf(ExitPreflight, "meshly ping sends ICMP from a raw socket and must run as root (use sudo)")
	}
	if cfg.AdminState != model.AdminUp {
		return errors.New("the link of this node is stopped: start it with `sudo meshly start`")
	}

	src, dst := cfg.Self.Address, peer.Address
	r := &pingReport{Schema: "meshly.ping/v1", Node: peer.Name, Address: dst.String(), From: cfg.Self.Name, FromAddress: src.String(), Packets: []pingPacket{}}
	if !*asJSON {
		a.printf("PING %s (%s) from %s (%s) through %s\n", peer.Name, dst, cfg.Self.Name, src, cfg.Interface.Name)
	}
	// Ctrl+C ends the pings early; the summary still follows.
	wctx, cancel := a.waitContext(ctx)
	defer cancel()
	var rtts []time.Duration
	for seq := 1; seq <= *count && wctx.Err() == nil; seq++ {
		rtt, err := a.Echo(wctx, src, dst, seq, pingTimeout)
		if wctx.Err() != nil {
			break // interrupted: this ping does not count
		}
		wait := pingInterval
		switch {
		case err == nil:
			rtts = append(rtts, rtt)
			r.Packets = append(r.Packets, pingPacket{Seq: seq, Reply: true, RTTMS: msPtr(rtt)})
			wait -= rtt
			if !*asJSON {
				a.printf("reply from %s: seq=%d time=%.1f ms\n", peer.Name, seq, ms(rtt))
			}
		case errors.Is(err, ping.ErrNoReply):
			r.Packets = append(r.Packets, pingPacket{Seq: seq})
			wait = 0 // the timeout was the wait
			if !*asJSON {
				a.printf("no reply: seq=%d (waited %s)\n", seq, pingTimeout)
			}
		default:
			return fmt.Errorf("cannot ping %s: %w; find out why: sudo meshly doctor", peer.Name, err)
		}
		r.Sent++
		if seq < *count && wait > 0 {
			select {
			case <-a.after(wait):
			case <-wctx.Done():
			}
		}
	}

	r.Received = len(rtts)
	if len(rtts) > 0 {
		lo, hi, sum := rtts[0], rtts[0], time.Duration(0)
		for _, d := range rtts {
			lo, hi, sum = min(lo, d), max(hi, d), sum+d
		}
		r.MinMS, r.AvgMS, r.MaxMS = msPtr(lo), msPtr(sum/time.Duration(len(rtts))), msPtr(hi)
	}
	if r.Sent > 0 && r.Received == 0 {
		r.Diagnosis = a.pingDiagnosis(ctx, cfg, peer)
	}
	if *asJSON {
		if err := a.json(r); err != nil {
			return err
		}
	} else {
		loss := 0
		if r.Sent > 0 {
			loss = 100 * (r.Sent - r.Received) / r.Sent
		}
		a.printf("--- %s: %d sent, %d received, %d%% loss", peer.Name, r.Sent, r.Received, loss)
		if r.Received > 0 {
			a.printf(", time min/avg/max %.1f/%.1f/%.1f ms", *r.MinMS, *r.AvgMS, *r.MaxMS)
		}
		a.printf("\n")
	}
	if r.Diagnosis != "" {
		return withCode(ExitUnreachable, errors.New(r.Diagnosis))
	}
	return nil
}

// pingTarget finds the peer named by args, by name or VPN address; without
// one, the only peer.
func pingTarget(c *model.Config, args []string) (model.Peer, error) {
	if len(args) == 0 {
		switch len(c.Peers) {
		case 0:
			return model.Peer{}, errorf(ExitConflict, "no other node has joined this network yet: run `sudo meshly invite` here and `sudo meshly join` on the other node")
		case 1:
			return c.Peers[0], nil
		}
		return model.Peer{}, errorf(ExitUsage, "name the node to ping: %s", peerNames(c))
	}
	name := args[0]
	if name == c.Self.Name || name == c.Self.Address.String() {
		return model.Peer{}, errorf(ExitUsage, "%s is this node; ping another one: %s", name, peerNames(c))
	}
	for _, p := range c.Peers {
		if p.Name == name || p.Address.String() == name {
			return p, nil
		}
	}
	return model.Peer{}, errorf(ExitConflict, "unknown node %q; other nodes of this network: %s", name, peerNames(c))
}

// pingDiagnosis explains why the peer did not answer, from the state of the
// link after the pings (they start a handshake if there was none).
func (a *App) pingDiagnosis(ctx context.Context, cfg *model.Config, peer model.Peer) string {
	st := diag.Collect(ctx, a.deps())
	for _, p := range st.Peers {
		if p.Name != peer.Name {
			continue
		}
		switch {
		case p.Connectivity == "handshake-recent" && p.HandshakeAge != nil:
			return fmt.Sprintf("no reply from %s, although the link has a recent handshake (%s ago): most likely %s does not allow ping from %s; on %s run: sudo meshly allow ping from %s",
				peer.Name, humanAge(*p.HandshakeAge), peer.Name, cfg.Self.Name, peer.Name, cfg.Self.Name)
		case p.Connectivity == "handshake-stale" && p.HandshakeAge != nil:
			return fmt.Sprintf("no reply from %s: the link is down, the last handshake was %s ago; find out why: sudo meshly doctor", peer.Name, humanAge(*p.HandshakeAge))
		}
	}
	return fmt.Sprintf("no reply from %s: the nodes have no connection (no WireGuard handshake); find out why: sudo meshly doctor", peer.Name)
}

// ms is d in milliseconds, rounded to hundredths.
func ms(d time.Duration) float64 { return math.Round(float64(d.Microseconds())/10) / 100 }

func msPtr(d time.Duration) *float64 {
	v := ms(d)
	return &v
}
