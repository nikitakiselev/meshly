//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nikitakiselev/meshly/internal/diag"
	"github.com/nikitakiselev/meshly/internal/ping"
)

func contains(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

func TestNodes(t *testing.T) {
	newTestNode(t, start).expect(ExitNotInit, "nodes")

	vps, home := pair(t)
	homeKey := home.config().Self.WGPublicKey
	contains(t, vps.must("nodes"),
		"Network homelab  10.100.0.0/24",
		"vps (this node)   10.100.0.1    203.0.113.10:51820",
		"never connected",
		"home is not connected. Find out why: sudo meshly doctor",
		"home may use nothing on this node yet. Allow a service: sudo meshly allow <port>/tcp from home")

	vps.k.Handshake("meshly0", homeKey, vps.now.Add(-36*time.Second))
	contains(t, vps.must("nodes"), "online, last seen 36s ago", "Check the link to home: sudo meshly ping home")

	vps.must("allow", "22/tcp", "from", "home")
	vps.must("allow", "ping", "from", "home")
	vps.k.Handshake("meshly0", homeKey, vps.now.Add(-2*time.Hour))
	var ns diag.Nodes
	if err := json.Unmarshal([]byte(vps.must("nodes", "--json")), &ns); err != nil {
		t.Fatal(err)
	}
	if ns.Schema != "meshly.nodes/v1" || len(ns.Nodes) != 2 || !ns.Nodes[0].ThisNode || ns.Nodes[0].Name != "vps" {
		t.Fatalf("nodes: %+v", ns)
	}
	h := ns.Nodes[1]
	if h.Name != "home" || h.VPNAddress != "10.100.0.2" || h.Connection != "offline" || h.LastSeenAgo == nil || *h.LastSeenAgo != 7200 ||
		!slices.Equal(h.MayUseHere, []string{"ping", "22/tcp"}) {
		t.Fatalf("home: %+v", h)
	}
	out := vps.must("nodes")
	contains(t, out, "offline, last seen 2h ago", "ping, 22/tcp")
	if strings.Contains(out, "may use nothing") {
		t.Errorf("hint for a peer with rules:\n%s", out)
	}

	vps.must("set", "keepalive", "0")
	contains(t, vps.must("nodes"), "idle or offline, last seen 2h ago")

	vps.app.Euid = 1000
	contains(t, vps.must("nodes"), "unknown (run with sudo)")
	vps.app.Euid = 0

	vps.must("stop")
	contains(t, vps.must("nodes"), "link stopped", "Start it: sudo meshly start")
}

// echo is a fake meshly ping target: reply says whether, and after how
// long, the peer answers each sequence number.
type echo struct {
	t     *testing.T
	reply func(seq int) (time.Duration, error)
	seqs  []int
}

func (e *echo) Echo(_ context.Context, src, dst netip.Addr, seq int, _ time.Duration) (time.Duration, error) {
	if src != vpsVPN || dst != homeVPN {
		e.t.Errorf("echo from %s to %s, want %s to %s", src, dst, vpsVPN, homeVPN)
	}
	e.seqs = append(e.seqs, seq)
	return e.reply(seq)
}

func pingPair(t *testing.T) (vps, home *testNode, e *echo) {
	vps, home = pair(t)
	e = &echo{t: t, reply: func(int) (time.Duration, error) { return 0, ping.ErrNoReply }}
	vps.app.Echo = e.Echo
	vps.app.After = func(time.Duration) <-chan time.Time {
		c := make(chan time.Time, 1)
		c <- time.Time{}
		return c
	}
	return vps, home, e
}

func TestPing(t *testing.T) {
	vps, home, e := pingPair(t)
	homeKey := home.config().Self.WGPublicKey

	vps.expect(ExitUsage, "ping", "-c", "0")
	vps.expect(ExitUsage, "ping", "home", "vps")
	vps.expect(ExitUsage, "ping", "vps")
	vps.expect(ExitConflict, "ping", "nosuch")
	vps.app.Euid = 1000
	vps.expect(ExitPreflight, "ping")
	vps.app.Euid = 0
	if len(e.seqs) > 0 {
		t.Fatalf("refused pings sent %v", e.seqs)
	}

	// No handshake at all: no connection.
	code, out, errOut := vps.run("ping", "-c", "2")
	if code != ExitUnreachable {
		t.Fatalf("exit %d, want %d\n%s%s", code, ExitUnreachable, out, errOut)
	}
	contains(t, out, "PING home (10.100.0.2) from vps (10.100.0.1) through meshly0", "no reply: seq=1", "no reply: seq=2", "--- home: 2 sent, 0 received, 100% loss\n")
	contains(t, errOut, "no reply from home: the nodes have no connection", "sudo meshly doctor")

	// A recent handshake but no reply: the peer does not allow ping.
	vps.k.Handshake("meshly0", homeKey, vps.now.Add(-36*time.Second))
	code, _, errOut = vps.run("ping", "home", "-c", "1")
	if code != ExitUnreachable {
		t.Fatalf("exit %d, want %d", code, ExitUnreachable)
	}
	contains(t, errOut, "recent handshake (36s ago): most likely home does not allow ping from vps; on home run: sudo meshly allow ping from vps")

	// Replies, by address.
	e.seqs = nil
	e.reply = func(seq int) (time.Duration, error) { return time.Duration(10+seq) * time.Millisecond, nil }
	contains(t, vps.must("ping", "10.100.0.2", "--count", "3"),
		"reply from home: seq=1 time=11.0 ms", "reply from home: seq=3 time=13.0 ms",
		"--- home: 3 sent, 3 received, 0% loss, time min/avg/max 11.0/12.0/13.0 ms")
	if !slices.Equal(e.seqs, []int{1, 2, 3}) {
		t.Fatalf("sequence numbers %v", e.seqs)
	}

	// Some lost: still a success.
	e.reply = func(seq int) (time.Duration, error) {
		if seq%2 == 0 {
			return 0, ping.ErrNoReply
		}
		return 5 * time.Millisecond, nil
	}
	contains(t, vps.must("ping"), "4 sent, 2 received, 50% loss")

	var r pingReport
	if err := json.Unmarshal([]byte(vps.must("ping", "--json", "-c", "2")), &r); err != nil {
		t.Fatal(err)
	}
	if r.Schema != "meshly.ping/v1" || r.Node != "home" || r.Sent != 2 || r.Received != 1 || len(r.Packets) != 2 ||
		!r.Packets[0].Reply || *r.Packets[0].RTTMS != 5 || r.Packets[1].Reply || r.Packets[1].RTTMS != nil || *r.AvgMS != 5 || r.Diagnosis != "" {
		t.Fatalf("report: %+v", r)
	}

	// A local failure stops at once.
	e.seqs = nil
	e.reply = func(int) (time.Duration, error) { return 0, errors.New("bind: cannot assign requested address") }
	code, _, errOut = vps.run("ping")
	if code != ExitError || len(e.seqs) != 1 {
		t.Fatalf("exit %d after %v", code, e.seqs)
	}
	contains(t, errOut, "cannot ping home: bind: cannot assign requested address")

	// Ctrl+C during the second ping: the summary of the first.
	var interrupt context.CancelFunc
	vps.app.WaitContext = func(c context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(c)
		interrupt = cancel
		return ctx, cancel
	}
	e.reply = func(seq int) (time.Duration, error) {
		if seq == 2 {
			interrupt()
			return 0, context.Canceled
		}
		return time.Millisecond, nil
	}
	contains(t, vps.must("ping", "-c", "10"), "--- home: 1 sent, 1 received, 0% loss")
	vps.app.WaitContext = nil

	vps.must("stop")
	vps.expect(ExitError, "ping")
}

func TestPingNoPeer(t *testing.T) {
	n := newTestNode(t, start)
	n.expect(ExitNotInit, "ping")
	n.must("init", "homelab", "--name", "vps")
	_, _, errOut := n.run("ping")
	if !strings.Contains(errOut, "no other node has joined") {
		t.Fatalf("stderr: %s", errOut)
	}
	n.expect(ExitConflict, "ping")
}
