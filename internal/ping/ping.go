// Package ping sends ICMP echo requests from the local VPN address, so that
// they go through the tunnel and the peer's policy decides whether they are
// answered.
package ping

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ErrNoReply means that no echo reply arrived in time.
var ErrNoReply = errors.New("no reply")

// Kernel sends echo requests through a raw ICMP socket, which needs root.
type Kernel struct{}

// Echo sends one echo request with sequence number seq from src to dst and
// waits up to timeout for the reply. It returns the round-trip time.
func (Kernel) Echo(ctx context.Context, src, dst netip.Addr, seq int, timeout time.Duration) (time.Duration, error) {
	c, err := icmp.ListenPacket("ip4:icmp", src.String())
	if err != nil {
		return 0, err
	}
	defer c.Close()
	// Ctrl+C ends the wait at once.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()

	id := os.Getpid() & 0xffff
	req, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("meshly ping")}}).Marshal(nil)
	if err != nil {
		return 0, err
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := c.WriteTo(req, &net.IPAddr{IP: dst.AsSlice()}); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		switch {
		case ctx.Err() != nil:
			return 0, ctx.Err()
		case errors.Is(err, os.ErrDeadlineExceeded):
			return 0, ErrNoReply
		case err != nil:
			return 0, err
		}
		// The raw socket sees every ICMP packet for src: keep only the
		// reply to this request.
		if a, ok := from.(*net.IPAddr); !ok || !a.IP.Equal(dst.AsSlice()) {
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id && e.Seq == seq {
			return time.Since(start), nil
		}
	}
}
