package pairing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

var errBlocked = errors.New("blocked")

func TestMemoryNetwork(t *testing.T) {
	addr := netip.MustParseAddrPort("10.100.0.1:51820")
	home := netip.MustParseAddr("10.100.0.2")
	m := NewMemory()
	l, err := m.View(addr.Addr(), nil).Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.View(addr.Addr(), nil).Listen(addr); err == nil {
		t.Fatal("second listen on the same address succeeded")
	}

	accepted := make(chan error, 1)
	remote := make(chan net.Addr, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		if c.LocalAddr().String() != addr.String() {
			accepted <- fmt.Errorf("server end: local address %s, want %s", c.LocalAddr(), addr)
			return
		}
		remote <- c.RemoteAddr()
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err != nil {
			accepted <- err
			return
		}
		_, err = c.Write([]byte("pong"))
		accepted <- err
	}()
	c, err := m.View(home, nil).Dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Like a kernel connection, each end reports the addresses as TCP
	// addresses: the server sees the dialing view's address.
	if ra, ok := c.RemoteAddr().(*net.TCPAddr); !ok || ra.AddrPort() != addr {
		t.Fatalf("client end: remote address %v, want %s", c.RemoteAddr(), addr)
	}
	la, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || la.AddrPort().Addr().Unmap() != home || la.Port == 0 {
		t.Fatalf("client end: local address %v, want %s and a port", c.LocalAddr(), home)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := c.Read(buf); err != nil || string(buf) != "pong" {
		t.Fatalf("read %q, %v", buf, err)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	if ra, ok := (<-remote).(*net.TCPAddr); !ok || ra.String() != la.String() {
		t.Fatalf("server end: remote address %v, want %s", ra, la)
	}
	go func() {
		if s, err := l.Accept(); err == nil {
			s.Close()
		}
	}()
	c2, err := m.View(home, nil).Dial(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	if c2.LocalAddr().String() == la.String() {
		t.Fatalf("two connections from %s share the port", c2.LocalAddr())
	}

	blocked := m.View(home, func(netip.AddrPort) error { return errBlocked })
	if _, err := blocked.Dial(context.Background(), addr); !errors.Is(err, errBlocked) {
		t.Fatalf("got %v, want errBlocked", err)
	}
	other := netip.MustParseAddrPort("10.100.0.9:51820")
	if _, err := m.View(home, nil).Dial(context.Background(), other); err == nil {
		t.Fatal("dial without a listener succeeded")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.View(home, nil).Dial(ctx, addr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial to a listener that never accepts: %v", err)
	}

	l.Close()
	if _, err := m.View(home, nil).Dial(context.Background(), addr); err == nil {
		t.Fatal("dial after Close succeeded")
	}
	if _, err := l.Accept(); err == nil {
		t.Fatal("accept after Close succeeded")
	}
}

func TestKernelLoopback(t *testing.T) {
	var k Kernel
	l, err := k.Listen(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := k.Dial(context.Background(), netip.MustParseAddrPort(l.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
