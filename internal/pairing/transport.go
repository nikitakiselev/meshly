package pairing

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Network is the transport the pairing protocol runs over.
type Network interface {
	Listen(addr netip.AddrPort) (net.Listener, error)
	Dial(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}

// Kernel is TCP through the kernel stack.
type Kernel struct{}

// Listen listens on addr; the caller picks the (VPN) address.
func (Kernel) Listen(addr netip.AddrPort) (net.Listener, error) {
	return net.Listen("tcp", addr.String())
}

// Dial connects to addr.
func (Kernel) Dial(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
}

// Memory is an in-process network for tests.
type Memory struct {
	mu        sync.Mutex
	listeners map[netip.AddrPort]*memListener
}

// NewMemory returns an empty in-memory network.
func NewMemory() *Memory {
	return &Memory{listeners: map[netip.AddrPort]*memListener{}}
}

// View returns a Network on m whose Dial first consults gate: a non-nil error
// from gate(to) fails the dial with that error.
func (m *Memory) View(gate func(to netip.AddrPort) error) Network {
	return &memView{m: m, gate: gate}
}

type memView struct {
	m    *Memory
	gate func(netip.AddrPort) error
}

func (v *memView) Listen(addr netip.AddrPort) (net.Listener, error) {
	m := v.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.listeners[addr]; ok {
		return nil, fmt.Errorf("listen %s: address already in use", addr)
	}
	l := &memListener{m: m, addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
	m.listeners[addr] = l
	return l, nil
}

func (v *memView) Dial(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if v.gate != nil {
		if err := v.gate(addr); err != nil {
			return nil, err
		}
	}
	v.m.mu.Lock()
	l := v.m.listeners[addr]
	v.m.mu.Unlock()
	if l == nil {
		return nil, fmt.Errorf("dial %s: connection refused", addr)
	}
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.done:
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	}
	_ = client.Close()
	_ = server.Close()
	return nil, fmt.Errorf("dial %s: connection refused", addr)
}

type memListener struct {
	m     *Memory
	addr  netip.AddrPort
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.m.mu.Lock()
		if l.m.listeners[l.addr] == l {
			delete(l.m.listeners, l.addr)
		}
		l.m.mu.Unlock()
	})
	return nil
}

func (l *memListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }
