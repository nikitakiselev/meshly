//go:build linux

package netstack

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A dump that changes interrupt is run again, up to dumpTries times.
func TestDumpRetriesInterrupted(t *testing.T) {
	calls := 0
	got, err := dump(func() ([]int, error) {
		calls++
		if calls < dumpTries {
			return []int{0}, netlink.ErrDumpInterrupted
		}
		return []int{1, 2}, nil
	})
	if err != nil || !slices.Equal(got, []int{1, 2}) || calls != dumpTries {
		t.Fatalf("got %v, %v after %d calls", got, err, calls)
	}
	calls = 0
	if _, err := dump(func() ([]int, error) { calls++; return nil, netlink.ErrDumpInterrupted }); !errors.Is(err, netlink.ErrDumpInterrupted) || calls != dumpTries {
		t.Fatalf("always interrupted: %v after %d calls", err, calls)
	}
	calls = 0
	if _, err := dump(func() ([]int, error) { calls++; return nil, unix.EPERM }); !errors.Is(err, unix.EPERM) || calls != 1 {
		t.Fatalf("other error: %v after %d calls", err, calls)
	}
}

func ipNet(s string) *net.IPNet {
	p := netip.MustParsePrefix(s)
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32)}
}

// The routes of table 109: meshly's become TableRoutes, also one whose link
// went away during the dump (Dev ""); routes of other programs and routes
// of meshly's protocol that meshly never creates count as foreign.
func TestTableRoutes(t *testing.T) {
	routes := []netlink.Route{
		{Protocol: RouteProtocol, Type: unix.RTN_UNREACHABLE},
		{Protocol: RouteProtocol, Type: unix.RTN_UNICAST, Dst: ipNet("172.17.0.0/16"), LinkIndex: 5},
		{Protocol: RouteProtocol, Type: unix.RTN_UNICAST, Dst: ipNet("172.18.0.0/16"), LinkIndex: 6},
		{Protocol: RouteProtocol, Type: unix.RTN_BLACKHOLE, Dst: ipNet("172.19.0.0/16")},
		{Protocol: unix.RTPROT_BOOT, Type: unix.RTN_UNICAST, Dst: ipNet("192.0.2.0/24"), LinkIndex: 5},
	}
	name := func(i int) (string, error) {
		if i == 5 {
			return "docker0", nil
		}
		return "", netlink.LinkNotFoundError{}
	}
	got, raw, foreign := tableRoutes(routes, name)
	want := []TableRoute{
		{Dst: netip.MustParsePrefix("0.0.0.0/0")},
		{Dst: netip.MustParsePrefix("172.17.0.0/16"), Dev: "docker0"},
		{Dst: netip.MustParsePrefix("172.18.0.0/16")},
	}
	if !slices.Equal(got, want) || foreign != 2 || len(raw) != 3 || raw[2].LinkIndex != 6 {
		t.Fatalf("got %+v, raw %+v, foreign %d", got, raw, foreign)
	}
}
