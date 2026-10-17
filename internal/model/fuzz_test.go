package model

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzParseRule(f *testing.F) {
	for _, s := range [][3]string{
		{"22/tcp", "from", "home"},
		{"53/udp", "from", "node-2"},
		{"ping", "from", "home"},
		{"0/tcp", "from", "home"},
		{"65536/udp", "from", "home"},
		{"022/tcp", "from", "home"},
		{"22/icmp", "from", "home"},
		{"22/tcp", "from", "from"},
		{"22/tcp", "to", "home"},
		{"", "", ""},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, svc, from, peer string) {
		r, err := ParseRule([]string{svc, from, peer})
		if err != nil {
			if r != (Rule{}) {
				t.Fatalf("error %v with non-zero rule %+v", err, r)
			}
			return
		}
		if err := r.Validate(); err != nil {
			t.Fatalf("parsed rule %+v does not validate: %v", r, err)
		}
		// The rendering is canonical: it reproduces the accepted input.
		if r.Service() != svc || r.Peer != peer || from != "from" {
			t.Fatalf("ParseRule(%q %q %q) = %+v renders as %q", svc, from, peer, r, r.String())
		}
		again, err := ParseRule(strings.Fields(r.String()))
		if err != nil || again != r {
			t.Fatalf("round trip of %q: %+v, %v", r.String(), again, err)
		}
	})
}

func FuzzParseEndpoint(f *testing.F) {
	for _, s := range []string{
		"203.0.113.10:51820", "[2001:db8::1]:51820", "[::ffff:203.0.113.10]:1",
		"0.0.0.0:51820", "[fe80::1%eth0]:51820", "example.com:51820", "1.2.3.4:0",
		"1.2.3.4:65536", "255.255.255.255:1", "[::ffff:1.2.3.4%x]:5", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ap, err := ParseEndpoint(s)
		if err != nil {
			return
		}
		if err := ValidateEndpoint(ap); err != nil {
			t.Fatalf("ParseEndpoint(%q) = %s which does not validate: %v", s, ap, err)
		}
		a := ap.Addr()
		if a.Is4In6() || a.Zone() != "" || ap.Port() == 0 {
			t.Fatalf("ParseEndpoint(%q) = %s is not normalised", s, ap)
		}
		again, err := ParseEndpoint(ap.String())
		if err != nil || again != ap {
			t.Fatalf("round trip of %s: %s, %v", ap, again, err)
		}
	})
}

func FuzzParseEndpointOrAddr(f *testing.F) {
	for _, s := range []string{
		"203.0.113.10", "203.0.113.10:4000", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:4000",
		"[203.0.113.10]", "::ffff:1.2.3.4", "fe80::1%eth0", "[fe80::1%eth0]", "example.com", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ap, err := ParseEndpointOrAddr(s, 51820)
		if err != nil {
			return
		}
		if err := ValidateEndpoint(ap); err != nil {
			t.Fatalf("ParseEndpointOrAddr(%q) = %s which does not validate: %v", s, ap, err)
		}
		if a := ap.Addr(); a.Is4In6() || a.Zone() != "" {
			t.Fatalf("ParseEndpointOrAddr(%q) = %s is not normalised", s, ap)
		}
		// Anything ParseEndpoint accepts means the same here.
		if strict, err := ParseEndpoint(s); err == nil && strict != ap {
			t.Fatalf("ParseEndpointOrAddr(%q) = %s, ParseEndpoint = %s", s, ap, strict)
		}
		again, err := ParseEndpoint(ap.String())
		if err != nil || again != ap {
			t.Fatalf("round trip of %s: %s, %v", ap, again, err)
		}
	})
}

func FuzzParseCIDR(f *testing.F) {
	for _, s := range []string{
		"10.100.0.0/24", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/30",
		"10.0.0.0/15", "10.0.0.0/31", "8.8.8.0/24", "fd00::/64", "10.100.0.1/24",
		"::ffff:10.0.0.0/112", "10.100.0.0/024", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseCIDR(s)
		if err != nil {
			return
		}
		if !p.Addr().Is4() || p.Masked() != p || p.Bits() < 16 || p.Bits() > 30 {
			t.Fatalf("ParseCIDR(%q) accepted %s", s, p)
		}
		if p.String() != s {
			t.Fatalf("ParseCIDR(%q) = %s: accepted input is not canonical", s, p)
		}
		again, err := ParseCIDR(p.String())
		if err != nil || again != p {
			t.Fatalf("round trip of %s: %s, %v", p, again, err)
		}
		a, b, err := AllocateAddresses(p)
		if err != nil {
			t.Fatalf("AllocateAddresses(%s): %v", p, err)
		}
		for _, x := range []netip.Addr{a, b} {
			if err := ValidateHostAddress(p, x); err != nil {
				t.Fatalf("AllocateAddresses(%s) gave unusable %s: %v", p, x, err)
			}
		}
		if cs := FindConflicts(p, []UsedPrefix{{Prefix: p, Source: "self"}}); len(cs) != 1 {
			t.Fatalf("FindConflicts(%s, itself) = %v", p, cs)
		}
	})
}
