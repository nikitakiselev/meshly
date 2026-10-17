package pairing

import (
	"net/netip"
	"testing"
	"time"
)

func FuzzParseCode(f *testing.F) {
	now := testExp.Add(-time.Minute)
	for _, s := range []string{
		"", "m1", "hello", "m2abc",
		forge([]byte{4, 203, 0, 113, 10, 0xCA, 0x6C}),
	} {
		f.Add(s)
	}
	for _, ep := range []string{"203.0.113.10:51820", "[2001:db8::1]:51820"} {
		c, _ := NewCode(netip.MustParseAddrPort(ep), testKey, netip.MustParsePrefix("10.100.0.0/24"), testExp)
		f.Add(c.String())
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCode(s, now)
		if err != nil {
			if c != nil {
				t.Fatalf("error %v with non-nil code", err)
			}
			return
		}
		c2, err := ParseCode(c.String(), now)
		if err != nil {
			t.Fatalf("re-parse of %q: %v", c.String(), err)
		}
		if *c2 != *c {
			t.Fatalf("round trip mismatch: %+v vs %+v", c, c2)
		}
	})
}
