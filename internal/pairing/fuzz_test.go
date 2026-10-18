package pairing

import (
	"errors"
	"net"
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
		// join stops reading at a valid code.
		if Partial(s) {
			t.Fatalf("the valid code %q is partial", s)
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

func FuzzReadRequest(f *testing.F) {
	h, c := testHello(), Confirm{WGPublicKey: testKey}
	for _, m := range []message{
		{Type: "hello", Hello: &h},
		{Type: "confirm", Confirm: &c},
		{Type: "ok"},
	} {
		b, _ := marshalMessage(m)
		f.Add(b)
	}
	f.Add([]byte("{}\n"))
	f.Add([]byte(`{"type":"hello"}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, b := net.Pipe()
		defer a.Close()
		go func() {
			_, _ = b.Write(data)
			b.Close()
		}()
		req, err := ReadRequest(a, time.Now().Add(5*time.Second))
		if err != nil {
			return
		}
		switch {
		case req.Hello != nil && req.Confirm == nil:
			err = req.Hello.Validate()
		case req.Confirm != nil && req.Hello == nil:
			err = req.Confirm.Validate()
		default:
			err = errors.New("request must carry exactly one body")
		}
		if err != nil {
			t.Fatalf("accepted %q but: %v", data, err)
		}
	})
}
