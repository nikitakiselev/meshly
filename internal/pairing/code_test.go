package pairing

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

// testKey is a valid base64 WireGuard public key (bytes 1..32).
const testKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

var testExp = time.Date(2026, 10, 18, 20, 40, 0, 0, time.UTC)

// testJoiner is the joining node's address in the codes of the tests: not
// the second host, as for a network whose second host is taken.
var testJoiner = netip.MustParseAddr("10.100.0.3")

func mustCode(t *testing.T, ep string) *Code {
	t.Helper()
	c, err := NewCode(netip.MustParseAddrPort(ep), testKey, netip.MustParsePrefix("10.100.0.0/24"), testJoiner, testExp)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCodeRoundTrip(t *testing.T) {
	re := regexp.MustCompile(`^m2[a-z2-7]+$`)
	for _, tc := range []struct {
		ep  string
		len int
	}{
		{"203.0.113.10:51820", 111},
		{"[2001:db8::1]:51820", 130},
	} {
		c := mustCode(t, tc.ep)
		s := c.String()
		if !re.MatchString(s) || len(s) != tc.len {
			t.Fatalf("%s: code %d chars, want %d of [a-z2-7]", tc.ep, len(s), tc.len)
		}
		got, err := ParseCode(s, testExp.Add(-time.Minute))
		if err != nil {
			t.Fatalf("%s: %v", tc.ep, err)
		}
		if *got != *c {
			t.Fatalf("%s: round trip mismatch:\n got %+v\nwant %+v", tc.ep, got, c)
		}
		inv, joi := got.Addresses()
		if inv != netip.MustParseAddr("10.100.0.1") || joi != netip.MustParseAddr("10.100.0.3") ||
			got.CIDR != netip.MustParsePrefix("10.100.0.0/24") {
			t.Fatalf("%s: addresses %s %s in %s", tc.ep, inv, joi, got.CIDR)
		}
	}
}

func TestNewCodeRejects(t *testing.T) {
	ep := netip.MustParseAddrPort("203.0.113.10:51820")
	cidr := netip.MustParsePrefix("10.100.0.0/24")
	joiner := func(a string) (*Code, error) { return NewCode(ep, testKey, cidr, netip.MustParseAddr(a), testExp) }
	for name, f := range map[string]func() (*Code, error){
		"endpoint": func() (*Code, error) { return NewCode(netip.AddrPort{}, testKey, cidr, testJoiner, testExp) },
		"port 0": func() (*Code, error) {
			return NewCode(netip.MustParseAddrPort("203.0.113.10:0"), testKey, cidr, testJoiner, testExp)
		},
		"key": func() (*Code, error) { return NewCode(ep, "nope", cidr, testJoiner, testExp) },
		"cidr": func() (*Code, error) {
			return NewCode(ep, testKey, netip.MustParsePrefix("10.0.0.0/8"), netip.MustParseAddr("10.0.0.2"), testExp)
		},
		"expiry": func() (*Code, error) {
			return NewCode(ep, testKey, cidr, testJoiner, time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC))
		},
		"joiner outside":           func() (*Code, error) { return joiner("10.100.1.3") },
		"joiner is the inviter":    func() (*Code, error) { return joiner("10.100.0.1") },
		"joiner network address":   func() (*Code, error) { return joiner("10.100.0.0") },
		"joiner broadcast address": func() (*Code, error) { return joiner("10.100.0.255") },
		"joiner missing":           func() (*Code, error) { return NewCode(ep, testKey, cidr, netip.Addr{}, testExp) },
	} {
		if c, err := f(); err == nil || c != nil {
			t.Errorf("%s: got %v, %v; want error", name, c, err)
		}
	}
}

func TestNewCodeTruncatesExpiry(t *testing.T) {
	c, err := NewCode(netip.MustParseAddrPort("203.0.113.10:51820"), testKey,
		netip.MustParsePrefix("10.100.0.0/24"), testJoiner, testExp.Add(1500*time.Millisecond).In(time.FixedZone("x", 3600)))
	if err != nil {
		t.Fatal(err)
	}
	if !c.ExpiresAt.Equal(testExp.Add(time.Second)) || c.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt = %v", c.ExpiresAt)
	}
}

func TestParseCodeTolerantInput(t *testing.T) {
	c := mustCode(t, "203.0.113.10:51820")
	s := c.String()
	in := "  " + strings.ToUpper(s[:50]) + "\r\n" + s[50:] + "\t\n"
	got, err := ParseCode(in, testExp)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *c {
		t.Fatalf("got %+v, want %+v", got, c)
	}
}

// forge builds a code from raw bytes with a valid checksum.
func forge(body []byte) string {
	h := sha256.New()
	h.Write([]byte("meshly-pair/2\x00"))
	h.Write(body)
	raw := append(append([]byte{}, body...), h.Sum(nil)[:4]...)
	return "m2" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
}

func TestParseCodeErrors(t *testing.T) {
	c := mustCode(t, "203.0.113.10:51820")
	s := c.String()
	swapped := []byte(s)
	if swapped[20] == 'a' {
		swapped[20] = 'b'
	} else {
		swapped[20] = 'a'
	}
	// A valid IPv4 body that tests mutate.
	body := func(mut func(b []byte)) string {
		b := []byte{4, 203, 0, 113, 10, 0xCA, 0x6C}
		b = append(b, bytes.Repeat([]byte{7}, 32)...)
		b = append(b, 10, 100, 0, 3, 24, 0x69, 0x00, 0x00, 0x00)
		b = append(b, bytes.Repeat([]byte{9}, 16)...)
		mut(b)
		return forge(b)
	}
	for _, tc := range []struct {
		name string
		in   string
		want error
	}{
		{"truncated", s[:len(s)-1], ErrMalformed},
		{"swapped char", string(swapped), ErrMalformed},
		{"version 1", "m1" + s[2:], ErrVersion},
		{"version 3", "m3" + s[2:], ErrVersion},
		{"empty", "", ErrMalformed},
		{"garbage", "hello", ErrMalformed},
		{"prefix only", "m2", ErrMalformed},
		{"forged ok layout", body(func(b []byte) {}), nil},
		{"zero key", body(func(b []byte) { clear(b[7:39]) }), ErrMalformed},
		{"/8 cidr", body(func(b []byte) { b[43] = 8 }), ErrMalformed},
		{"/33 cidr", body(func(b []byte) { b[43] = 33 }), ErrMalformed},
		{"joiner is the inviter", body(func(b []byte) { b[42] = 1 }), ErrMalformed},
		{"joiner network address", body(func(b []byte) { b[42] = 0 }), ErrMalformed},
		{"joiner broadcast address", body(func(b []byte) { b[42] = 255 }), ErrMalformed},
		{"public joiner", body(func(b []byte) { copy(b[39:43], []byte{8, 8, 8, 3}) }), ErrMalformed},
		{"port 0", body(func(b []byte) { b[5], b[6] = 0, 0 }), ErrMalformed},
		{"bad family", body(func(b []byte) { b[0] = 5 }), ErrMalformed},
		{"trailing byte", forge(append([]byte{4, 203, 0, 113, 10, 0xCA, 0x6C}, make([]byte, 80)...)), ErrMalformed},
	} {
		_, err := ParseCode(tc.in, time.Unix(0, 0))
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	// Expiry and clock skew.
	if _, err := ParseCode(s, testExp.Add(4*time.Minute)); err != nil {
		t.Errorf("within skew: %v", err)
	}
	if _, err := ParseCode(s, testExp.Add(ClockSkew)); err != nil {
		t.Errorf("at skew boundary: %v", err)
	}
	late := testExp.Add(ClockSkew + time.Second)
	_, err := ParseCode(s, late)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: err = %v", err)
	}
	for _, w := range []string{testExp.Format(time.RFC3339), late.Format(time.RFC3339)} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("message %q lacks %s", err, w)
		}
	}
}

// Every proper start of a code is partial, as typed or pasted (whitespace,
// letter case); a complete code, garbage, another version and a code with
// an unknown family are not.
func TestPartial(t *testing.T) {
	for _, ep := range []string{"203.0.113.10:51820", "[2001:db8::1]:51820"} {
		s := mustCode(t, ep).String()
		for i := 0; i < len(s); i++ {
			if !Partial(s[:i]) {
				t.Fatalf("%s: the first %d characters are not partial", ep, i)
			}
		}
		if Partial(s) || Partial(s+"a") {
			t.Errorf("%s: a complete code is partial", ep)
		}
		if half := len(s) / 2; !Partial(" " + strings.ToUpper(s[:half]) + "\r\n\t" + s[half:len(s)-1] + "\n") {
			t.Errorf("%s: a wrapped start of the code is not partial", ep)
		}
	}
	for _, s := range []string{"garbage", "hello", "m1", "m1aq", "m3", "m2a1", "m2ab", "m2aa", "x", "m2a=", "m2 aq!"} {
		if Partial(s) {
			t.Errorf("%q is partial", s)
		}
	}
}

func TestSecrets(t *testing.T) {
	a := mustCode(t, "203.0.113.10:51820")
	b := *a
	sa1, err := a.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	sa2, _ := a.Secrets()
	if *sa1 != *sa2 {
		t.Error("same code gave different secrets")
	}
	b.Secret[0] ^= 1
	sb, _ := b.Secrets()
	if sb.PrivateKey == sa1.PrivateKey || sb.PresharedKey == sa1.PresharedKey {
		t.Error("different secret gave a repeated key")
	}
	k := sa1.PrivateKey
	if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Errorf("private key not clamped: %x", k)
	}
	if sa1.PrivateKey == sa1.PresharedKey {
		t.Error("private and preshared keys are equal")
	}
	if sa1.TempPublicKey() != sa1.PrivateKey.PublicKey().String() {
		t.Error("TempPublicKey mismatch")
	}

	// Golden vector: guards against accidental changes of the derivation.
	var g Code
	for i := range g.Secret {
		g.Secret[i] = byte(i)
	}
	sg, err := g.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if got := sg.TempPublicKey(); got != goldenPublic {
		t.Errorf("TempPublicKey = %q, want %q", got, goldenPublic)
	}
	if got := sg.PresharedKey.String(); got != goldenPreshared {
		t.Errorf("PresharedKey = %q, want %q", got, goldenPreshared)
	}
}

const (
	goldenPublic    = "eaRZKncuUz6YOlYY9jPnrh47SUJLVKPC3ukulvM8mgs="
	goldenPreshared = "gMVyfhONv5kmy97O5iV8vDcgtehAYCz+/TjIh5oRVY0="
)

func TestWipe(t *testing.T) {
	c := mustCode(t, "203.0.113.10:51820")
	s, _ := c.Secrets()
	c.Wipe()
	s.Wipe()
	if c.Secret != [16]byte{} || s.PrivateKey != ([32]byte{}) || s.PresharedKey != ([32]byte{}) {
		t.Error("secret material not zeroed")
	}
}
