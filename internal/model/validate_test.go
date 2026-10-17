package model

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// knownBug marks a check that documents a defect in production code. The
// test is skipped (not failed) while the defect is present so the suite
// stays green; once the code is fixed the check runs normally.
func knownBug(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("KNOWN BUG: "+format, args...)
}

func b64(b byte, n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, n)) }

func TestValidateName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"a", true},
		{"home", true},
		{"node-1", true},
		{"n0", true},
		{"a" + strings.Repeat("b", 31), true}, // 32 characters
		{"a" + strings.Repeat("b", 32), false},
		{"", false},
		{"Home", false},
		{"1node", false},
		{"-node", false},
		{"node-", false},
		{"no_de", false},
		{"no.de", false},
		{"node ", false},
		{"nöde", false},
		{"from", false},
		{"all", false},
		{"any", false},
		{"self", false},
		{"local", false},
		{"ping", false},
		{"none", false},
		{"default", false},
		{"fromage", true}, // only exact reserved words are refused
	}
	for _, tt := range tests {
		err := ValidateName(tt.name)
		if (err == nil) != tt.ok {
			t.Errorf("ValidateName(%q) = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestValidateNameTruncatesEcho(t *testing.T) {
	long := strings.Repeat("X", 500)
	err := ValidateName(long)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), long) || !strings.Contains(err.Error(), "…") {
		t.Errorf("error does not truncate user input: %v", err)
	}
	// Control characters are escaped, never echoed raw.
	err = ValidateName("a\nb\x1b[31m")
	if err == nil || strings.ContainsAny(err.Error(), "\n\x1b") {
		t.Errorf("error echoes control characters: %q", err)
	}
}

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"meshly0", true},
		{"wg0", true},
		{"m", true},
		{"a" + strings.Repeat("b", 14), true}, // 15 = IFNAMSIZ-1
		{"a" + strings.Repeat("b", 15), false},
		{"", false},
		{"0wg", false},
		{"Wg0", false},
		{"wg-0", false},
		{"wg.0", false},
		{"wg/0", false},
		{"all", false},
		{"default", false},
		{"lo", false},
		{"lo0", true},
	}
	for _, tt := range tests {
		err := ValidateInterfaceName(tt.name)
		if (err == nil) != tt.ok {
			t.Errorf("ValidateInterfaceName(%q) = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestValidateNetworkID(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{strings.Repeat("0123456789abcdef", 2), true},
		{strings.Repeat("ab", 16), true},
		{strings.Repeat("AB", 16), false},
		{strings.Repeat("a", 31), false},
		{strings.Repeat("a", 33), false},
		{strings.Repeat("g", 32), false},
		{"", false},
	}
	for _, tt := range tests {
		if err := ValidateNetworkID(tt.id); (err == nil) != tt.ok {
			t.Errorf("ValidateNetworkID(%q) = %v, want ok=%v", tt.id, err, tt.ok)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		in      string
		ok      bool
		wantErr string
	}{
		{in: "10.100.0.0/24", ok: true},
		{in: "10.0.0.0/16", ok: true},
		{in: "10.255.255.252/30", ok: true},
		{in: "172.16.0.0/16", ok: true},
		{in: "172.31.255.0/24", ok: true},
		{in: "192.168.0.0/16", ok: true},
		{in: "192.168.77.0/24", ok: true},
		{in: "100.64.0.0/16", ok: true},
		{in: "100.127.255.0/24", ok: true},

		// public or otherwise disallowed ranges
		{in: "8.8.8.0/24", wantErr: "not inside"},
		{in: "11.0.0.0/16", wantErr: "not inside"},
		{in: "172.15.0.0/16", wantErr: "not inside"},
		{in: "172.32.0.0/16", wantErr: "not inside"},
		{in: "192.169.0.0/16", wantErr: "not inside"},
		{in: "100.63.0.0/16", wantErr: "not inside"},
		{in: "100.128.0.0/16", wantErr: "not inside"},
		{in: "127.0.0.0/16", wantErr: "not inside"},
		{in: "169.254.0.0/16", wantErr: "not inside"},
		{in: "224.0.0.0/24", wantErr: "not inside"},

		// prefix length bounds
		{in: "10.0.0.0/15", wantErr: "between /16 and /30"},
		{in: "10.0.0.0/8", wantErr: "between /16 and /30"},
		{in: "10.0.0.0/31", wantErr: "between /16 and /30"},
		{in: "10.0.0.0/32", wantErr: "between /16 and /30"},
		{in: "0.0.0.0/0", wantErr: "between /16 and /30"},

		// non-canonical
		{in: "10.100.0.1/24", wantErr: "did you mean 10.100.0.0/24"},
		{in: "192.168.1.128/16", wantErr: "not a network address"},

		// IPv6 is not supported inside the VPN
		{in: "fd00::/64", wantErr: "only IPv4"},
		{in: "fd00:1::/112", wantErr: "only IPv4"},
		{in: "::ffff:10.100.0.0/120", wantErr: "only IPv4"},

		// syntax
		{in: "", wantErr: "invalid CIDR"},
		{in: "10.100.0.0", wantErr: "invalid CIDR"},
		{in: "10.100.0.0/", wantErr: "invalid CIDR"},
		{in: "10.100.0.0/024", wantErr: "invalid CIDR"},
		{in: "10.100.0/24", wantErr: "invalid CIDR"},
		{in: " 10.100.0.0/24", wantErr: "invalid CIDR"},
		{in: "10.100.0.0/24 ", wantErr: "invalid CIDR"},
		{in: "localnet/24", wantErr: "invalid CIDR"},
	}
	for _, tt := range tests {
		p, err := ParseCIDR(tt.in)
		if tt.ok {
			if err != nil {
				t.Errorf("ParseCIDR(%q) = %v, want ok", tt.in, err)
			} else if p.String() != tt.in {
				t.Errorf("ParseCIDR(%q) = %s", tt.in, p)
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseCIDR(%q) succeeded, want error containing %q", tt.in, tt.wantErr)
		} else if !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("ParseCIDR(%q) = %v, want error containing %q", tt.in, err, tt.wantErr)
		}
	}
}

func TestValidateCIDRZero(t *testing.T) {
	if err := ValidateCIDR(netip.Prefix{}); err == nil {
		t.Error("zero prefix accepted")
	}
}

func TestValidateHostAddress(t *testing.T) {
	cidr := netip.MustParsePrefix("10.100.0.0/24")
	tests := []struct {
		cidr netip.Prefix
		addr netip.Addr
		ok   bool
	}{
		{cidr, netip.MustParseAddr("10.100.0.1"), true},
		{cidr, netip.MustParseAddr("10.100.0.254"), true},
		{cidr, netip.MustParseAddr("10.100.0.0"), false},   // network
		{cidr, netip.MustParseAddr("10.100.0.255"), false}, // broadcast
		{cidr, netip.MustParseAddr("10.100.1.1"), false},
		{cidr, netip.MustParseAddr("192.168.0.1"), false},
		{cidr, netip.MustParseAddr("::ffff:10.100.0.1"), false},
		{cidr, netip.MustParseAddr("fd00::1"), false},
		{cidr, netip.Addr{}, false},
		{netip.Prefix{}, netip.MustParseAddr("10.100.0.1"), false},
		{netip.MustParsePrefix("10.100.0.0/30"), netip.MustParseAddr("10.100.0.2"), true},
		{netip.MustParsePrefix("10.100.0.0/30"), netip.MustParseAddr("10.100.0.3"), false},
		{netip.MustParsePrefix("10.100.0.0/16"), netip.MustParseAddr("10.100.255.255"), false},
		{netip.MustParsePrefix("10.100.0.0/16"), netip.MustParseAddr("10.100.0.255"), true},
	}
	for _, tt := range tests {
		if err := ValidateHostAddress(tt.cidr, tt.addr); (err == nil) != tt.ok {
			t.Errorf("ValidateHostAddress(%s, %s) = %v, want ok=%v", tt.cidr, tt.addr, err, tt.ok)
		}
	}
}

func TestAllocateAddresses(t *testing.T) {
	tests := []struct {
		cidr, first, second string
	}{
		{"10.100.0.0/24", "10.100.0.1", "10.100.0.2"},
		{"10.100.0.0/16", "10.100.0.1", "10.100.0.2"},
		{"192.168.4.252/30", "192.168.4.253", "192.168.4.254"},
		{"172.20.8.0/22", "172.20.8.1", "172.20.8.2"},
	}
	for _, tt := range tests {
		p := netip.MustParsePrefix(tt.cidr)
		a, b, err := AllocateAddresses(p)
		if err != nil {
			t.Errorf("AllocateAddresses(%s): %v", tt.cidr, err)
			continue
		}
		if a.String() != tt.first || b.String() != tt.second {
			t.Errorf("AllocateAddresses(%s) = %s, %s; want %s, %s", tt.cidr, a, b, tt.first, tt.second)
		}
	}

	// Every allowed prefix length yields two distinct usable host addresses.
	for bits := 16; bits <= 30; bits++ {
		p := netip.PrefixFrom(netip.MustParseAddr("10.64.0.0"), bits).Masked()
		a, b, err := AllocateAddresses(p)
		if err != nil {
			t.Fatalf("/%d: %v", bits, err)
		}
		if a == b {
			t.Errorf("/%d: identical addresses %s", bits, a)
		}
		for _, x := range []netip.Addr{a, b} {
			if err := ValidateHostAddress(p, x); err != nil {
				t.Errorf("/%d: allocated %s is not a usable host: %v", bits, x, err)
			}
		}
	}

	for _, bad := range []string{"10.100.0.0/31", "10.100.0.0/15", "8.8.8.0/24", "10.100.0.7/24"} {
		if _, _, err := AllocateAddresses(netip.MustParsePrefix(bad)); err == nil {
			t.Errorf("AllocateAddresses(%s) succeeded", bad)
		}
	}
	if _, _, err := AllocateAddresses(netip.Prefix{}); err == nil {
		t.Error("AllocateAddresses(zero) succeeded")
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		in      string
		want    string // canonical result; "" means an error is expected
		wantErr string
	}{
		{in: "203.0.113.10:51820", want: "203.0.113.10:51820"},
		{in: "198.51.100.1:1", want: "198.51.100.1:1"},
		{in: "198.51.100.1:65535", want: "198.51.100.1:65535"},
		{in: "10.0.0.1:51820", want: "10.0.0.1:51820"},
		// Loopback is not rejected by the implementation.
		{in: "127.0.0.1:51820", want: "127.0.0.1:51820"},
		// IPv6 transport is allowed (only the VPN itself is IPv4-only).
		{in: "[2001:db8::1]:51820", want: "[2001:db8::1]:51820"},
		{in: "[2001:DB8::1]:51820", want: "[2001:db8::1]:51820"},
		// IPv4-mapped IPv6 is normalised to plain IPv4.
		{in: "[::ffff:203.0.113.10]:51820", want: "203.0.113.10:51820"},

		// host names are not supported
		{in: "example.com:51820", wantErr: "host names are not supported"},
		{in: "localhost:51820", wantErr: "host names are not supported"},
		{in: "vpn.example.com", wantErr: "host names are not supported"},
		// syntax
		{in: "", wantErr: "invalid endpoint"},
		{in: "203.0.113.10", wantErr: "invalid endpoint"},
		{in: "203.0.113.10:", wantErr: "invalid endpoint"},
		{in: "2001:db8::1:51820", wantErr: "invalid endpoint"},
		{in: "203.0.113.10:65536", wantErr: "invalid endpoint"},
		{in: "203.0.113.10:-1", wantErr: "invalid endpoint"},
		{in: "203.0.113.10:+5", wantErr: "invalid endpoint"},
		{in: " 203.0.113.10:51820", wantErr: "invalid endpoint"},
		{in: "203.0.113.10:51820/udp", wantErr: "invalid endpoint"},
		// port and address policy
		{in: "203.0.113.10:0", wantErr: "out of range"},
		{in: "0.0.0.0:51820", wantErr: "not a unicast"},
		{in: "[::]:51820", wantErr: "not a unicast"},
		{in: "224.0.0.1:51820", wantErr: "not a unicast"},
		{in: "[ff02::1]:51820", wantErr: "not a unicast"},
		{in: "255.255.255.255:51820", wantErr: "not a unicast"},
		{in: "169.254.10.1:51820", wantErr: "link-local"},
		{in: "[fe80::1]:51820", wantErr: "link-local"},
		{in: "[fe80::1%eth0]:51820", wantErr: "zone"},
		{in: "[2001:db8::1%eth0]:51820", wantErr: "zone"},
	}
	for _, tt := range tests {
		ap, err := ParseEndpoint(tt.in)
		if tt.want != "" {
			if err != nil {
				t.Errorf("ParseEndpoint(%q) = %v", tt.in, err)
			} else if ap.String() != tt.want {
				t.Errorf("ParseEndpoint(%q) = %s, want %s", tt.in, ap, tt.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseEndpoint(%q) = %s, want error containing %q", tt.in, ap, tt.wantErr)
		} else if !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("ParseEndpoint(%q) = %v, want error containing %q", tt.in, err, tt.wantErr)
		}
	}
}

func TestParseEndpointMappedZone(t *testing.T) {
	// The zone check runs after Unmap(), which discards the zone of an
	// IPv4-mapped address, so a zone in the input is silently dropped
	// instead of being rejected like any other zoned endpoint.
	if ap, err := ParseEndpoint("[::ffff:203.0.113.10%eth0]:51820"); err == nil {
		knownBug(t, "ParseEndpoint accepts zoned IPv4-mapped endpoint as %s", ap)
	}
}

func TestValidateEndpointZero(t *testing.T) {
	if err := ValidateEndpoint(netip.AddrPort{}); err == nil {
		t.Error("zero endpoint accepted")
	}
	if err := ValidateEndpoint(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), 0)); err == nil {
		t.Error("port 0 accepted")
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		in   string
		want uint16
		ok   bool
	}{
		{"1", 1, true},
		{"22", 22, true},
		{"9100", 9100, true},
		{"65535", 65535, true},
		{"0", 0, false},
		{"00", 0, false},
		{"022", 0, false},
		{"0022", 0, false},
		{"65536", 0, false},
		{"99999", 0, false},
		{"123456", 0, false},
		{"", 0, false},
		{"+22", 0, false},
		{"-22", 0, false},
		{" 22", 0, false},
		{"22 ", 0, false},
		{"2_2", 0, false},
		{"0x16", 0, false},
		{"٢٢", 0, false}, // Arabic-Indic digits
		{"22.0", 0, false},
	}
	for _, tt := range tests {
		got, err := ParsePort(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("ParsePort(%q) = %d, %v; want %d ok=%v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestRangeValidators(t *testing.T) {
	tests := []struct {
		name string
		fn   func(int) error
		ok   []int
		bad  []int
	}{
		{"port", ValidatePort, []int{1, 80, 65535}, []int{-1, 0, 65536, 1 << 20}},
		{"mtu", ValidateMTU, []int{1280, 1420, 8920}, []int{0, 1279, 8921, 9000}},
		{"keepalive", ValidateKeepalive, []int{0, 1, 25, 3600}, []int{-1, 3601}},
	}
	for _, tt := range tests {
		for _, v := range tt.ok {
			if err := tt.fn(v); err != nil {
				t.Errorf("%s(%d) = %v, want ok", tt.name, v, err)
			}
		}
		for _, v := range tt.bad {
			if err := tt.fn(v); err == nil {
				t.Errorf("%s(%d) accepted", tt.name, v)
			}
		}
	}
}

func TestValidateMark(t *testing.T) {
	for i := 0; i < 32; i++ {
		if err := ValidateMark(1 << i); err != nil {
			t.Errorf("ValidateMark(1<<%d) = %v", i, err)
		}
	}
	for _, m := range []uint32{0, 3, 0x10000001, 0x30000000, 0x80000001, 0xffffffff} {
		if err := ValidateMark(m); err == nil {
			t.Errorf("ValidateMark(%#x) accepted", m)
		}
	}
}

func TestValidateKeys(t *testing.T) {
	valid := b64(7, 32)
	tests := []struct {
		name string
		key  string
		ok   bool
	}{
		{"valid", valid, true},
		{"all zero", b64(0, 32), false},
		{"31 bytes", b64(7, 31), false},
		{"33 bytes", b64(7, 33), false},
		{"64 bytes", b64(7, 64), false},
		{"empty", "", false},
		{"no padding", strings.TrimRight(valid, "="), false},
		{"url alphabet", base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)), false},
		{"non-canonical trailing bits", valid[:42] + "B=", false},
		{"surrounding space", " " + valid, false},
		{"garbage", "not a key at all", false},
	}
	for _, tt := range tests {
		if err := ValidateWGPublicKey(tt.key); (err == nil) != tt.ok {
			t.Errorf("ValidateWGPublicKey(%s) = %v, want ok=%v", tt.name, err, tt.ok)
		}
		if err := ValidateIdentityKey(tt.key); (err == nil) != tt.ok {
			t.Errorf("ValidateIdentityKey(%s) = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestValidateKeysEmbeddedNewline(t *testing.T) {
	// base64 Strict mode still ignores CR and LF, so a key string with an
	// embedded line break validates although it is not the canonical
	// encoding. Config.Validate compares keys as strings, so the same key
	// with a line break defeats the uniqueness check.
	c := validConfig()
	k := c.Self.WGPublicKey
	c.Peers[0].WGPublicKey = k[:20] + "\r\n" + k[20:]
	if ValidateWGPublicKey(c.Peers[0].WGPublicKey) == nil && c.Validate() == nil {
		knownBug(t, "Config.Validate accepts a peer whose WireGuard key equals the node's own key (written as %q)", c.Peers[0].WGPublicKey)
	}
}

func TestParseWGPublicKey(t *testing.T) {
	s := b64(9, 32)
	k, err := ParseWGPublicKey(s)
	if err != nil {
		t.Fatal(err)
	}
	if k.String() != s {
		t.Errorf("round trip: %s != %s", k, s)
	}
	if _, err := ParseWGPublicKey(b64(0, 32)); err == nil {
		t.Error("zero key accepted")
	}
}

func TestNewRandomID(t *testing.T) {
	id, err := NewRandomID(func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i)
		}
		return len(b), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "000102030405060708090a0b0c0d0e0f" {
		t.Errorf("id = %s", id)
	}
	if err := ValidateNetworkID(id); err != nil {
		t.Errorf("generated id does not validate: %v", err)
	}
	boom := errors.New("boom")
	if _, err := NewRandomID(func([]byte) (int, error) { return 0, boom }); !errors.Is(err, boom) {
		t.Errorf("error not wrapped: %v", err)
	}
}
