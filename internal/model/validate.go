package model

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	nameRe   = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`)
	ifnameRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)
	hexIDRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// reservedNames cannot be used as node or network names because they are
// either CLI keywords or would be ambiguous in rules.
var reservedNames = map[string]bool{
	"from": true, "all": true, "any": true, "self": true, "local": true,
	"ping": true, "none": true, "default": true,
}

// reservedIfnames would make per-interface sysctl paths global
// (/proc/sys/net/ipv4/conf/{all,default}) or collide with loopback.
var reservedIfnames = map[string]bool{"all": true, "default": true, "lo": true}

// allowedRanges are the private/shared IPv4 ranges a VPN CIDR may use.
var allowedRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// ValidateName checks node and network names: lowercase DNS-label style,
// 1..32 characters.
func ValidateName(s string) error {
	if !nameRe.MatchString(s) {
		return fmt.Errorf("invalid name %q: use 1-32 characters a-z, 0-9 and '-', starting with a letter", truncate(s))
	}
	if reservedNames[s] {
		return fmt.Errorf("name %q is reserved", s)
	}
	return nil
}

// ValidateInterfaceName checks the managed interface name.
func ValidateInterfaceName(s string) error {
	if !ifnameRe.MatchString(s) || reservedIfnames[s] {
		return fmt.Errorf("invalid interface name %q: use 1-15 characters a-z and 0-9, starting with a letter", truncate(s))
	}
	return nil
}

// ValidateNetworkID checks a random network or operation identifier
// (128 bits, lowercase hex).
func ValidateNetworkID(s string) error {
	if !hexIDRe.MatchString(s) {
		return errors.New("must be 32 lowercase hex characters")
	}
	return nil
}

// ValidateCIDR checks the VPN prefix: IPv4, canonical, /16../30, inside a
// private or shared address range.
func ValidateCIDR(p netip.Prefix) error {
	if !p.IsValid() {
		return errors.New("missing or invalid CIDR")
	}
	if !p.Addr().Is4() {
		return errors.New("only IPv4 is supported inside the VPN")
	}
	if p.Masked() != p {
		return fmt.Errorf("%s is not a network address (did you mean %s?)", p, p.Masked())
	}
	if p.Bits() < 16 || p.Bits() > 30 {
		return fmt.Errorf("prefix length must be between /16 and /30, got /%d", p.Bits())
	}
	for _, r := range allowedRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return nil
		}
	}
	return fmt.Errorf("%s is not inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10", p)
}

// ParseCIDR parses and validates a VPN CIDR.
func ParseCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", truncate(s))
	}
	return p, ValidateCIDR(p)
}

// ValidateHostAddress checks that a is a usable host address of cidr.
func ValidateHostAddress(cidr netip.Prefix, a netip.Addr) error {
	if !a.IsValid() || !a.Is4() {
		return errors.New("missing or non-IPv4 address")
	}
	if !cidr.IsValid() || !cidr.Contains(a) {
		return fmt.Errorf("%s is outside %s", a, cidr)
	}
	if a == cidr.Masked().Addr() || a == lastAddr(cidr) {
		return fmt.Errorf("%s is the network or broadcast address of %s", a, cidr)
	}
	return nil
}

// FirstHost returns the first host address of the prefix: the address of
// the node that creates the network, through which every other node joins.
func FirstHost(cidr netip.Prefix) (netip.Addr, error) {
	if err := ValidateCIDR(cidr); err != nil {
		return netip.Addr{}, err
	}
	return cidr.Addr().Next(), nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= (1 << (32 - p.Bits())) - 1
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// ParseEndpoint parses a numeric "IPv4:port" or "[IPv6]:port" endpoint.
// Host names are deliberately not supported in the MVP.
func ParseEndpoint(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: expected numeric IP:PORT (host names are not supported)", truncate(s))
	}
	if port := s[strings.LastIndexByte(s, ':')+1:]; len(port) > 1 && port[0] == '0' {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: port with leading zeros", truncate(s))
	}
	// The zone check must see the address before Unmap drops the zone.
	if ap.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("endpoint must not contain an IPv6 zone")
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	return ap, ValidateEndpoint(ap)
}

// ParseEndpointOrAddr is ParseEndpoint that also accepts a bare address
// ("203.0.113.10", "2001:db8::1" or "[2001:db8::1]") and gives it the port
// defPort. An IPv6 endpoint with a port needs the brackets.
func ParseEndpointOrAddr(s string, defPort uint16) (netip.AddrPort, error) {
	host := s
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		host = s[1 : len(s)-1]
	}
	a, err := netip.ParseAddr(host)
	if err != nil || (host != s && !a.Is6()) {
		if _, err := netip.ParseAddrPort(s); err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: expected a numeric IP or IP:PORT (host names are not supported)", truncate(s))
		}
		return ParseEndpoint(s)
	}
	if a.Zone() != "" {
		return netip.AddrPort{}, errors.New("endpoint must not contain an IPv6 zone")
	}
	ap := netip.AddrPortFrom(a.Unmap(), defPort)
	return ap, ValidateEndpoint(ap)
}

// LinkAddr is an address and the interface that carries it.
type LinkAddr struct {
	Addr netip.Addr
	Link string
}

// sharedSpace is the carrier-grade NAT range (RFC 6598).
var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// IsPublicIPv4 reports whether a is an IPv4 address hosts on the internet
// can send packets to: not private (RFC 1918), shared (RFC 6598), loopback,
// link-local, multicast or reserved. The documentation ranges (RFC 5737)
// count as public: they never appear on real hosts, and the test labs use
// them as the internet.
func IsPublicIPv4(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	switch {
	case a.IsPrivate(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsMulticast(), a.IsUnspecified(),
		sharedSpace.Contains(a), b[0] == 0, b[0] >= 240:
		return false
	}
	return true
}

// PublicIPv4 returns the public IPv4 addresses among addrs, sorted and
// without duplicates.
func PublicIPv4(addrs []LinkAddr) []LinkAddr {
	var out []LinkAddr
	for _, la := range addrs {
		la.Addr = la.Addr.Unmap()
		if IsPublicIPv4(la.Addr) && !slices.Contains(out, la) {
			out = append(out, la)
		}
	}
	slices.SortFunc(out, func(x, y LinkAddr) int {
		if c := x.Addr.Compare(y.Addr); c != 0 {
			return c
		}
		return strings.Compare(x.Link, y.Link)
	})
	return out
}

// ValidateEndpoint checks a WireGuard transport endpoint.
func ValidateEndpoint(ap netip.AddrPort) error {
	a := ap.Addr()
	switch {
	case !a.IsValid():
		return errors.New("invalid endpoint address")
	case a.Zone() != "":
		return errors.New("endpoint must not contain an IPv6 zone")
	case a.IsUnspecified(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("endpoint address %s is not a unicast address", a)
	case a.IsLinkLocalUnicast():
		return fmt.Errorf("endpoint address %s is link-local", a)
	}
	return ValidatePort(int(ap.Port()))
}

// ValidatePort checks a TCP/UDP port number.
func ValidatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", p)
	}
	return nil
}

// ParsePort parses a decimal port without sign, spaces or leading zeros.
func ParsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("invalid port %q", truncate(s))
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port %q", truncate(s))
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", truncate(s))
	}
	if err := ValidatePort(n); err != nil {
		return 0, err
	}
	return uint16(n), nil
}

// ValidateMTU checks the interface MTU. 1280 keeps IPv6 outer transport
// valid; 8920 is a 9000-byte jumbo frame minus WireGuard overhead.
func ValidateMTU(m int) error {
	if m < 1280 || m > 8920 {
		return fmt.Errorf("MTU %d out of range 1280-8920", m)
	}
	return nil
}

// ValidateKeepalive checks PersistentKeepalive seconds (0 disables).
func ValidateKeepalive(s int) error {
	if s < 0 || s > 3600 {
		return fmt.Errorf("keepalive %d out of range 0-3600 seconds", s)
	}
	return nil
}

// ValidateMark checks the firewall mark: exactly one bit.
func ValidateMark(m uint32) error {
	if bits.OnesCount32(m) != 1 {
		return fmt.Errorf("mark 0x%08x must have exactly one bit set", m)
	}
	return nil
}

// decodeKey decodes a key in canonical base64 only: the decoder ignores
// CR and LF, so without the round-trip check one key would have many
// spellings and string comparisons (duplicate keys) could be bypassed.
func decodeKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("non-canonical base64")
	}
	return b, nil
}

// ValidateWGPublicKey checks a base64 Curve25519 public key.
func ValidateWGPublicKey(s string) error {
	b, err := decodeKey(s)
	if err != nil || len(b) != 32 {
		return errors.New("must be a base64-encoded 32-byte WireGuard key")
	}
	if isZero(b) {
		return errors.New("all-zero key is not allowed")
	}
	return nil
}

// NewRandomID returns 128 random bits as lowercase hex.
func NewRandomID(randRead func([]byte) (int, error)) (string, error) {
	var b [16]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("random source failed: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func isZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// truncate bounds user-controlled strings echoed in error messages; callers
// format them with %q so control characters are escaped.
func truncate(s string) string {
	const max = 64
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}
