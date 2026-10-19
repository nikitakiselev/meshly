// Package pairing implements the one-time invite code that adds a node to a
// network: the code format and the temporary keys derived from its secret.
package pairing

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/nikitakiselev/meshly/internal/model"
)

const (
	DefaultTTL = 10 * time.Minute
	MinTTL     = time.Minute
	MaxTTL     = time.Hour
	// ClockSkew is how long past its expiry a code is still accepted, to
	// tolerate unsynchronized clocks.
	ClockSkew = 5 * time.Minute
)

var (
	ErrMalformed = errors.New("the invite code is damaged or incomplete")
	ErrVersion   = errors.New("the invite code was made by another meshly version; upgrade meshly on both nodes")
	ErrExpired   = errors.New("the invite code has expired")
)

const (
	prefix    = "m2"
	domain    = "meshly-pair/2"
	checkLen  = 4
	secretLen = 16
	// bodyLen4 and bodyLen6 are the bytes before the checksum, by family.
	bodyLen4 = 1 + 4 + 2 + 32 + 4 + 1 + 4 + secretLen
	bodyLen6 = bodyLen4 + 12
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Code is the content of an invite code. Secret is key material: never
// print or log a Code.
type Code struct {
	Endpoint   netip.AddrPort // inviter's public UDP endpoint
	InviterKey string         // inviter's WireGuard public key, base64
	CIDR       netip.Prefix
	Joiner     netip.Addr // the joining node's VPN address
	ExpiresAt  time.Time  // whole seconds, UTC
	Secret     [secretLen]byte
}

// NewCode validates the fields and returns a Code with a fresh random
// secret. expiresAt is truncated to whole seconds.
func NewCode(endpoint netip.AddrPort, inviterKey string, cidr netip.Prefix, joiner netip.Addr, expiresAt time.Time) (*Code, error) {
	c := &Code{
		Endpoint:   endpoint,
		InviterKey: inviterKey,
		CIDR:       cidr,
		Joiner:     joiner,
		ExpiresAt:  expiresAt.Truncate(time.Second).UTC(),
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	if _, err := rand.Read(c.Secret[:]); err != nil {
		return nil, fmt.Errorf("read random secret: %w", err)
	}
	return c, nil
}

func (c *Code) validate() error {
	if a := c.Endpoint.Addr(); a.Is4In6() {
		return errors.New("endpoint must be a plain IPv4 or IPv6 address")
	}
	if err := model.ValidateEndpoint(c.Endpoint); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if err := model.ValidateWGPublicKey(c.InviterKey); err != nil {
		return fmt.Errorf("inviter key: %w", err)
	}
	inviter, err := model.FirstHost(c.CIDR)
	if err != nil {
		return fmt.Errorf("CIDR: %w", err)
	}
	if err := model.ValidateHostAddress(c.CIDR, c.Joiner); err != nil {
		return fmt.Errorf("joiner: %w", err)
	}
	if c.Joiner == inviter {
		return errors.New("joiner: the inviter's address")
	}
	if u := c.ExpiresAt.Unix(); u < 0 || u > math.MaxUint32 {
		return errors.New("expiry is out of range")
	}
	return nil
}

func checksum(body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil)[:checkLen]
}

// String returns the text form of the code. It contains the secret.
func (c *Code) String() string {
	var b []byte
	if c.Endpoint.Addr().Is4() {
		b = append(b, 4)
		a := c.Endpoint.Addr().As4()
		b = append(b, a[:]...)
	} else {
		b = append(b, 6)
		a := c.Endpoint.Addr().As16()
		b = append(b, a[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, c.Endpoint.Port())
	key, _ := wgtypes.ParseKey(c.InviterKey)
	b = append(b, key[:]...)
	joiner := c.Joiner.As4()
	b = append(b, joiner[:]...)
	b = append(b, byte(c.CIDR.Bits()))
	b = binary.BigEndian.AppendUint32(b, uint32(c.ExpiresAt.Unix()))
	b = append(b, c.Secret[:]...)
	b = append(b, checksum(b)...)
	return prefix + strings.ToLower(b32.EncodeToString(b))
}

// normalize removes whitespace and lowercases: how a person's input is read.
func normalize(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s))
}

// Partial reports whether s, read as ParseCode reads it, is the start of a
// code that more input could complete: the prefix, base32, and fewer
// characters than the family byte implies. A complete code, garbage and
// another version are not partial.
func Partial(s string) bool {
	s = normalize(s)
	if len(s) < len(prefix) {
		return s == prefix[:len(s)]
	}
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	body := s[len(prefix):]
	v := make([]byte, len(body)) // the 5-bit values
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c >= 'a' && c <= 'z':
			v[i] = c - 'a'
		case c >= '2' && c <= '7':
			v[i] = c - '2' + 26
		default:
			return false
		}
	}
	if len(body) < 2 {
		return true
	}
	switch v[0]<<3 | v[1]>>2 { // the family byte
	case 4:
		return len(body) < b32.EncodedLen(bodyLen4+checkLen)
	case 6:
		return len(body) < b32.EncodedLen(bodyLen6+checkLen)
	}
	return false
}

// ParseCode decodes and validates a code typed or pasted by a person:
// whitespace anywhere and letter case are ignored. A code is accepted up to
// ClockSkew past its expiry.
func ParseCode(s string, now time.Time) (*Code, error) {
	s = normalize(s)
	if len(s) >= 2 && s[0] == 'm' && s[1] >= '0' && s[1] <= '9' && s[:2] != prefix {
		return nil, ErrVersion
	}
	if !strings.HasPrefix(s, prefix) {
		return nil, ErrMalformed
	}
	raw, err := b32.DecodeString(strings.ToUpper(s[len(prefix):]))
	if err != nil || len(raw) < bodyLen4+checkLen {
		return nil, ErrMalformed
	}
	body, sum := raw[:len(raw)-checkLen], raw[len(raw)-checkLen:]
	if !bytes.Equal(sum, checksum(body)) {
		return nil, ErrMalformed
	}

	var c Code
	var ip netip.Addr
	switch body[0] {
	case 4:
		if len(body) != bodyLen4 {
			return nil, ErrMalformed
		}
		ip = netip.AddrFrom4([4]byte(body[1:5]))
		body = body[5:]
	case 6:
		if len(body) != bodyLen6 {
			return nil, ErrMalformed
		}
		ip = netip.AddrFrom16([16]byte(body[1:17]))
		body = body[17:]
	default:
		return nil, ErrMalformed
	}
	c.Endpoint = netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body))
	c.InviterKey = wgtypes.Key(body[2:34]).String()
	c.Joiner = netip.AddrFrom4([4]byte(body[34:38]))
	c.CIDR = netip.PrefixFrom(c.Joiner, int(body[38])).Masked()
	c.ExpiresAt = time.Unix(int64(binary.BigEndian.Uint32(body[39:43])), 0).UTC()
	copy(c.Secret[:], body[43:])
	if c.validate() != nil {
		return nil, ErrMalformed
	}
	if now.After(c.ExpiresAt.Add(ClockSkew)) {
		return nil, fmt.Errorf("%w (valid until %s, now %s)", ErrExpired,
			c.ExpiresAt.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return &c, nil
}

// Addresses returns the VPN addresses of the inviter, the first host of
// the network, and the joiner.
func (c *Code) Addresses() (inviter, joiner netip.Addr) {
	inviter, _ = model.FirstHost(c.CIDR)
	return inviter, c.Joiner
}

// Wipe zeroes the secret.
func (c *Code) Wipe() { clear(c.Secret[:]) }

// Secrets are the temporary keys derived from a code's secret.
type Secrets struct {
	PrivateKey   wgtypes.Key // temporary WireGuard key of the joiner
	PresharedKey wgtypes.Key
}

// Secrets derives the temporary keys with HKDF-SHA256.
func (c *Code) Secrets() (*Secrets, error) {
	priv, err := hkdf.Key(sha256.New, c.Secret[:], nil, domain+" wireguard-key", 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	psk, err := hkdf.Key(sha256.New, c.Secret[:], nil, domain+" preshared-key", 32)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	// Clamp as in RFC 7748.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	return &Secrets{PrivateKey: wgtypes.Key(priv), PresharedKey: wgtypes.Key(psk)}, nil
}

// TempPublicKey returns the base64 public key of the temporary key.
func (s *Secrets) TempPublicKey() string { return s.PrivateKey.PublicKey().String() }

// Wipe zeroes the keys.
func (s *Secrets) Wipe() {
	clear(s.PrivateKey[:])
	clear(s.PresharedKey[:])
}
