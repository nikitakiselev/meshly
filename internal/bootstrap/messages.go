package bootstrap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/model"
)

// Time limits of the protocol.
const (
	DefaultInviteTTL = time.Hour
	MaxInviteTTL     = 24 * time.Hour
	AcceptTTL        = 24 * time.Hour
	// ClockSkew tolerates small clock differences between the nodes.
	ClockSkew = 5 * time.Minute
)

// NetworkInfo describes the network in invites and accepts.
type NetworkInfo struct {
	ID   string       `json:"id"`
	Name string       `json:"name"`
	CIDR netip.Prefix `json:"cidr"`
	MTU  int          `json:"mtu"`
}

// NodeInfo is the identity and addressing of a node.
type NodeInfo struct {
	Name        string         `json:"name"`
	IdentityKey string         `json:"identity_key"`
	WGPublicKey string         `json:"wg_public_key"`
	Address     netip.Addr     `json:"address"`
	Endpoint    netip.AddrPort `json:"endpoint,omitzero"`
}

// Fingerprint is the human-verifiable identity of the node.
func (n NodeInfo) Fingerprint() string { return Fingerprint(n.IdentityKey, n.WGPublicKey) }

// Invite is created by the inviting node (typically the VPS).
type Invite struct {
	SchemaVersion   int         `json:"schema_version"`
	Type            MessageType `json:"type"`
	Protocol        string      `json:"protocol"`
	Network         NetworkInfo `json:"network"`
	InviteID        string      `json:"invite_id"`
	CreatedAt       time.Time   `json:"created_at"`
	ExpiresAt       time.Time   `json:"expires_at"`
	Issuer          NodeInfo    `json:"issuer"`
	AssignedAddress netip.Addr  `json:"assigned_address"`
}

// JoinRequest is created by the joining node and bound to one invite.
type JoinRequest struct {
	SchemaVersion int         `json:"schema_version"`
	Type          MessageType `json:"type"`
	Protocol      string      `json:"protocol"`
	NetworkID     string      `json:"network_id"`
	InviteID      string      `json:"invite_id"`
	InviteDigest  string      `json:"invite_digest"`
	RequestID     string      `json:"request_id"`
	CreatedAt     time.Time   `json:"created_at"`
	ExpiresAt     time.Time   `json:"expires_at"`
	Candidate     NodeInfo    `json:"candidate"`
}

// JoinAccept is created by the inviting node after explicit approval and is
// bound to exactly one request (and transitively one invite).
type JoinAccept struct {
	SchemaVersion int         `json:"schema_version"`
	Type          MessageType `json:"type"`
	Protocol      string      `json:"protocol"`
	Network       NetworkInfo `json:"network"`
	InviteID      string      `json:"invite_id"`
	InviteDigest  string      `json:"invite_digest"`
	RequestID     string      `json:"request_id"`
	RequestDigest string      `json:"request_digest"`
	CreatedAt     time.Time   `json:"created_at"`
	ExpiresAt     time.Time   `json:"expires_at"`
	Issuer        NodeInfo    `json:"issuer"`
	Member        NodeInfo    `json:"member"`
}

// SealInvite signs an invite.
func SealInvite(inv *Invite, priv ed25519.PrivateKey) (*Signed, error) {
	inv.SchemaVersion, inv.Type, inv.Protocol = SchemaVersion, TypeInvite, Protocol
	if err := checkSigner(priv, inv.Issuer.IdentityKey); err != nil {
		return nil, err
	}
	return seal(TypeInvite, inv, priv)
}

// SealJoinRequest signs a join request.
func SealJoinRequest(req *JoinRequest, priv ed25519.PrivateKey) (*Signed, error) {
	req.SchemaVersion, req.Type, req.Protocol = SchemaVersion, TypeJoinRequest, Protocol
	if err := checkSigner(priv, req.Candidate.IdentityKey); err != nil {
		return nil, err
	}
	return seal(TypeJoinRequest, req, priv)
}

// SealJoinAccept signs a join accept.
func SealJoinAccept(acc *JoinAccept, priv ed25519.PrivateKey) (*Signed, error) {
	acc.SchemaVersion, acc.Type, acc.Protocol = SchemaVersion, TypeJoinAccept, Protocol
	if err := checkSigner(priv, acc.Issuer.IdentityKey); err != nil {
		return nil, err
	}
	return seal(TypeJoinAccept, acc, priv)
}

func checkSigner(priv ed25519.PrivateKey, identity string) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || base64.StdEncoding.EncodeToString(pub) != identity {
		return errors.New("signing key does not match the identity in the message")
	}
	return nil
}

// ParseInvite authenticates (self-signature) and validates an invite file.
// The self-signature only proves integrity relative to the embedded key;
// trust comes from the administrator comparing the fingerprint.
func ParseInvite(data []byte, now time.Time) (*Invite, *Signed, error) {
	s, err := Open(data, TypeInvite)
	if err != nil {
		return nil, nil, err
	}
	var inv Invite
	if err := strictUnmarshal(s.Payload, &inv); err != nil {
		return nil, nil, invalidf("malformed invite: %v", err)
	}
	if err := checkHeader(inv.SchemaVersion, inv.Type, inv.Protocol, TypeInvite); err != nil {
		return nil, nil, err
	}
	if err := verifyWith(s, inv.Issuer.IdentityKey); err != nil {
		return nil, nil, err
	}
	if err := validateNetwork(inv.Network); err != nil {
		return nil, nil, err
	}
	if err := model.ValidateNetworkID(inv.InviteID); err != nil {
		return nil, nil, invalidf("invite_id: %v", err)
	}
	if err := validateNode("issuer", inv.Issuer, inv.Network.CIDR); err != nil {
		return nil, nil, err
	}
	if err := model.ValidateHostAddress(inv.Network.CIDR, inv.AssignedAddress); err != nil {
		return nil, nil, invalidf("assigned_address: %v", err)
	}
	if inv.AssignedAddress == inv.Issuer.Address {
		return nil, nil, invalidf("assigned_address equals the issuer address")
	}
	if err := checkValidity("invite", inv.CreatedAt, inv.ExpiresAt, MaxInviteTTL, now); err != nil {
		return nil, nil, err
	}
	return &inv, s, nil
}

// ParseJoinRequest authenticates (self-signature) and validates a request.
// Binding to an invite is checked by the caller against local state.
func ParseJoinRequest(data []byte, now time.Time) (*JoinRequest, *Signed, error) {
	s, err := Open(data, TypeJoinRequest)
	if err != nil {
		return nil, nil, err
	}
	var req JoinRequest
	if err := strictUnmarshal(s.Payload, &req); err != nil {
		return nil, nil, invalidf("malformed join request: %v", err)
	}
	if err := checkHeader(req.SchemaVersion, req.Type, req.Protocol, TypeJoinRequest); err != nil {
		return nil, nil, err
	}
	if err := verifyWith(s, req.Candidate.IdentityKey); err != nil {
		return nil, nil, err
	}
	for name, id := range map[string]string{"network_id": req.NetworkID, "invite_id": req.InviteID, "request_id": req.RequestID} {
		if err := model.ValidateNetworkID(id); err != nil {
			return nil, nil, invalidf("%s: %v", name, err)
		}
	}
	if err := validateDigest(req.InviteDigest); err != nil {
		return nil, nil, invalidf("invite_digest: %v", err)
	}
	if err := validateNode("candidate", req.Candidate, netip.Prefix{}); err != nil {
		return nil, nil, err
	}
	if err := checkValidity("join request", req.CreatedAt, req.ExpiresAt, MaxInviteTTL, now); err != nil {
		return nil, nil, err
	}
	return &req, s, nil
}

// ParseJoinAccept authenticates an accept with the issuer identity key that
// was pinned when the invite was verified, then validates it.
func ParseJoinAccept(data []byte, pinnedIssuerIdentity string, now time.Time) (*JoinAccept, *Signed, error) {
	s, err := Open(data, TypeJoinAccept)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyWith(s, pinnedIssuerIdentity); err != nil {
		return nil, nil, err
	}
	var acc JoinAccept
	if err := strictUnmarshal(s.Payload, &acc); err != nil {
		return nil, nil, invalidf("malformed join accept: %v", err)
	}
	if err := checkHeader(acc.SchemaVersion, acc.Type, acc.Protocol, TypeJoinAccept); err != nil {
		return nil, nil, err
	}
	if acc.Issuer.IdentityKey != pinnedIssuerIdentity {
		return nil, nil, invalidf("issuer identity differs from the invite")
	}
	if err := validateNetwork(acc.Network); err != nil {
		return nil, nil, err
	}
	for name, id := range map[string]string{"invite_id": acc.InviteID, "request_id": acc.RequestID} {
		if err := model.ValidateNetworkID(id); err != nil {
			return nil, nil, invalidf("%s: %v", name, err)
		}
	}
	for name, d := range map[string]string{"invite_digest": acc.InviteDigest, "request_digest": acc.RequestDigest} {
		if err := validateDigest(d); err != nil {
			return nil, nil, invalidf("%s: %v", name, err)
		}
	}
	if err := validateNode("issuer", acc.Issuer, acc.Network.CIDR); err != nil {
		return nil, nil, err
	}
	if err := validateNode("member", acc.Member, acc.Network.CIDR); err != nil {
		return nil, nil, err
	}
	if err := checkValidity("join accept", acc.CreatedAt, acc.ExpiresAt, AcceptTTL, now); err != nil {
		return nil, nil, err
	}
	return &acc, s, nil
}

func verifyWith(s *Signed, identity string) error {
	if err := model.ValidateIdentityKey(identity); err != nil {
		return invalidf("signer identity key: %v", err)
	}
	pub, _ := base64.StdEncoding.DecodeString(identity)
	return s.Verify(ed25519.PublicKey(pub))
}

func checkHeader(schema int, t MessageType, proto string, want MessageType) error {
	if schema != SchemaVersion {
		if schema > SchemaVersion {
			return invalidf("schema_version %d was created by a newer meshly; upgrade this node", schema)
		}
		return invalidf("unsupported schema_version %d", schema)
	}
	if t != want {
		return invalidf("payload type %q does not match envelope type %q", truncateStr(string(t)), want)
	}
	if proto != Protocol {
		return invalidf("unsupported protocol %q", truncateStr(proto))
	}
	return nil
}

func validateNetwork(n NetworkInfo) error {
	if err := model.ValidateNetworkID(n.ID); err != nil {
		return invalidf("network.id: %v", err)
	}
	if err := model.ValidateName(n.Name); err != nil {
		return invalidf("network.name: %v", err)
	}
	if err := model.ValidateCIDR(n.CIDR); err != nil {
		return invalidf("network.cidr: %v", err)
	}
	if err := model.ValidateMTU(n.MTU); err != nil {
		return invalidf("network.mtu: %v", err)
	}
	return nil
}

// validateNode checks node fields; cidr may be invalid when unknown.
func validateNode(role string, n NodeInfo, cidr netip.Prefix) error {
	if err := model.ValidateName(n.Name); err != nil {
		return invalidf("%s.name: %v", role, err)
	}
	if err := model.ValidateIdentityKey(n.IdentityKey); err != nil {
		return invalidf("%s.identity_key: %v", role, err)
	}
	if err := model.ValidateWGPublicKey(n.WGPublicKey); err != nil {
		return invalidf("%s.wg_public_key: %v", role, err)
	}
	if cidr.IsValid() {
		if err := model.ValidateHostAddress(cidr, n.Address); err != nil {
			return invalidf("%s.address: %v", role, err)
		}
	} else if !n.Address.IsValid() || !n.Address.Is4() {
		return invalidf("%s.address: missing or non-IPv4 address", role)
	}
	if n.Endpoint.IsValid() {
		if err := model.ValidateEndpoint(n.Endpoint); err != nil {
			return invalidf("%s.endpoint: %v", role, err)
		}
	}
	return nil
}

func validateDigest(d string) error {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		return errors.New("must be sha256:<64 hex>")
	}
	return nil
}

func checkValidity(what string, created, expires time.Time, maxTTL time.Duration, now time.Time) error {
	if created.IsZero() || expires.IsZero() {
		return invalidf("%s has no validity period", what)
	}
	if !expires.After(created) {
		return invalidf("%s expires before it was created", what)
	}
	if expires.Sub(created) > maxTTL {
		return invalidf("%s validity period exceeds %s", what, maxTTL)
	}
	if created.After(now.Add(ClockSkew)) {
		return invalidf("%s was created in the future (%s); check the clocks of both nodes", what, created.UTC().Format(time.RFC3339))
	}
	if !now.Before(expires) {
		return fmt.Errorf("%w: %s expired at %s", ErrExpired, what, expires.UTC().Format(time.RFC3339))
	}
	return nil
}

// ErrExpired is returned for messages outside their validity period.
var ErrExpired = errors.New("expired")

var fpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint derives the human-verifiable node fingerprint from the node's
// Ed25519 identity key and WireGuard public key: 160 bits of
// SHA-256("meshly-fingerprint/1" || 0 || identity || wg), base32, grouped.
func Fingerprint(identityKey, wgKey string) string {
	id, err1 := base64.StdEncoding.DecodeString(identityKey)
	wg, err2 := base64.StdEncoding.DecodeString(wgKey)
	if err1 != nil || err2 != nil {
		return "INVALID"
	}
	h := sha256.New()
	h.Write([]byte("meshly-fingerprint/1"))
	h.Write([]byte{0})
	h.Write(id)
	h.Write(wg)
	enc := fpEncoding.EncodeToString(h.Sum(nil)[:20])
	var groups []string
	for i := 0; i < len(enc); i += 4 {
		groups = append(groups, enc[i:i+4])
	}
	return strings.Join(groups, "-")
}

// NormalizeFingerprint makes user input comparable (case, separators).
func NormalizeFingerprint(s string) string {
	s = strings.ToUpper(s)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == ':' {
			return -1
		}
		return r
	}, s)
}

// FingerprintsEqual compares fingerprints ignoring formatting.
func FingerprintsEqual(a, b string) bool {
	na, nb := NormalizeFingerprint(a), NormalizeFingerprint(b)
	return len(na) == 32 && na == nb
}
