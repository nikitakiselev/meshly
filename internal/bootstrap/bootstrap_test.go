package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type node struct {
	priv ed25519.PrivateKey
	info NodeInfo
}

func newNode(t testing.TB, name, addr string) node {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wg := make([]byte, 32)
	_, _ = rand.Read(wg)
	return node{priv: priv, info: NodeInfo{
		Name: name, IdentityKey: base64.StdEncoding.EncodeToString(pub),
		WGPublicKey: base64.StdEncoding.EncodeToString(wg), Address: netip.MustParseAddr(addr),
	}}
}

var testNet = NetworkInfo{ID: strings.Repeat("ab", 16), Name: "homelab", CIDR: netip.MustParsePrefix("10.100.0.0/24"), MTU: 1420}

func makeInvite(t testing.TB, issuer node) *Signed {
	t.Helper()
	is := issuer.info
	is.Endpoint = netip.MustParseAddrPort("203.0.113.10:51820")
	s, err := SealInvite(&Invite{
		Network: testNet, InviteID: strings.Repeat("01", 16), CreatedAt: t0, ExpiresAt: t0.Add(time.Hour),
		Issuer: is, AssignedAddress: netip.MustParseAddr("10.100.0.2"),
	}, issuer.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func makeRequest(t testing.TB, cand node, inv *Signed) *Signed {
	t.Helper()
	s, err := SealJoinRequest(&JoinRequest{
		NetworkID: testNet.ID, InviteID: strings.Repeat("01", 16), InviteDigest: inv.Digest(),
		RequestID: strings.Repeat("02", 16), CreatedAt: t0.Add(time.Minute), ExpiresAt: t0.Add(time.Hour), Candidate: cand.info,
	}, cand.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func makeAccept(t testing.TB, issuer, member node, inv, req *Signed) *Signed {
	t.Helper()
	s, err := SealJoinAccept(&JoinAccept{
		Network: testNet, InviteID: strings.Repeat("01", 16), InviteDigest: inv.Digest(),
		RequestID: strings.Repeat("02", 16), RequestDigest: req.Digest(), CreatedAt: t0.Add(2 * time.Minute),
		ExpiresAt: t0.Add(2*time.Minute + AcceptTTL), Issuer: issuer.info, Member: member.info,
	}, issuer.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// rewrite decodes an envelope, lets f change it and re-encodes it without
// re-signing.
func rewrite(t testing.TB, raw []byte, f func(env map[string]any, payload map[string]any)) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(env["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(pb, &payload); err != nil {
		t.Fatal(err)
	}
	f(env, payload)
	pb, _ = json.Marshal(payload)
	env["payload"] = base64.RawURLEncoding.EncodeToString(pb)
	out, _ := json.Marshal(env)
	return out
}

func TestRoundTrip(t *testing.T) {
	vps, home := newNode(t, "vps", "10.100.0.1"), newNode(t, "home", "10.100.0.2")
	inv := makeInvite(t, vps)
	got, s, err := ParseInvite(inv.Raw, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer.Name != "vps" || s.Digest() != inv.Digest() || got.AssignedAddress.String() != "10.100.0.2" {
		t.Fatalf("invite content: %+v", got)
	}
	req := makeRequest(t, home, inv)
	r, _, err := ParseJoinRequest(req.Raw, t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if r.InviteDigest != inv.Digest() {
		t.Fatal("request not bound to the invite digest")
	}
	acc := makeAccept(t, vps, home, inv, req)
	a, _, err := ParseJoinAccept(acc.Raw, vps.info.IdentityKey, t0.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if a.RequestDigest != req.Digest() || a.Member.WGPublicKey != home.info.WGPublicKey {
		t.Fatal("accept binding lost")
	}
}

func TestTamperingDetected(t *testing.T) {
	vps := newNode(t, "vps", "10.100.0.1")
	inv := makeInvite(t, vps)
	now := t0.Add(time.Minute)
	attacker := newNode(t, "evil", "10.100.0.1")
	cases := map[string][]byte{
		"assigned address": rewrite(t, inv.Raw, func(_, p map[string]any) { p["assigned_address"] = "10.100.0.3" }),
		"endpoint": rewrite(t, inv.Raw, func(_, p map[string]any) {
			p["issuer"].(map[string]any)["endpoint"] = "198.51.100.66:51820"
		}),
		"wg key": rewrite(t, inv.Raw, func(_, p map[string]any) {
			p["issuer"].(map[string]any)["wg_public_key"] = attacker.info.WGPublicKey
		}),
		// Replacing the identity key without the matching private key.
		"identity key": rewrite(t, inv.Raw, func(_, p map[string]any) {
			p["issuer"].(map[string]any)["identity_key"] = attacker.info.IdentityKey
		}),
		"expiry": rewrite(t, inv.Raw, func(_, p map[string]any) { p["expires_at"] = "2027-01-01T00:00:00Z" }),
		"type":   rewrite(t, inv.Raw, func(e, _ map[string]any) { e["type"] = "join-accept" }),
		"signature": rewrite(t, inv.Raw, func(e, _ map[string]any) {
			e["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseInvite(raw, now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("tampered invite accepted or wrong error: %v", err)
			}
		})
	}
}

func TestSignatureDomainSeparation(t *testing.T) {
	// A valid signature over an invite payload must not verify as a
	// join-accept with the same payload bytes.
	vps := newNode(t, "vps", "10.100.0.1")
	inv := makeInvite(t, vps)
	pub, _ := base64.StdEncoding.DecodeString(vps.info.IdentityKey)
	s := &Signed{Type: TypeJoinAccept, Payload: inv.Payload, Signature: inv.Signature}
	if err := s.Verify(ed25519.PublicKey(pub)); err == nil {
		t.Fatal("signature verifies for another message type")
	}
}

func TestStrictJSON(t *testing.T) {
	vps := newNode(t, "vps", "10.100.0.1")
	inv := makeInvite(t, vps)
	now := t0.Add(time.Minute)
	var env map[string]any
	_ = json.Unmarshal(inv.Raw, &env)
	sig, payload := env["signature"].(string), env["payload"].(string)
	cases := map[string]string{
		"duplicate key":   `{"format":"meshly-bootstrap","format":"meshly-bootstrap","version":1,"type":"invite","payload":"` + payload + `","signature":"` + sig + `"}`,
		"case alias":      `{"format":"meshly-bootstrap","version":1,"type":"invite","payload":"` + payload + `","signature":"` + sig + `","PAYLOAD":"x"}`,
		"unknown field":   `{"format":"meshly-bootstrap","version":1,"type":"invite","payload":"` + payload + `","signature":"` + sig + `","extra":1}`,
		"trailing data":   `{"format":"meshly-bootstrap","version":1,"type":"invite","payload":"` + payload + `","signature":"` + sig + `"} {}`,
		"array top level": `[1,2,3]`,
		"newer version":   `{"format":"meshly-bootstrap","version":2,"type":"invite","payload":"` + payload + `","signature":"` + sig + `"}`,
		"wrong format":    `{"format":"other","version":1,"type":"invite","payload":"` + payload + `","signature":"` + sig + `"}`,
		"padded base64":   `{"format":"meshly-bootstrap","version":1,"type":"invite","payload":"` + payload + `==","signature":"` + sig + `"}`,
		"deep nesting":    `{"format":"meshly-bootstrap","version":1,"type":"invite","payload":"","signature":"","x":` + strings.Repeat("[", 20) + strings.Repeat("]", 20) + `}`,
		"too large":       `{"format":"` + strings.Repeat("a", MaxFileSize) + `"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseInvite([]byte(raw), now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted or wrong error: %v", err)
			}
		})
	}
	// The same checks apply to the signed payload: a duplicated key inside
	// a correctly signed payload is rejected.
	dupPayload := []byte(`{"schema_version":1,"schema_version":1}`)
	s := &Signed{Type: TypeInvite, Payload: dupPayload}
	if err := strictUnmarshal(s.Payload, &Invite{}); err == nil {
		t.Fatal("duplicate key in payload accepted")
	}
}

func TestValidityPeriod(t *testing.T) {
	vps := newNode(t, "vps", "10.100.0.1")
	inv := makeInvite(t, vps)
	for _, c := range []struct {
		name    string
		now     time.Time
		wantErr error
	}{
		{"valid", t0.Add(30 * time.Minute), nil},
		{"small clock skew", t0.Add(-4 * time.Minute), nil},
		{"created in the future", t0.Add(-6 * time.Minute), ErrInvalid},
		{"expired", t0.Add(time.Hour), ErrExpired},
		{"long expired", t0.Add(48 * time.Hour), ErrExpired},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := ParseInvite(inv.Raw, c.now)
			if c.wantErr == nil && err != nil || c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("got %v, want %v", err, c.wantErr)
			}
		})
	}
	// A validity period longer than the maximum is refused even if signed.
	is := vps.info
	is.Endpoint = netip.MustParseAddrPort("203.0.113.10:51820")
	long, err := SealInvite(&Invite{Network: testNet, InviteID: strings.Repeat("01", 16), CreatedAt: t0,
		ExpiresAt: t0.Add(MaxInviteTTL + time.Second), Issuer: is, AssignedAddress: netip.MustParseAddr("10.100.0.2")}, vps.priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseInvite(long.Raw, t0.Add(time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overlong validity accepted: %v", err)
	}
}

func TestAcceptPinnedToInviter(t *testing.T) {
	vps, home := newNode(t, "vps", "10.100.0.1"), newNode(t, "home", "10.100.0.2")
	inv := makeInvite(t, vps)
	req := makeRequest(t, home, inv)
	// An attacker who saw the request cannot produce an accept: signed with
	// another key, or claiming the inviter's identity.
	evil := newNode(t, "vps", "10.100.0.1")
	forged := makeAccept(t, evil, home, inv, req)
	now := t0.Add(3 * time.Minute)
	if _, _, err := ParseJoinAccept(forged.Raw, vps.info.IdentityKey, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accept from another key accepted: %v", err)
	}
	acc := makeAccept(t, vps, home, inv, req)
	if _, _, err := ParseJoinAccept(acc.Raw, evil.info.IdentityKey, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accept verified against the wrong pinned key: %v", err)
	}
}

func TestSealRefusesForeignSigner(t *testing.T) {
	vps, other := newNode(t, "vps", "10.100.0.1"), newNode(t, "x", "10.100.0.1")
	is := vps.info
	if _, err := SealInvite(&Invite{Network: testNet, Issuer: is}, other.priv); err == nil {
		t.Fatal("sealed with a key that is not the issuer identity")
	}
}

func TestRequestSelfSigned(t *testing.T) {
	vps, home, evil := newNode(t, "vps", "10.100.0.1"), newNode(t, "home", "10.100.0.2"), newNode(t, "evil", "10.100.0.2")
	req := makeRequest(t, home, makeInvite(t, vps))
	// Swap the candidate's keys for the attacker's without re-signing.
	raw := rewrite(t, req.Raw, func(_, p map[string]any) {
		c := p["candidate"].(map[string]any)
		c["wg_public_key"] = evil.info.WGPublicKey
	})
	if _, _, err := ParseJoinRequest(raw, t0.Add(2*time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("request with swapped key accepted: %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	n := newNode(t, "vps", "10.100.0.1")
	fp := n.info.Fingerprint()
	if len(fp) != 39 || strings.Count(fp, "-") != 7 {
		t.Fatalf("format: %q", fp)
	}
	if fp != Fingerprint(n.info.IdentityKey, n.info.WGPublicKey) {
		t.Fatal("not deterministic")
	}
	if !FingerprintsEqual(fp, strings.ToLower(strings.ReplaceAll(fp, "-", " "))) {
		t.Fatal("formatting differences are not ignored")
	}
	other := newNode(t, "vps", "10.100.0.1")
	if FingerprintsEqual(fp, other.info.Fingerprint()) {
		t.Fatal("different nodes share a fingerprint")
	}
	// Both keys are covered: changing only the WireGuard key changes it.
	if Fingerprint(n.info.IdentityKey, other.info.WGPublicKey) == fp {
		t.Fatal("fingerprint does not cover the WireGuard key")
	}
	if FingerprintsEqual("", "") || FingerprintsEqual("ABCD", "ABCD") {
		t.Fatal("short or empty fingerprints compare equal")
	}
}

func FuzzOpen(f *testing.F) {
	vps := newNode(f, "vps", "10.100.0.1")
	inv := makeInvite(f, vps)
	f.Add(inv.Raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"format":"meshly-bootstrap","version":1,"type":"invite","payload":"e30","signature":""}`))
	f.Add([]byte(`{"a":{"b":[1,{"c":null}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, typ := range []MessageType{TypeInvite, TypeJoinRequest, TypeJoinAccept} {
			s, err := Open(data, typ)
			if err != nil {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("error not wrapped in ErrInvalid: %v", err)
				}
				continue
			}
			if s.Type != typ || len(s.Signature) != ed25519.SignatureSize {
				t.Fatalf("Open accepted inconsistent envelope: %+v", s)
			}
		}
		// The full parsers must never panic and only accept authentic data.
		if inv, _, err := ParseInvite(data, t0.Add(time.Minute)); err == nil {
			if inv.Issuer.IdentityKey != vps.info.IdentityKey && string(data) != string(inv.Issuer.IdentityKey) {
				// Any accepted invite must carry a valid self-signature;
				// re-verify explicitly.
				s, _ := Open(data, TypeInvite)
				if verifyWith(s, inv.Issuer.IdentityKey) != nil {
					t.Fatal("accepted invite without a valid signature")
				}
			}
		}
		_, _, _ = ParseJoinRequest(data, t0)
		_, _, _ = ParseJoinAccept(data, vps.info.IdentityKey, t0)
	})
}
