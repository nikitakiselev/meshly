// Package bootstrap implements the Meshly trust bootstrap protocol: signed,
// strictly validated invite / join-request / join-accept files exchanged by
// administrators over an existing trusted channel (for example SSH/SCP).
//
// Wire format: a small JSON envelope carrying the exact payload bytes in
// base64url and an Ed25519 signature over
//
//	"meshly-bootstrap/1" || 0x00 || type || 0x00 || payload
//
// Signing the exact bytes (instead of a re-serialised object) gives one
// unambiguous signed representation without a JSON canonicalisation scheme.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// Protocol identifies the bootstrap protocol and its version.
	Protocol = "meshly-bootstrap/1"
	// EnvelopeFormat is the value of the envelope "format" field.
	EnvelopeFormat = "meshly-bootstrap"
	// EnvelopeVersion is the only supported envelope version.
	EnvelopeVersion = 1
	// SchemaVersion is the only supported payload schema version.
	SchemaVersion = 1
	// MaxFileSize bounds every bootstrap file read from disk.
	MaxFileSize = 64 << 10
	// maxJSONDepth bounds nesting of decoded JSON.
	maxJSONDepth = 8
)

// MessageType is the kind of a bootstrap message.
type MessageType string

const (
	TypeInvite      MessageType = "invite"
	TypeJoinRequest MessageType = "join-request"
	TypeJoinAccept  MessageType = "join-accept"
)

// ErrInvalid wraps every validation failure of an untrusted file.
var ErrInvalid = errors.New("invalid bootstrap file")

func invalidf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

type envelope struct {
	Format    string      `json:"format"`
	Version   int         `json:"version"`
	Type      MessageType `json:"type"`
	Payload   string      `json:"payload"`
	Signature string      `json:"signature"`
}

// Signed is a decoded, not yet authenticated envelope.
type Signed struct {
	Type      MessageType
	Payload   []byte
	Signature []byte
	// Raw are the exact envelope bytes.
	Raw []byte
}

func signedMessage(t MessageType, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString(Protocol)
	b.WriteByte(0)
	b.WriteString(string(t))
	b.WriteByte(0)
	b.Write(payload)
	return b.Bytes()
}

// Digest identifies a message: SHA-256 over the signed bytes.
func (s *Signed) Digest() string { return digestOf(s.Type, s.Payload) }

func digestOf(t MessageType, payload []byte) string {
	sum := sha256.Sum256(signedMessage(t, payload))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Verify checks the signature with the given Ed25519 public key.
func (s *Signed) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return invalidf("bad signer key")
	}
	if !ed25519.Verify(pub, signedMessage(s.Type, s.Payload), s.Signature) {
		return invalidf("signature verification failed: the file was modified or not created by the claimed node")
	}
	return nil
}

// seal marshals payload, signs it and returns the envelope bytes.
func seal(t MessageType, payload any, priv ed25519.PrivateKey) (*Signed, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(pb) > MaxFileSize/2 {
		return nil, errors.New("payload too large")
	}
	sig := ed25519.Sign(priv, signedMessage(t, pb))
	env := envelope{
		Format:    EnvelopeFormat,
		Version:   EnvelopeVersion,
		Type:      t,
		Payload:   base64.RawURLEncoding.EncodeToString(pb),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	return &Signed{Type: t, Payload: pb, Signature: sig, Raw: raw}, nil
}

// Open parses an envelope of the expected type without authenticating it.
func Open(data []byte, want MessageType) (*Signed, error) {
	if len(data) > MaxFileSize {
		return nil, invalidf("file is larger than %d bytes", MaxFileSize)
	}
	var env envelope
	if err := strictUnmarshal(data, &env); err != nil {
		return nil, invalidf("malformed envelope: %v", err)
	}
	if env.Format != EnvelopeFormat {
		return nil, invalidf("not a meshly bootstrap file")
	}
	if env.Version != EnvelopeVersion {
		if env.Version > EnvelopeVersion {
			return nil, invalidf("envelope version %d was created by a newer meshly; upgrade this node", env.Version)
		}
		return nil, invalidf("unsupported envelope version %d", env.Version)
	}
	if env.Type != want {
		return nil, invalidf("expected a %s file, got %q", want, truncateStr(string(env.Type)))
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return nil, invalidf("payload is not valid base64url")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, invalidf("signature is not a base64 Ed25519 signature")
	}
	return &Signed{Type: env.Type, Payload: payload, Signature: sig, Raw: bytes.Clone(data)}, nil
}

// strictUnmarshal decodes exactly one JSON object into v: unknown fields,
// duplicate keys, excessive nesting and trailing data are rejected so that
// two parsers can never disagree about the content.
func strictUnmarshal(data []byte, v any) error {
	if err := checkJSON(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// checkJSON validates structure: a single top-level object, no duplicate
// keys at any level, bounded depth, no trailing data.
func checkJSON(data []byte) error {
	type frame struct {
		obj       bool
		keys      map[string]struct{}
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("top-level value must be an object")
	}
	stack := []*frame{{obj: true, keys: map[string]struct{}{}, expectKey: true}}
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].expectKey = true
		}
	}
	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON: %v", err)
		}
		top := stack[len(stack)-1]
		if top.obj && top.expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				valueDone()
				continue
			}
			k, ok := tok.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			// encoding/json matches field names case-insensitively, so
			// "INVITE_ID" would silently alias "invite_id": only canonical
			// keys are accepted.
			if !canonicalKey(k) {
				return fmt.Errorf("non-canonical key %q", truncateStr(k))
			}
			if _, dup := top.keys[k]; dup {
				return fmt.Errorf("duplicate key %q", truncateStr(k))
			}
			top.keys[k] = struct{}{}
			top.expectKey = false
			continue
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return errors.New("JSON nesting too deep")
				}
				f := &frame{obj: d == '{', expectKey: d == '{'}
				if f.obj {
					f.keys = map[string]struct{}{}
				}
				stack = append(stack, f)
			case ']', '}':
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		valueDone()
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON object")
	}
	return nil
}

func canonicalKey(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func truncateStr(s string) string {
	if r := []rune(s); len(r) > 64 {
		return string(r[:64]) + "…"
	}
	return s
}
