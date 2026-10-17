package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Keys are the node's long-term secrets. They are only loaded when needed
// and must never be logged or printed: every fmt verb, String, GoString and
// JSON encoding of Keys (value or pointer) is redacted.
type Keys struct {
	WG       wgtypes.Key
	Identity ed25519.PrivateKey
}

const redactedKeys = "[redacted keys]"

// String never reveals key material.
func (k Keys) String() string { return redactedKeys }

// GoString never reveals key material.
func (k Keys) GoString() string { return redactedKeys }

// Format redacts every verb, including %d and %x on the fields.
func (k Keys) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedKeys) }

// MarshalJSON never reveals key material.
func (k Keys) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedKeys + `"`), nil }

// WGPublic returns the base64 WireGuard public key.
func (k *Keys) WGPublic() string { return k.WG.PublicKey().String() }

// IdentityPublic returns the base64 Ed25519 public key.
func (k *Keys) IdentityPublic() string {
	return base64.StdEncoding.EncodeToString(k.Identity.Public().(ed25519.PublicKey))
}

// Wipe overwrites the in-memory key material (best effort: Go may have
// made copies that cannot be reached).
func (k *Keys) Wipe() {
	if k == nil {
		return
	}
	for i := range k.WG {
		k.WG[i] = 0
	}
	for i := range k.Identity {
		k.Identity[i] = 0
	}
}

// KeysExist reports whether both key files exist.
func (p Paths) KeysExist() bool {
	_, e1 := os.Lstat(p.WGKeyFile())
	_, e2 := os.Lstat(p.IdentityFile())
	return e1 == nil && e2 == nil
}

// LoadOrCreateKeys loads existing keys or generates new ones locally. If
// only one of the two key files exists it refuses: regenerating would
// silently replace a surviving key (and with it the node's identity).
func (p Paths) LoadOrCreateKeys() (*Keys, bool, error) {
	if p.KeysExist() {
		k, err := p.LoadKeys()
		return k, false, err
	}
	for _, f := range []string{p.WGKeyFile(), p.IdentityFile()} {
		if _, err := os.Lstat(f); err == nil {
			return nil, false, fmt.Errorf("key file %s exists but its counterpart is missing; restore it from a backup or remove this node's state with `meshly reset`", f)
		}
	}
	wg, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, false, fmt.Errorf("generate WireGuard key: %w", err)
	}
	_, id, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generate identity key: %w", err)
	}
	k := &Keys{WG: wg, Identity: id}
	if err := p.writeSecret(p.WGKeyFile(), base64.StdEncoding.EncodeToString(wg[:])); err != nil {
		return nil, false, err
	}
	if err := p.writeSecret(p.IdentityFile(), base64.StdEncoding.EncodeToString(id.Seed())); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

func (p Paths) writeSecret(path, b64 string) error {
	data := []byte(b64 + "\n")
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()
	return WriteAtomic(path, data, 0o600)
}

// LoadKeys reads both secrets, enforcing 0600 root-owned regular files.
func (p Paths) LoadKeys() (*Keys, error) {
	if err := CheckDir(p.KeysDir, 0o700, p.Owner); err != nil {
		return nil, err
	}
	wgRaw, err := p.readSecret(p.WGKeyFile(), 32)
	if err != nil {
		return nil, err
	}
	seed, err := p.readSecret(p.IdentityFile(), ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	k := &Keys{Identity: ed25519.NewKeyFromSeed(seed)}
	copy(k.WG[:], wgRaw)
	for i := range wgRaw {
		wgRaw[i] = 0
	}
	for i := range seed {
		seed[i] = 0
	}
	return k, nil
}

func (p Paths) readSecret(path string, size int) ([]byte, error) {
	b, err := ReadFile(path, 0o600, p.Owner, 256)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("key file %s is missing", path)
		}
		return nil, err
	}
	defer func() {
		for i := range b {
			b[i] = 0
		}
	}()
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != size {
		// Do not include the content in the error.
		return nil, fmt.Errorf("key file %s is corrupted", path)
	}
	return raw, nil
}

// RemoveKeys deletes the key files (reset).
func (p Paths) RemoveKeys() error {
	for _, f := range []string{p.WGKeyFile(), p.IdentityFile()} {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return SyncDir(p.KeysDir)
}
