package store

import (
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
	WG wgtypes.Key
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

// Wipe overwrites the in-memory key material (best effort: Go may have
// made copies that cannot be reached).
func (k *Keys) Wipe() {
	if k == nil {
		return
	}
	for i := range k.WG {
		k.WG[i] = 0
	}
}

// KeysExist reports whether the WireGuard key file exists.
func (p Paths) KeysExist() bool {
	_, err := os.Lstat(p.WGKeyFile())
	return err == nil
}

// LoadOrCreateKeys loads the existing WireGuard key or generates a new one
// locally. The bool reports whether the key was created.
func (p Paths) LoadOrCreateKeys() (*Keys, bool, error) {
	if p.KeysExist() {
		k, err := p.LoadKeys()
		return k, false, err
	}
	wg, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, false, fmt.Errorf("generate WireGuard key: %w", err)
	}
	k := &Keys{WG: wg}
	if err := p.writeSecret(p.WGKeyFile(), base64.StdEncoding.EncodeToString(wg[:])); err != nil {
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

// LoadKeys reads the secret, enforcing a 0600 root-owned regular file.
func (p Paths) LoadKeys() (*Keys, error) {
	if err := CheckDir(p.KeysDir, 0o700, p.Owner); err != nil {
		return nil, err
	}
	wgRaw, err := p.readSecret(p.WGKeyFile(), 32)
	if err != nil {
		return nil, err
	}
	k := &Keys{}
	copy(k.WG[:], wgRaw)
	for i := range wgRaw {
		wgRaw[i] = 0
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

// RemoveKeys deletes the key file (reset).
func (p Paths) RemoveKeys() error {
	if err := os.Remove(p.WGKeyFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return SyncDir(p.KeysDir)
}
