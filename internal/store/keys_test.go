package store

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/nikitakiselev/meshly/internal/model"
)

func TestLoadOrCreateKeys(t *testing.T) {
	p := newPaths(t)
	if p.KeysExist() {
		t.Fatal("keys exist in a fresh root")
	}
	k, created, err := p.LoadOrCreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("created = false for new keys")
	}
	if !p.KeysExist() {
		t.Error("KeysExist = false after creation")
	}
	if m := permOf(t, p.KeysDir); m != 0o700 {
		t.Errorf("keys dir mode %04o, want 0700", m)
	}
	if m := permOf(t, p.WGKeyFile()); m != 0o600 {
		t.Errorf("%s mode %04o, want 0600", p.WGKeyFile(), m)
	}
	if got, want := readString(t, p.WGKeyFile()), base64.StdEncoding.EncodeToString(k.WG[:])+"\n"; got != want {
		t.Error("wireguard.key does not hold the generated key")
	}
	if err := model.ValidateWGPublicKey(k.WGPublic()); err != nil {
		t.Errorf("WGPublic: %v", err)
	}
	if k.WGPublic() == base64.StdEncoding.EncodeToString(k.WG[:]) {
		t.Error("WGPublic returns the private key")
	}

	k2, created, err := p.LoadOrCreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("created = true for existing keys")
	}
	if k2.WGPublic() != k.WGPublic() {
		t.Error("reloaded keys differ")
	}
	if k2.WG != k.WG {
		t.Error("reloaded private keys differ")
	}
}

func TestLoadKeysRefusesInsecure(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, p Paths)
	}{
		{"group-readable wireguard key", func(t *testing.T, p Paths) { must(t, os.Chmod(p.WGKeyFile(), 0o640)) }},
		{"open keys dir", func(t *testing.T, p Paths) { must(t, os.Chmod(p.KeysDir, 0o755)) }},
		{"symlinked key", func(t *testing.T, p Paths) {
			real := p.WGKeyFile() + ".real"
			must(t, os.Rename(p.WGKeyFile(), real))
			must(t, os.Symlink(real, p.WGKeyFile()))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPaths(t)
			if _, _, err := p.LoadOrCreateKeys(); err != nil {
				t.Fatal(err)
			}
			tt.setup(t, p)
			if _, err := p.LoadKeys(); !errors.Is(err, ErrInsecure) {
				t.Errorf("LoadKeys = %v, want ErrInsecure", err)
			}
		})
	}
}

func TestLoadKeysCorrupted(t *testing.T) {
	tests := []struct {
		name, content, want string
	}{
		{"not base64", "SECRET-GARBAGE!!\n", "corrupted"},
		{"short", base64.StdEncoding.EncodeToString([]byte("SECRET-short")) + "\n", "corrupted"},
		{"too long", strings.Repeat("A", 300), "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPaths(t)
			if _, _, err := p.LoadOrCreateKeys(); err != nil {
				t.Fatal(err)
			}
			writeFile(t, p.WGKeyFile(), tt.content, 0o600)
			_, err := p.LoadKeys()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadKeys = %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), strings.TrimSpace(tt.content)) {
				t.Errorf("error echoes key file content: %v", err)
			}
		})
	}

	p := newPaths(t)
	if _, _, err := p.LoadOrCreateKeys(); err != nil {
		t.Fatal(err)
	}
	must(t, os.Remove(p.WGKeyFile()))
	if _, err := p.LoadKeys(); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("LoadKeys with a missing key file = %v", err)
	}
	if p.KeysExist() {
		t.Error("KeysExist with the key file missing")
	}
}

func TestRemoveKeys(t *testing.T) {
	p := newPaths(t)
	if _, _, err := p.LoadOrCreateKeys(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := p.RemoveKeys(); err != nil {
			t.Fatalf("RemoveKeys #%d: %v", i, err)
		}
	}
	if p.KeysExist() {
		t.Error("keys still exist")
	}
	if names := dirNames(t, p.KeysDir); len(names) != 0 {
		t.Errorf("keys dir not empty: %v", names)
	}
}

func TestKeysWipe(t *testing.T) {
	var nilKeys *Keys
	nilKeys.Wipe() // must not panic

	p := newPaths(t)
	k, _, err := p.LoadOrCreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	k.Wipe()
	for _, b := range k.WG {
		if b != 0 {
			t.Fatal("WireGuard key not wiped")
		}
	}
}

// secretForms returns encodings of k's private material that must never
// appear in any rendering of the Keys value.
func secretForms(k *Keys) []string {
	var out []string
	for _, raw := range [][]byte{k.WG[:]} {
		for _, s := range []string{
			base64.StdEncoding.EncodeToString(raw),
			base64.RawURLEncoding.EncodeToString(raw),
			hex.EncodeToString(raw),
			string(raw[:16]),                                                      // raw bytes (%s of a []byte)
			strings.Trim(fmt.Sprint(raw[:8]), "[]"),                               // decimal bytes (%v)
			fmt.Sprintf("0x%x, 0x%x, 0x%x, 0x%x", raw[0], raw[1], raw[2], raw[3]), // %#v
		} {
			out = append(out, s[:min(len(s), 20)])
		}
	}
	return out
}

func TestKeysNeverPrinted(t *testing.T) {
	p := newPaths(t)
	k, _, err := p.LoadOrCreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	jsonOf := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			return "json error: " + err.Error()
		}
		return string(b)
	}
	tests := []struct {
		name string
		out  string
		// known marks renderings that currently leak (see report).
		known bool
	}{
		{name: "%v", out: fmt.Sprintf("%v", k)},
		{name: "%+v", out: fmt.Sprintf("%+v", k)},
		{name: "%#v", out: fmt.Sprintf("%#v", k)},
		{name: "%s", out: fmt.Sprintf("%s", k)},
		{name: "%q", out: fmt.Sprintf("%q", k)},
		{name: "%x", out: fmt.Sprintf("%x", k)},
		{name: "Sprint", out: fmt.Sprint(k)},
		{name: "Sprintln", out: fmt.Sprintln("keys:", k)},
		{name: "error wrap", out: fmt.Errorf("load %v: %w", k, errors.New("x")).Error()},
		{name: "struct field %+v", out: fmt.Sprintf("%+v", struct{ K *Keys }{k})},
		{name: "struct field %#v", out: fmt.Sprintf("%#v", struct{ K *Keys }{k})},
		{name: "slice %v", out: fmt.Sprintf("%v", []*Keys{k})},
		{name: "map %v", out: fmt.Sprintf("%v", map[string]*Keys{"k": k})},
		{name: "json.Marshal pointer", out: jsonOf(k)},
		{name: "json.Marshal in struct", out: jsonOf(struct{ K *Keys }{k})},
		{name: "json.Marshal value", out: jsonOf(*k)},
		{name: "value %v", out: fmt.Sprintf("%v", *k)},
		{name: "value %+v", out: fmt.Sprintf("%+v", *k)},
		{name: "value %#v", out: fmt.Sprintf("%#v", *k)},
		{name: "value %s", out: fmt.Sprintf("%s", *k)},
	}
	secrets := secretForms(k)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, s := range secrets {
				if strings.Contains(tt.out, s) {
					if tt.known {
						knownBug(t, "rendering %s reveals private key material (matched an encoding of the key)", tt.name)
					}
					t.Fatalf("rendering %s reveals private key material (matched an encoding of the key)", tt.name)
				}
			}
			if tt.known {
				t.Logf("%s no longer leaks; drop the known flag", tt.name)
			}
		})
	}
	if s := k.String(); s != "[redacted keys]" || k.GoString() != s {
		t.Errorf("String/GoString = %q / %q", s, k.GoString())
	}
}
