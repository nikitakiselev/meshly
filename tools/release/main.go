// Command release manages the meshly release signing key and signs
// SHA256SUMS. It uses only crypto/ed25519 from the standard library.
//
//	go run ./tools/release keygen [-key FILE]           create a key, print the public key
//	go run ./tools/release pubkey [-key FILE]           print the public key of FILE
//	go run ./tools/release sign   [-key FILE] SUMS      write SUMS.sig
//	go run ./tools/release verify -pub BASE64 SUMS      check SUMS.sig
//
// The private key file holds the base64 Ed25519 seed and must be mode 0600.
// It never belongs in the repository. The default location is
// $MESHLY_RELEASE_KEY or ~/.config/meshly-release/release.key.
//
// The signature covers "meshly-release/1" || 0x00 || SHA256SUMS, the same
// message internal/upgrade and scripts/install.sh verify.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nikitakiselev/meshly/internal/upgrade"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func defaultKeyPath() string {
	if p := os.Getenv("MESHLY_RELEASE_KEY"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "meshly-release", "release.key")
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: release keygen|pubkey|sign|verify [flags]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	keyPath := fs.String("key", defaultKeyPath(), "private key file")
	pub := fs.String("pub", "", "base64 public key (verify)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		return keygen(*keyPath)
	case "pubkey":
		priv, err := loadKey(*keyPath)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
		return nil
	case "sign":
		if fs.NArg() != 1 {
			return errors.New("usage: release sign [-key FILE] SHA256SUMS")
		}
		return sign(*keyPath, fs.Arg(0))
	case "verify":
		if fs.NArg() != 1 || *pub == "" {
			return errors.New("usage: release verify -pub BASE64 SHA256SUMS")
		}
		key, err := upgrade.ParseKey(*pub)
		if err != nil {
			return err
		}
		sums, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(fs.Arg(0) + ".sig")
		if err != nil {
			return err
		}
		if err := upgrade.VerifySums(key, sums, sig); err != nil {
			return err
		}
		fmt.Println("signature OK")
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func keygen(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a release key", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "private key written to %s (keep it offline and backed up)\n", path)
	fmt.Println(base64.StdEncoding.EncodeToString(pubKey))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by other users (mode %v); chmod 600 it", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a meshly release key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func sign(keyPath, sumsPath string) error {
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, upgrade.SignedMessage(sums))
	// Self-check with the same code path the upgrade uses.
	if err := upgrade.VerifySums(priv.Public().(ed25519.PublicKey), sums, []byte(base64.StdEncoding.EncodeToString(sig))); err != nil {
		return err
	}
	return os.WriteFile(sumsPath+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}
