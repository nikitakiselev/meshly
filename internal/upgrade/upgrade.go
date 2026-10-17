// Package upgrade implements `meshly upgrade`: it downloads a release from
// GitHub, verifies an Ed25519 signature over SHA256SUMS with the release
// public key compiled into this binary, verifies the SHA-256 of the binary,
// and atomically replaces the running executable (keeping <exe>.prev).
//
// Release assets (built and signed by scripts/release.sh; the private key
// never leaves the release machine):
//
//	SHA256SUMS                 "<sha256>  meshly-<version>-linux-<arch>" lines
//	SHA256SUMS.sig             base64 Ed25519 signature over
//	                           "meshly-release/1" || 0x00 || SHA256SUMS
//	meshly-<version>-linux-<arch>
//
// The version is taken only from the signed SHA256SUMS, and downgrades are
// refused unless forced, so an attacker cannot replay an older signed
// release.
package upgrade

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases are downloaded from.
const Repo = "nikitakiselev/meshly"

// ReleaseKey is the base64 Ed25519 public key that signs releases. It is
// injected at build time:
//
//	-ldflags "-X github.com/nikitakiselev/meshly/internal/upgrade.ReleaseKey=<base64>"
//
// Builds without a key refuse to upgrade.
var ReleaseKey = ""

// SignatureDomain separates release signatures from any other use of the key.
const SignatureDomain = "meshly-release/1"

const (
	maxSumsSize   = 64 << 10
	maxBinarySize = 256 << 20
)

// ErrVerify is returned when a downloaded artifact fails verification.
var ErrVerify = errors.New("release verification failed")

// Release is a verified release description.
type Release struct {
	Version string
	Asset   string
	SHA256  string
	URL     string
}

// Client downloads releases.
type Client struct {
	HTTP *http.Client
	// BaseURL is "https://github.com/<repo>/releases"; overridable for tests.
	BaseURL string
	Arch    string
	Key     string
}

// NewClient returns a client for the configured repository.
func NewClient(arch string) *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 5 * time.Minute},
		BaseURL: "https://github.com/" + Repo + "/releases",
		Arch:    arch,
		Key:     ReleaseKey,
	}
}

func (c *Client) get(ctx context.Context, url string, max int64) ([]byte, error) {
	if !allowedURL(url) {
		return nil, fmt.Errorf("refusing non-HTTPS URL %s", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "meshly-upgrade")
	hc := *c.HTTP
	hc.CheckRedirect = checkRedirect
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, max)
	}
	return b, nil
}

// allowedURL accepts HTTPS, and plain HTTP only to the loopback host (for
// tests and local mirrors).
func allowedURL(raw string) bool {
	u, err := neturl.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || !strings.HasPrefix(raw, u.Scheme+"://") {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// checkRedirect applies the URL policy to redirects (GitHub redirects
// release downloads to its HTTPS object storage).
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	if !allowedURL(req.URL.String()) {
		return fmt.Errorf("refusing redirect to non-HTTPS URL %s", req.URL.Redacted())
	}
	return nil
}

// Resolve fetches and verifies the release description. version "" means
// the latest release.
func (c *Client) Resolve(ctx context.Context, version string) (*Release, error) {
	pub, err := ParseKey(c.Key)
	if err != nil {
		return nil, err
	}
	dir := c.BaseURL + "/latest/download"
	if version != "" {
		if !semverRe.MatchString(version) {
			return nil, fmt.Errorf("invalid version %q", version)
		}
		dir = c.BaseURL + "/download/v" + version
	}
	sums, err := c.get(ctx, dir+"/SHA256SUMS", maxSumsSize)
	if err != nil {
		return nil, err
	}
	sig, err := c.get(ctx, dir+"/SHA256SUMS.sig", 1024)
	if err != nil {
		return nil, err
	}
	if err := VerifySums(pub, sums, sig); err != nil {
		return nil, err
	}
	rel, err := FindAsset(sums, c.Arch)
	if err != nil {
		return nil, err
	}
	if version != "" && rel.Version != version {
		return nil, fmt.Errorf("%w: SHA256SUMS describes version %s, expected %s", ErrVerify, rel.Version, version)
	}
	rel.URL = c.BaseURL + "/download/v" + rel.Version + "/" + rel.Asset
	return rel, nil
}

// Download fetches the binary and checks its hash.
func (c *Client) Download(ctx context.Context, rel *Release) ([]byte, error) {
	b, err := c.get(ctx, rel.URL, maxBinarySize)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != rel.SHA256 {
		return nil, fmt.Errorf("%w: SHA-256 of %s does not match the signed SHA256SUMS", ErrVerify, rel.Asset)
	}
	return b, nil
}

// ParseKey decodes the compiled-in release key.
func ParseKey(s string) (ed25519.PublicKey, error) {
	if s == "" {
		return nil, errors.New("this build has no release signing key; upgrade is disabled (install an official release, or rebuild with RELEASE_KEY)")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("compiled-in release key is invalid")
	}
	return ed25519.PublicKey(b), nil
}

// SignedMessage is what the release key signs.
func SignedMessage(sums []byte) []byte {
	return append([]byte(SignatureDomain+"\x00"), sums...)
}

// VerifySums checks the signature file over SHA256SUMS.
func VerifySums(pub ed25519.PublicKey, sums, sigFile []byte) error {
	sig, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(sigFile)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed SHA256SUMS.sig", ErrVerify)
	}
	if !ed25519.Verify(pub, SignedMessage(sums), sig) {
		return fmt.Errorf("%w: invalid signature on SHA256SUMS (not signed by the meshly release key)", ErrVerify)
	}
	return nil
}

var (
	semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$`)
	sumsRe   = regexp.MustCompile(`^([0-9a-f]{64})  meshly-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)-linux-([a-z0-9]+)$`)
)

// FindAsset parses SHA256SUMS and returns the entry for arch.
func FindAsset(sums []byte, arch string) (*Release, error) {
	var found *Release
	versions := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		m := sumsRe.FindStringSubmatch(line)
		if m == nil {
			continue // other assets (install.sh, ...)
		}
		versions[m[2]] = true
		if m[3] == arch {
			found = &Release{SHA256: m[1], Version: m[2], Asset: "meshly-" + m[2] + "-linux-" + m[3]}
		}
	}
	if len(versions) > 1 {
		return nil, fmt.Errorf("%w: SHA256SUMS lists more than one version", ErrVerify)
	}
	if found == nil {
		return nil, fmt.Errorf("release has no binary for linux/%s", arch)
	}
	return found, nil
}

// Compare compares two semantic versions by SemVer 2.0 precedence: the
// numeric core first; a pre-release sorts before the release; pre-release
// identifiers compare numerically when both are numeric, numeric ones
// sort before alphanumeric ones, and a longer list wins a common prefix.
func Compare(a, b string) int {
	pa, sa, _ := strings.Cut(a, "-")
	pb, sb, _ := strings.Cut(b, "-")
	x, y := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < 3; i++ {
		var xi, yi int
		if i < len(x) {
			xi, _ = strconv.Atoi(x[i])
		}
		if i < len(y) {
			yi, _ = strconv.Atoi(y[i])
		}
		if c := cmp.Compare(xi, yi); c != 0 {
			return c
		}
	}
	switch {
	case sa == sb:
		return 0
	case sa == "":
		return 1
	case sb == "":
		return -1
	}
	ia, ib := strings.Split(sa, "."), strings.Split(sb, ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		na, ea := strconv.ParseUint(ia[i], 10, 64)
		nb, eb := strconv.ParseUint(ib[i], 10, 64)
		var c int
		switch {
		case ea == nil && eb == nil:
			c = cmp.Compare(na, nb)
		case ea == nil:
			c = -1
		case eb == nil:
			c = 1
		default:
			c = strings.Compare(ia[i], ib[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(ia), len(ib))
}

// Install atomically replaces exe with bin after checking that the new
// binary runs and reports the expected version. The previous binary is
// kept as exe+".prev".
func Install(ctx context.Context, exe string, bin []byte, wantVersion string) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".meshly-new-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	got, err := ReportedVersion(ctx, tmpName)
	if err != nil {
		return fmt.Errorf("new binary does not run on this system: %w", err)
	}
	if got != wantVersion {
		return fmt.Errorf("%w: new binary reports version %s, expected %s", ErrVerify, got, wantVersion)
	}
	if err := copyFile(exe, exe+".prev"); err != nil {
		return fmt.Errorf("back up current binary: %w", err)
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return err
	}
	ok = true
	d, err := os.Open(dir)
	if err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Rollback restores exe from exe+".prev".
func Rollback(exe string) error {
	prev := exe + ".prev"
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("no previous binary at %s", prev)
	}
	tmp := exe + ".rollback"
	if err := copyFile(prev, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, exe)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err == nil {
		_ = f.Sync()
		f.Close()
	}
	return os.Rename(tmp, dst)
}

// ReportedVersion runs `<bin> version --short`.
func ReportedVersion(ctx context.Context, bin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "version", "--short")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
