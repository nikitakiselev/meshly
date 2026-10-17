package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Binary is the fixed path of the nft frontend. It is executed directly
// (never through a shell) with a fixed argument vector; rulesets are passed
// on stdin.
const Binary = "/usr/sbin/nft"

// MinVersion is the oldest nftables release Meshly is tested with
// (Debian 12).
var MinVersion = [3]int{1, 0, 6}

// Runner executes nft.
type Runner interface {
	// Run executes nft with args, feeding stdin.
	Run(ctx context.Context, stdin string, args ...string) (stdout []byte, err error)
}

// ExecRunner runs the real binary.
type ExecRunner struct{ Path string }

// Run implements Runner.
func (r ExecRunner) Run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	path := r.Path
	if path == "" {
		path = Binary
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if len(msg) > 2000 {
			msg = msg[:2000] + "…"
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%s not found: install nftables (apt install nftables)", path)
		}
		return nil, fmt.Errorf("nft %s failed: %v: %s", strings.Join(args, " "), err, msg)
	}
	return out.Bytes(), nil
}

var versionRe = regexp.MustCompile(`nftables v(\d+)\.(\d+)(?:\.(\d+))?`)

// Version returns the installed nft version.
func Version(ctx context.Context, r Runner) ([3]int, error) {
	out, err := r.Run(ctx, "", "--version")
	if err != nil {
		return [3]int{}, err
	}
	m := versionRe.FindStringSubmatch(string(out))
	if m == nil {
		return [3]int{}, fmt.Errorf("cannot parse nft version from %q", strings.TrimSpace(string(out)))
	}
	var v [3]int
	for i := 0; i < 3; i++ {
		if m[i+1] != "" {
			v[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return v, nil
}

// VersionAtLeast compares versions.
func VersionAtLeast(v, min [3]int) bool {
	for i := 0; i < 3; i++ {
		if v[i] != min[i] {
			return v[i] > min[i]
		}
	}
	return true
}

// Client wraps a Runner with the operations Meshly needs.
type Client struct{ R Runner }

// Check validates a script in the kernel without committing it (nft -c).
func (c Client) Check(ctx context.Context, script string) error {
	_, err := c.R.Run(ctx, script, "-c", "-f", "-")
	return err
}

// ApplyScript commits a script atomically.
func (c Client) ApplyScript(ctx context.Context, script string) error {
	_, err := c.R.Run(ctx, script, "-f", "-")
	return err
}

// ListRuleset returns the full ruleset as parsed JSON.
func (c Client) ListRuleset(ctx context.Context) (*Ruleset, error) {
	out, err := c.R.Run(ctx, "", "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return ParseRuleset(out)
}

// ListTable returns the Meshly table as JSON objects, or nil if absent.
func (c Client) ListTable(ctx context.Context) (*Ruleset, error) {
	rs, err := c.ListRuleset(ctx)
	if err != nil {
		return nil, err
	}
	return rs.Table(TableFamily, TableName), nil
}
