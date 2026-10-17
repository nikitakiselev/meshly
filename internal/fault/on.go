//go:build meshly_faultinject

package fault

import (
	"fmt"
	"os"
	"strings"
)

// Enabled reports whether fault injection is compiled in.
const Enabled = true

// Point fails ("error") or kills the process without cleanup ("crash",
// simulating power loss) when the named point is listed in MESHLY_FAULT.
func Point(name string) error {
	for _, spec := range strings.Split(os.Getenv("MESHLY_FAULT"), ",") {
		p, action, _ := strings.Cut(strings.TrimSpace(spec), "=")
		if p != name {
			continue
		}
		switch action {
		case "crash":
			fmt.Fprintf(os.Stderr, "meshly: injected crash at %s\n", name)
			os.Exit(137)
		default:
			return fmt.Errorf("%w at %s", ErrInjected, name)
		}
	}
	return nil
}

// TestEnv returns a test override from the environment (fault-injection
// builds only), e.g. MESHLY_TEST_RELEASE_URL for upgrade tests.
func TestEnv(name string) string { return os.Getenv(name) }
