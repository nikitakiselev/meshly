//go:build !meshly_faultinject

package fault

// Point is a no-op in production builds.
func Point(string) error { return nil }

// Enabled reports whether fault injection is compiled in.
const Enabled = false

// TestEnv returns "" in production builds: test overrides are ignored.
func TestEnv(string) string { return "" }
