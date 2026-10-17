// Package version holds build information set via -ldflags.
package version

// Version and Commit are overridden at build time:
//
//	-ldflags "-X github.com/nikitakiselev/meshly/internal/version.Version=0.0.1"
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
)
