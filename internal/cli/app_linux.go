//go:build linux

package cli

import (
	"os"
	"runtime"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/netstack"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/preflight"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/systemd"
	"github.com/nikitakiselev/meshly/internal/wg"
)

// NewApp wires the production implementations.
func NewApp() *App {
	paths := store.DefaultPaths()
	now := store.Now
	links := netstack.New()
	fw := nft.Client{R: nft.ExecRunner{}}
	a := &App{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Stdin:       os.Stdin,
		Interactive: IsTerminal(os.Stdin) && IsTerminal(os.Stderr),
		Paths:       paths,
		Now:         now,
		Journal:     journal.Open(paths.JournalFile(), now),
		Sys:         preflight.NewSystem(fw, links),
		Systemd:     systemd.New(),
		Euid:        os.Geteuid(),
		LockTimeout: 30 * time.Second,
		Arch:        runtime.GOARCH,
	}
	a.Engine = &engine.Engine{
		Links: links, WG: wg.Kernel{}, FW: fw, Paths: paths,
		LoadKeys: paths.LoadKeys, Now: now,
		Progress: func(s string) { a.printf("  %s\n", s) },
	}
	return a
}
