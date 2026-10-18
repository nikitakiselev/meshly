//go:build linux

package cli

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/netstack"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/pairing"
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
		Pairing:     pairing.Kernel{},
		WaitContext: interruptible,
		After:       time.After,
		Hostname:    os.Hostname,
	}
	a.Engine = &engine.Engine{
		Links: links, WG: wg.Kernel{}, FW: fw, Paths: paths,
		LoadKeys: paths.LoadKeys, Now: now,
		Progress: func(s string) { a.printf("  %s\n", s) },
	}
	return a
}

// interruptible ends with Ctrl+C, SIGTERM, the hang-up of the terminal (a
// closed SSH session) or SIGPIPE (`| tee` killed by Ctrl+C first), so that
// the invite or join cleans up rather than dies halfway: caught, a broken
// pipe only fails the write. Once caught, SIGPIPE comes from a broken pipe
// on any descriptor, not only stdout or stderr. A SIGHUP or SIGPIPE ignored
// at start, as under nohup, stays ignored.
func interruptible(c context.Context) (context.Context, context.CancelFunc) {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	for _, s := range []os.Signal{syscall.SIGHUP, syscall.SIGPIPE} {
		if !signal.Ignored(s) {
			sigs = append(sigs, s)
		}
	}
	return signal.NotifyContext(c, sigs...)
}
