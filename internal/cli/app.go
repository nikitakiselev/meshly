// Package cli implements the meshly command line.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/bootstrap"
	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/lock"
	"github.com/nikitakiselev/meshly/internal/preflight"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/systemd"
	"golang.org/x/sys/unix"
)

// Exit codes are stable and documented in docs/cli.md.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitPreflight   = 3  // unsupported or unprepared environment, nothing changed
	ExitInvalidFile = 4  // bootstrap file rejected (signature, binding, expiry, schema)
	ExitConflict    = 5  // ownership/address/state conflict, nothing changed
	ExitBusy        = 6  // another meshly operation holds the lock
	ExitRolledBack  = 7  // apply failed, previous configuration restored
	ExitSafeMode    = 8  // apply failed, VPN closed (safe mode)
	ExitNotInit     = 9  // meshly is not initialized
	ExitDeclined    = 10 // confirmation missing or declined
	ExitWarnings    = 11 // doctor: warnings
	ExitProblems    = 12 // doctor: problems
)

// exitError carries an exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func withCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: code, err: err}
}

func errorf(code int, format string, a ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, a...)}
}

// App holds the collaborators of all commands.
type App struct {
	Stdout      io.Writer
	Stderr      io.Writer
	Stdin       io.Reader
	Interactive bool
	Paths       store.Paths
	Now         func() time.Time
	Engine      *engine.Engine
	Journal     *journal.Journal
	Sys         *preflight.System
	Systemd     *systemd.Manager
	Euid        int
	LockTimeout time.Duration
	Arch        string
}

type command struct {
	name    string
	summary string
	hidden  bool
	run     func(a *App, ctx context.Context, args []string) error
}

func commands() []command {
	return []command{
		{"init", "create a network on this node (usually the server with a public UDP endpoint)", false, (*App).cmdInit},
		{"invite", "create a one-time, time-limited invite file for the second node", false, (*App).cmdInvite},
		{"join", "create a join request from an invite (on the second node)", false, (*App).cmdJoin},
		{"approve", "verify a join request and explicitly approve the new node", false, (*App).cmdApprove},
		{"activate", "activate the approved membership from an accept file", false, (*App).cmdActivate},
		{"allow", "allow a peer to reach a local service through the VPN", false, (*App).cmdAllow},
		{"deny", "remove an allow rule (existing connections stop as well)", false, (*App).cmdDeny},
		{"rules", "list allow rules", false, (*App).cmdRules},
		{"revoke", "close access of a peer and remove it", false, (*App).cmdRevoke},
		{"status", "show configuration, kernel state and connectivity", false, (*App).cmdStatus},
		{"doctor", "diagnose problems", false, (*App).cmdDoctor},
		{"start", "start the VPN link and enable autostart", false, (*App).cmdStart},
		{"stop", "stop the VPN link (stays stopped after reboot)", false, (*App).cmdStop},
		{"restart", "tear the link down and bring it up again", false, (*App).cmdRestart},
		{"set", "change a setting: mtu, keepalive, endpoint, peer-endpoint, cidr", false, (*App).cmdSet},
		{"logs", "show the meshly operation journal", false, (*App).cmdLogs},
		{"upgrade", "download, verify and install the latest release, then restart", false, (*App).cmdUpgrade},
		{"reset", "remove the link, configuration and keys from this node", false, (*App).cmdReset},
		{"version", "print the version", false, (*App).cmdVersion},
		{"help", "show help for a command", false, (*App).cmdHelp},
		{"service", "systemd entry points: start|stop|reload|check|install", true, (*App).cmdService},
		{"recover", "finish or roll back an interrupted operation", true, (*App).cmdRecover},
	}
}

// unsupported is replaced on platforms where meshly cannot work.
var unsupported = func(string) error { return nil }

// Main runs the CLI and returns the process exit code.
func (a *App) Main(args []string) int {
	ctx := context.Background()
	if len(args) == 0 {
		a.usage(a.Stderr)
		return ExitUsage
	}
	name := args[0]
	switch name {
	case "-h", "--help":
		a.usage(a.Stdout)
		return ExitOK
	case "-v", "--version":
		name = "version"
	}
	for _, c := range commands() {
		if c.name != name {
			continue
		}
		if err := unsupported(name); err != nil {
			return a.report(withCode(ExitPreflight, err))
		}
		err := c.run(a, ctx, args[1:])
		return a.report(err)
	}
	fmt.Fprintf(a.Stderr, "meshly: unknown command %q\n\n", name)
	a.usage(a.Stderr)
	return ExitUsage
}

func (a *App) report(err error) int {
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	code := codeOf(err)
	if code == ExitWarnings || code == ExitProblems {
		return code // doctor already printed its report
	}
	msg := err.Error()
	fmt.Fprintf(a.Stderr, "meshly: error: %s\n", msg)
	return code
}

func codeOf(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	var ae *engine.ApplyError
	if errors.As(err, &ae) {
		if ae.SafeMode {
			return ExitSafeMode
		}
		if ae.RolledBack {
			return ExitRolledBack
		}
	}
	var pe *preflight.Error
	switch {
	case errors.As(err, &pe):
		return ExitPreflight
	case errors.Is(err, engine.ErrConflict):
		return ExitConflict
	case errors.Is(err, lock.ErrBusy):
		return ExitBusy
	case errors.Is(err, store.ErrNotInitialized):
		return ExitNotInit
	case errors.Is(err, bootstrap.ErrInvalid), errors.Is(err, bootstrap.ErrExpired):
		return ExitInvalidFile
	case errors.Is(err, store.ErrInsecure):
		return ExitPreflight
	case errors.Is(err, store.ErrExists):
		return ExitConflict
	}
	return ExitError
}

func (a *App) printf(format string, args ...any) { fmt.Fprintf(a.Stdout, format, args...) }

func (a *App) json(v any) error {
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// flagSet creates a flag set whose usage prints the command help.
func (a *App) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("meshly "+name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.Usage = func() { a.commandHelp(a.Stderr, name) }
	return fs
}

// parse accepts flags before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, withCode(ExitUsage, err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func (a *App) requireRoot() error {
	if a.Euid != 0 {
		return errorf(ExitPreflight, "this command changes system configuration and must run as root (use sudo)")
	}
	return nil
}

// writeOutput writes a bootstrap file for the administrator. Under sudo the
// file is given to the invoking user, so that they can copy it to the
// other node (scp) without root.
func (a *App) writeOutput(path string, data []byte, mode fs.FileMode, force bool) error {
	uid, gid := -1, -1
	if a.Euid == 0 {
		u, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
		g, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
		if err1 == nil && err2 == nil && u > 0 && g >= 0 {
			uid, gid = u, g
		}
	}
	return store.WriteOutputAs(path, data, mode, force, uid, gid)
}

// actor identifies who ran the command, for the audit trail.
func actor(euid int) string {
	s := "uid=" + strconv.Itoa(euid)
	if u := os.Getenv("SUDO_USER"); u != "" && validLogin(u) {
		s += " sudo_user=" + u
	} else if u, err := user.Current(); err == nil {
		s += " user=" + u.Username
	}
	return s
}

func validLogin(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// session is a locked mutating context.
type session struct {
	a    *App
	lock *lock.Lock
}

// begin takes the lock, prepares directories and recovers an interrupted
// operation. Callers must call end.
func (a *App) begin(ctx context.Context) (*session, error) {
	if err := a.requireRoot(); err != nil {
		return nil, err
	}
	if err := a.Paths.EnsureDirs(); err != nil {
		return nil, withCode(ExitPreflight, err)
	}
	l, err := lock.Acquire(a.Paths.LockFile(), a.LockTimeout)
	if err != nil {
		return nil, err
	}
	s := &session{a: a, lock: l}
	rec, err := a.Engine.Recover(ctx, a.Journal)
	if rec != nil {
		fmt.Fprintf(a.Stderr, "meshly: recovered interrupted operation %q: %s\n", rec.Op, rec.Mode)
	}
	if err != nil {
		s.end()
		return nil, err
	}
	return s, nil
}

func (s *session) end() { s.lock.Release() }

// confirm asks a yes/no question on the terminal. Non-interactive runs
// return false.
func (a *App) confirm(question string) bool {
	if !a.Interactive {
		return false
	}
	fmt.Fprintf(a.Stderr, "%s ", question)
	line, err := bufio.NewReader(a.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(line), "yes")
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlGetTermios)
	return err == nil
}

func (a *App) audit(op, args, detail string) {
	_ = a.Journal.Append(journal.Record{Event: journal.EventAudit, OpID: "-", Op: op, Args: args, Actor: actor(a.Euid), Detail: detail})
}
