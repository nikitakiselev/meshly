package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/systemd"
)

// Skipping a failed/inactive state here leaves the restored binary on disk
// while its formerly running service and VPN remain down.
func TestUpgradeRestoredBinaryRestartsFailedService(t *testing.T) {
	exe := upgradeInstallStub(t)
	state := "failed"
	a := &App{Systemd: &systemd.Manager{Available: true, Run: func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "restart":
			if !slices.Equal(args, []string{"restart", systemd.Unit}) {
				t.Fatalf("restart arguments: %v", args)
			}
			state = "active"
			return nil, nil
		case "show":
			return []byte(fmt.Sprintf("ActiveState=%s\nUnitFileState=enabled\nResult=success\n", state)), nil
		default:
			t.Fatalf("unexpected systemctl command: %v", args)
			return nil, nil
		}
	}}}
	if err := a.restartWith(context.Background(), exe, true); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Fatalf("restored service is %s; want active", state)
	}
}

// A successful-looking partial response cannot turn a failed systemctl query
// into verification that the restored service is active.
func TestUpgradeRestartReportsStateReadFailure(t *testing.T) {
	queryErr := errors.New("systemd connection lost")
	a := &App{Systemd: &systemd.Manager{Available: true, Run: func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "restart" {
			return nil, nil
		}
		return []byte("ActiveState=active\nUnitFileState=enabled\nResult=success\n"), queryErr
	}}}
	err := a.restartWith(context.Background(), upgradeInstallStub(t), true)
	if !errors.Is(err, queryErr) {
		t.Fatalf("want state read failure %v, got %v", queryErr, err)
	}
}

func TestUpgradeRestartReportsInactiveService(t *testing.T) {
	a := &App{Systemd: &systemd.Manager{Available: true, Run: func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "restart" {
			return nil, nil
		}
		return []byte("ActiveState=inactive\nUnitFileState=enabled\nResult=exit-code\n"), nil
	}}}
	if err := a.restartWith(context.Background(), upgradeInstallStub(t), true); err == nil || !strings.Contains(err.Error(), "inactive") {
		t.Fatalf("want inactive-service failure, got %v", err)
	}
}

func TestUpgradeRollbackReportsRestorationFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		previous bool
		want     string
	}{
		{"binary restore fails", false, "binary rollback failed"},
		{"restored service fails", true, "restored 0.0.1 but the service still fails"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			exe := filepath.Join(root, "meshly")
			mustWrite := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			mustWrite(exe, "#!/bin/sh\necho new-version-install-failed >&2\nexit 12\n")
			if tc.previous {
				mustWrite(exe+".prev", "#!/bin/sh\necho previous-version-install-failed >&2\nexit 13\n")
			}
			paths := store.RootedPaths(filepath.Join(root, "state"), os.Getuid())
			if err := paths.EnsureDirs(); err != nil {
				t.Fatal(err)
			}
			a := &App{Stderr: io.Discard, Journal: journal.Open(paths.JournalFile(), time.Now)}
			err := a.restartUpgrade(context.Background(), exe, "0.0.1", "0.0.2", true)
			if err == nil || codeOf(err) == ExitRolledBack || !strings.Contains(err.Error(), "new-version-install-failed") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want original and restoration failures without recovered exit code; got %v", err)
			}
			if tc.previous {
				if !strings.Contains(err.Error(), "previous-version-install-failed") {
					t.Fatalf("lost restoration error: %v", err)
				}
				got, rerr := os.ReadFile(exe)
				if rerr != nil || !strings.Contains(string(got), "previous-version-install-failed") {
					t.Fatalf("previous binary not restored: %q, %v", got, rerr)
				}
			}
		})
	}
}

func upgradeInstallStub(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "meshly")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}
