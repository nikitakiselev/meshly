package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/netstack"
)

// A directory at the revision filename deterministically prevents atomic
// history replacement, including when tests run as root.
func blockHistory(t *testing.T, v *env, revision uint64) func() {
	t.Helper()
	path := v.paths.HistoryFile(revision)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

func requireClosed(t *testing.T, v *env) {
	t.Helper()
	if l := v.k.Links["meshly0"]; l != nil && l.Up {
		t.Fatal("VPN traffic path reopened while recovery persistence is blocked")
	}
}

func TestForwardPersistenceFailureRetainsIntent(t *testing.T) {
	for _, name := range []string{"deny", "revoke", "stop"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			v := newEnv(t)
			c := v.config()
			c.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
			v.commit(c)
			base, _ := v.paths.LoadConfig()
			target := base.Clone()
			switch name {
			case "deny":
				target.Rules = nil
			case "revoke":
				target.Rules = nil
				target.Peers = nil
			case "stop":
				target.AdminState = model.AdminDown
			}
			unblock := blockHistory(t, v, base.Revision+1)
			_, err := v.e.Execute(ctx, v.j, Op{Name: name, Recovery: journal.Forward, Base: base, Target: target})
			var ae *ApplyError
			if !errors.As(err, &ae) || !ae.SafeMode {
				t.Fatalf("want safe mode after failed save: %v", err)
			}
			requireClosed(t, v)
			if inc, err := v.j.Incomplete(); err != nil || inc == nil {
				t.Fatalf("lost access-reducing intent: %v, %v", inc, err)
			}
			for i := 0; i < 2; i++ {
				if _, err := v.e.Recover(ctx, v.j); err == nil {
					t.Fatal("recovery succeeded while persistence remains blocked")
				}
				requireClosed(t, v)
				if inc, _ := v.j.Incomplete(); inc == nil {
					t.Fatal("failed recovery lost intent")
				}
			}
			unblock()
			rec, err := v.e.Recover(ctx, v.j)
			if err != nil || rec == nil || rec.Mode != "rolled-forward" {
				t.Fatalf("recovery: %+v, %v", rec, err)
			}
			got, err := v.paths.LoadConfig()
			if err != nil || !SameConfig(got, target) {
				t.Fatalf("target not persisted: %+v, %v", got, err)
			}
			if p := v.plan(target); len(p) > 0 {
				t.Fatalf("target not applied: %v", p)
			}
			if inc, _ := v.j.Incomplete(); inc != nil {
				t.Fatal("successful recovery remains pending")
			}
		})
	}
}

func TestRecoverPersistenceFailureClosesExistingPath(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
	v.commit(c)
	base, _ := v.paths.LoadConfig()
	target := base.Clone()
	target.Revision++
	target.Rules = nil
	if err := v.j.Append(journal.Record{Event: journal.EventBegin, OpID: "interrupted-deny", Op: "deny", Recovery: journal.Forward, Target: target, Interface: "meshly0"}); err != nil {
		t.Fatal(err)
	}
	blockHistory(t, v, target.Revision)
	if _, err := v.e.Recover(context.Background(), v.j); err == nil {
		t.Fatal("want persistence failure")
	}
	requireClosed(t, v)
}

func TestBackwardFailedBaseSaveDoesNotRecoverSavedGrant(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	v.commit(v.config())
	base, _ := v.paths.LoadConfig()
	target := base.Clone()
	target.Revision++
	target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
	if err := v.j.Append(journal.Record{Event: journal.EventBegin, OpID: "failed-allow", Op: "allow", Recovery: journal.Backward, Target: target, Interface: "meshly0", BaseRevision: base.Revision, Base: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.Reconcile(ctx, target, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	if err := v.e.persist(target); err != nil {
		t.Fatal(err)
	}
	unblock := blockHistory(t, v, base.Revision)
	err := v.e.fail(ctx, v.j, Op{Name: "allow", Recovery: journal.Backward, Base: base, Target: target}, "failed-allow", "meshly0", errors.New("failed after saving target"))
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.SafeMode {
		t.Fatalf("want safe mode: %v", err)
	}
	requireClosed(t, v)
	if inc, _ := v.j.Incomplete(); inc == nil {
		t.Fatal("lost rollback intent while saved grant remains")
	}
	if _, err := v.e.Recover(ctx, v.j); err == nil {
		t.Fatal("want blocked base save to keep recovery pending")
	}
	requireClosed(t, v)
	unblock()
	rec, err := v.e.Recover(ctx, v.j)
	if err != nil || rec == nil || rec.Mode != "rolled-back" {
		t.Fatalf("recovery: %+v, %v", rec, err)
	}
	got, err := v.paths.LoadConfig()
	if err != nil || len(got.Rules) != 0 || got.Revision != base.Revision {
		t.Fatalf("failed grant restored: %+v, %v", got, err)
	}
	if p := v.plan(base); len(p) > 0 {
		t.Fatalf("kernel not at base: %v", p)
	}
}

// Only a journal commit completes a new access-granting operation. A
// target saved before a crash must not override the durable rollback base.
func TestBackwardRecoveryAfterTargetSave(t *testing.T) {
	for _, tc := range []struct {
		name         string
		legacy, init bool
		mode         string
		rules        int
	}{
		{name: "new record restores base", mode: "rolled-back"},
		{name: "legacy record retains completion semantics", legacy: true, mode: "completed", rules: 1},
		{name: "init restores absent base", init: true, mode: "rolled-back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			v := newEnv(t)
			var base *model.Config
			if !tc.init {
				v.commit(v.config())
				base, _ = v.paths.LoadConfig()
			}
			target := v.config()
			target.Revision = 1
			if base != nil {
				target = base.Clone()
				target.Revision++
			}
			target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
			begin := journal.Record{Event: journal.EventBegin, OpID: "crashed-grant", Op: "allow", Recovery: journal.Backward, Target: target, Interface: "meshly0"}
			if !tc.legacy {
				begin.Base = base
				begin.BaseAbsent = base == nil
			}
			if err := v.j.Append(begin); err != nil {
				t.Fatal(err)
			}
			if _, err := v.e.Reconcile(ctx, target, "meshly0", nil); err != nil {
				t.Fatal(err)
			}
			if err := v.e.persist(target); err != nil {
				t.Fatal(err)
			}
			rec, err := v.e.Recover(ctx, v.j)
			if err != nil || rec == nil || rec.Mode != tc.mode {
				t.Fatalf("recovery: %+v, %v", rec, err)
			}
			got, err := v.paths.LoadConfig()
			if tc.init {
				if err == nil || got != nil {
					t.Fatalf("init target survived rollback: %+v, %v", got, err)
				}
				requireClosed(t, v)
				return
			}
			if err != nil || len(got.Rules) != tc.rules {
				t.Fatalf("recovered rules: %+v, %v", got, err)
			}
		})
	}
}

// A failing journal append during rollback must leave enough information
// in the original begin to recover the base after persistence is repaired.
func TestBackwardRecoveryWhenFailureJournalUnavailable(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	v.commit(v.config())
	base, _ := v.paths.LoadConfig()
	target := base.Clone()
	target.Revision++
	target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
	if err := v.j.Append(journal.Record{Event: journal.EventBegin, OpID: "unlogged-failure", Op: "allow", Recovery: journal.Backward, Base: base, Target: target, Interface: "meshly0"}); err != nil {
		t.Fatal(err)
	}
	if err := v.e.persist(target); err != nil {
		t.Fatal(err)
	}
	unblock := blockHistory(t, v, base.Revision)
	path := v.paths.JournalFile()
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := v.e.fail(ctx, v.j, Op{Name: "allow", Recovery: journal.Backward, Base: base, Target: target}, "unlogged-failure", "meshly0", errors.New("failed after save"))
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.SafeMode {
		t.Fatalf("want safe mode: %v", err)
	}
	requireClosed(t, v)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	unblock()
	if _, err := v.e.Recover(ctx, v.j); err != nil {
		t.Fatal(err)
	}
	got, err := v.paths.LoadConfig()
	if err != nil || len(got.Rules) != 0 {
		t.Fatalf("unlogged failure restored grant: %+v, %v", got, err)
	}
}

func TestForwardRetryReportsPersistenceFailure(t *testing.T) {
	v := newEnv(t)
	v.commit(v.config())
	base, _ := v.paths.LoadConfig()
	target := base.Clone()
	target.AdminState = model.AdminDown
	target.Revision++
	blockHistory(t, v, target.Revision)
	err := v.e.fail(context.Background(), v.j, Op{Name: "stop", Recovery: journal.Forward, Base: base, Target: target}, "stop", "meshly0", errors.New("initial apply failure"))
	if err == nil || !strings.Contains(err.Error(), "write history") {
		t.Fatalf("retry persistence failure omitted: %v", err)
	}
}

func TestRecoveryRestoresJournalIntentWithCorruptConfig(t *testing.T) {
	for _, direction := range []string{journal.Forward, journal.Backward} {
		t.Run(direction, func(t *testing.T) {
			v := newEnv(t)
			c := v.config()
			c.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
			v.commit(c)
			base, _ := v.paths.LoadConfig()
			target := base.Clone()
			target.Revision++
			target.Rules = nil
			if err := v.j.Append(journal.Record{Event: journal.EventBegin, OpID: "corrupt-config", Op: "change", Recovery: direction, Base: base, Target: target, Interface: "meshly0"}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(v.paths.ConfigFile(), []byte("{broken"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := v.e.Recover(context.Background(), v.j); err != nil {
				t.Fatal(err)
			}
			got, err := v.paths.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if direction == journal.Backward {
				want = 1
			}
			if len(got.Rules) != want {
				t.Fatalf("recovered %d rules, want %d", len(got.Rules), want)
			}
		})
	}
}

func TestCommitJournalFailureDoesNotLeaveGrant(t *testing.T) {
	for _, docker := range []bool{false, true} {
		t.Run(fmt.Sprint("docker=", docker), func(t *testing.T) {
			ctx := context.Background()
			v := newEnv(t)
			v.commit(v.config())
			base, _ := v.paths.LoadConfig()
			target := base.Clone()
			target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
			if docker {
				v.k.SetDocker([]netstack.Bridge{docker0})
				v.k.Fail("docker.routing", 1)
			}
			blocked := false
			path := v.paths.JournalFile()
			v.e.Progress = func(line string) {
				if blocked || !strings.Contains(line, "firewall") {
					return
				}
				blocked = true
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			_, err := v.e.Execute(ctx, v.j, Op{Name: "allow", Recovery: journal.Backward, Base: base, Target: target})
			if err == nil {
				t.Fatal("reported successful grant without durable journal commit")
			}
			got, loadErr := v.paths.LoadConfig()
			if loadErr != nil || len(got.Rules) != 0 {
				t.Fatalf("uncommitted grant remains saved: %+v, %v (apply: %v)", got, loadErr, err)
			}
			if len(v.plan(base)) != 0 {
				t.Fatal("uncommitted grant remains in kernel")
			}
		})
	}
}

// Append can write the complete commit line and then report a Sync/Close
// failure. A subsequent failed rollback must supersede that readable commit.
func TestVisibleCommitThenFailedRollbackRetainsBaseIntent(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	v.commit(v.config())
	base, _ := v.paths.LoadConfig()
	target := base.Clone()
	target.Revision++
	target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 8080}}
	op := Op{Name: "allow", Recovery: journal.Backward, Base: base, Target: target}
	if err := v.j.Append(journal.Record{Event: journal.EventBegin, OpID: "sync-failed", Op: "allow", Recovery: journal.Backward, Base: base, Target: target, Interface: "meshly0"}); err != nil {
		t.Fatal(err)
	}
	if err := v.e.persist(target); err != nil {
		t.Fatal(err)
	}
	if err := v.j.Append(journal.Record{Event: journal.EventCommit, OpID: "sync-failed", Op: "allow"}); err != nil {
		t.Fatal(err)
	}
	unblock := blockHistory(t, v, base.Revision)
	err := v.e.fail(ctx, v.j, op, "sync-failed", "meshly0", errors.New("commit sync failed after full write"))
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.SafeMode {
		t.Fatalf("want safe mode: %v", err)
	}
	requireClosed(t, v)
	if inc, _ := v.j.Incomplete(); inc == nil {
		t.Fatal("readable commit discarded subsequent failed rollback intent")
	}
	if _, err := v.e.Recover(ctx, v.j); err == nil {
		t.Fatal("blocked rollback unexpectedly completed")
	}
	requireClosed(t, v)
	unblock()
	if _, err := v.e.Recover(ctx, v.j); err != nil {
		t.Fatal(err)
	}
	got, err := v.paths.LoadConfig()
	if err != nil || len(got.Rules) != 0 {
		t.Fatalf("failed grant survived recovery: %+v, %v", got, err)
	}
	if inc, _ := v.j.Incomplete(); inc != nil {
		t.Fatal("successful rollback remains pending")
	}
}
