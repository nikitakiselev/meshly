//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine"
	"github.com/nikitakiselev/meshly/internal/engine/enginetest"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/lock"
	"github.com/nikitakiselev/meshly/internal/netstack"
	"github.com/nikitakiselev/meshly/internal/nft"
)

// watchRun is a `meshly service watch` running in the background, fed with
// the changes the test reports.
type watchRun struct {
	t       *testing.T
	events  chan struct{}
	cancels chan context.CancelFunc
	done    chan struct{}
	stopped sync.Once
	exit    int
	out     string
	// checks counts the finished checks; subscribedAt is their number when
	// the watch subscribed (-1: not yet).
	checks       atomic.Int64
	subscribedAt atomic.Int64
}

// startWatch runs `meshly service watch` on n and returns once the watch has
// subscribed and finished its first check. SIGTERM is simulated through
// WaitContext.
func startWatch(t *testing.T, n *testNode) *watchRun {
	t.Helper()
	w := &watchRun{t: t, events: make(chan struct{}, 1), cancels: make(chan context.CancelFunc, 1), done: make(chan struct{})}
	w.subscribedAt.Store(-1)
	if n.app.WatchQuiet == 0 {
		n.app.WatchQuiet, n.app.WatchMax = 20*time.Millisecond, 100*time.Millisecond
	}
	n.app.WatchRetry = 30 * time.Millisecond
	if n.app.WatchBackoff == 0 {
		n.app.WatchBackoff = time.Hour
	}
	n.app.WaitContext = func(c context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(c)
		w.cancels <- cancel
		return ctx, cancel
	}
	n.app.Changes = func(context.Context) (<-chan struct{}, error) {
		w.subscribedAt.Store(w.checks.Load())
		return w.events, nil
	}
	n.app.watchChecked = func() { w.checks.Add(1) }
	go func() {
		defer close(w.done)
		code, out, errOut := n.run("service", "watch")
		w.exit, w.out = code, out+errOut
	}()
	t.Cleanup(func() { w.stop() })
	if !w.checked(1) || w.subscribedAt.Load() < 0 {
		code, out := w.stop()
		t.Fatalf("meshly service watch did not subscribe and check: exit %d\n%s", code, out)
	}
	return w
}

// checked waits until the watch has finished n checks in all and reports
// whether it has.
func (w *watchRun) checked(n int64) bool {
	within(10*time.Second, func() bool {
		select {
		case <-w.done:
			return true
		default:
			return w.checks.Load() >= n
		}
	})
	return w.checks.Load() >= n
}

// change reports a change as the kernel does: at most one is pending.
func (w *watchRun) change() {
	select {
	case w.events <- struct{}{}:
	default:
	}
}

// stop simulates SIGTERM and returns the exit code and the output.
func (w *watchRun) stop() (int, string) {
	w.stopped.Do(func() {
		select {
		case cancel := <-w.cancels:
			cancel()
		case <-w.done:
		}
		select {
		case <-w.done:
		case <-time.After(10 * time.Second):
			w.t.Fatal("meshly service watch did not stop")
		}
	})
	return w.exit, w.out
}

// within reports whether cond becomes true within d.
func within(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	return true
}

// checkRepairs counts the journal records of check-repair transactions
// with one of the events. The watch may be writing the last line.
func checkRepairs(t *testing.T, n *testNode, events ...string) int {
	t.Helper()
	b, err := os.ReadFile(n.app.Paths.JournalFile())
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	c := 0
	for _, line := range lines[:len(lines)-1] {
		var r journal.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		for _, e := range events {
			if r.Op == "check-repair" && r.Event == e {
				c++
			}
		}
	}
	return c
}

var docker0 = []netstack.Bridge{{Name: "docker0", Prefixes: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}}}

// dockerApplied reports whether forwarding and policy routing are on.
func dockerApplied(n *testNode) bool {
	fwd, _ := n.k.LinkOps().Forwarding("meshly0")
	r, _ := n.k.LinkOps().ObserveDockerRouting()
	return fwd && len(r.Rules) > 0 && len(r.Routes) > 0
}

func TestServiceWatchAppliesDockerNetwork(t *testing.T) {
	vps, _ := pair(t)
	w := startWatch(t, vps)
	vps.k.SetDocker(docker0)
	w.change()
	if !within(time.Second, func() bool { return dockerApplied(vps) }) {
		t.Fatal("the Docker network is not applied")
	}
	if !within(time.Second, func() bool { return checkRepairs(t, vps, journal.EventCommit) == 1 }) {
		t.Fatal("no committed check-repair")
	}
	code, out := w.stop()
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if n := checkRepairs(t, vps, journal.EventBegin); n != 1 {
		t.Fatalf("%d check-repair transactions, want 1\n%s", n, out)
	}
	if !strings.Contains(out, "meshly: drift detected, repairing: Docker networks changed: +docker0") ||
		!strings.Contains(out, "Applying check-repair:") {
		t.Fatalf("output:\n%s", out)
	}
}

// A new Docker network comes as a burst: the bridge, then Docker's
// iptables rules, its jump to the top of FORWARD again and again. One
// repair follows the burst.
func TestServiceWatchDebounce(t *testing.T) {
	vps, _ := pair(t)
	vps.k.AddIptables("ip", "FORWARD", "drop", 1)
	// The burst takes some 50 ms; scheduling under -race on CI must not
	// stretch a pause in it past the quiet time.
	vps.app.WatchQuiet, vps.app.WatchMax = 200*time.Millisecond, 2*time.Second
	w := startWatch(t, vps)
	vps.k.SetDocker(docker0)
	for i := range 20 {
		if i%5 == 0 {
			rs := vps.k.IptablesRules("ip", "FORWARD")
			vps.k.SetIptablesRules("ip", "FORWARD", append([]enginetest.IptablesRule{{Handle: 900 + i}}, rs...))
		}
		w.change()
		time.Sleep(2500 * time.Microsecond)
	}
	ours := func() bool {
		rs := vps.k.IptablesRules("ip", "FORWARD")
		return len(rs) > 0 && rs[0].Comment == nft.IptablesComment
	}
	if !within(2*vps.app.WatchMax, func() bool { return dockerApplied(vps) && ours() }) {
		t.Fatalf("not applied: FORWARD %+v", vps.k.IptablesRules("ip", "FORWARD"))
	}
	time.Sleep(2 * vps.app.WatchQuiet)
	if n := checkRepairs(t, vps, journal.EventBegin); n != 1 {
		_, out := w.stop()
		t.Fatalf("%d check-repair transactions, want 1\n%s", n, out)
	}
}

// Changes that never pause do not hold the repair off past WatchMax.
func TestServiceWatchMaxWait(t *testing.T) {
	vps, _ := pair(t)
	w := startWatch(t, vps)
	vps.k.SetDocker(docker0)
	if !within(time.Second, func() bool { w.change(); return dockerApplied(vps) }) {
		t.Fatal("not applied while the changes went on")
	}
}

// The first check covers the changes made while the watch was not running.
// The watch subscribes before it: nothing that changes during the check is
// missed.
func TestServiceWatchChecksAtStart(t *testing.T) {
	vps, _ := pair(t)
	vps.k.SetDocker(docker0)
	w := startWatch(t, vps)
	if !dockerApplied(vps) {
		t.Fatal("not applied at start")
	}
	if n := w.subscribedAt.Load(); n != 0 {
		t.Fatalf("subscribed after %d checks, want before the first", n)
	}
}

// Review Focus 4: a change that comes while another command holds the lock
// is applied once the lock is free.
func TestServiceWatchWaitsForLock(t *testing.T) {
	vps, _ := pair(t)
	w := startWatch(t, vps)
	l, err := lock.Acquire(vps.app.Paths.LockFile(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	vps.k.SetDocker(docker0)
	w.change()
	time.Sleep(200 * time.Millisecond)
	if dockerApplied(vps) || checkRepairs(t, vps, journal.EventBegin) != 0 {
		l.Release()
		t.Fatal("repaired while the lock was held")
	}
	l.Release()
	if !within(500*time.Millisecond, func() bool { return dockerApplied(vps) }) {
		_, out := w.stop()
		t.Fatalf("not applied after the lock was released\n%s", out)
	}
}

// A change that leaves the desired state as it is (such as the watch's
// own repair) writes nothing to the journal.
func TestServiceWatchNoChangeNoJournal(t *testing.T) {
	vps, _ := pair(t)
	w := startWatch(t, vps)
	before := readFile(t, vps.app.Paths.JournalFile())
	w.change()
	if !w.checked(w.checks.Load() + 1) {
		t.Fatal("no check after the change")
	}
	if after := readFile(t, vps.app.Paths.JournalFile()); after != before {
		t.Fatalf("journal written:\n%s", strings.TrimPrefix(after, before))
	}
	// The watch is alive: a real change is still repaired.
	vps.k.SetDocker(docker0)
	w.change()
	if !within(time.Second, func() bool { return dockerApplied(vps) }) {
		_, out := w.stop()
		t.Fatalf("not applied\n%s", out)
	}
}

// A failed repair changes the kernel itself (rollback, safe mode). The
// watch does not answer those changes with the same failing transaction
// every second: for WatchBackoff it leaves the retry to the check timer.
func TestServiceWatchBacksOffAfterFailure(t *testing.T) {
	vps, _ := pair(t)
	vps.k.AddIptables("ip", "INPUT", "drop", 1)
	vps.must("service", "check")
	vps.app.WatchBackoff = 500 * time.Millisecond
	w := startWatch(t, vps)
	base := checkRepairs(t, vps, journal.EventBegin)
	vps.k.Fail("iptables.apply", -1)
	vps.k.SetIptablesRules("ip", "INPUT", []enginetest.IptablesRule{{Handle: 900}})
	w.change()
	if !within(time.Second, func() bool {
		return checkRepairs(t, vps, journal.EventRolledBack, journal.EventSafeMode) == 1
	}) {
		_, out := w.stop()
		t.Fatalf("the repair did not fail\n%s", out)
	}
	for range 20 {
		w.change()
		time.Sleep(10 * time.Millisecond)
	}
	if n := checkRepairs(t, vps, journal.EventBegin) - base; n != 1 {
		_, out := w.stop()
		t.Fatalf("%d check-repair transactions during the backoff, want 1\n%s", n, out)
	}
	time.Sleep(vps.app.WatchBackoff - 100*time.Millisecond)
	w.change()
	if !within(time.Second, func() bool { return checkRepairs(t, vps, journal.EventBegin)-base == 2 }) {
		_, out := w.stop()
		t.Fatalf("no new attempt after the backoff\n%s", out)
	}
	code, out := w.stop()
	if code != 0 || !strings.Contains(out, "meshly: watch: ") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// A repair that succeeds only without the Docker networks counts as a
// failure: its own changes are not answered with the same repair, the
// next try comes after WatchBackoff.
func TestServiceWatchBacksOffWithoutDocker(t *testing.T) {
	vps, _ := pair(t)
	vps.app.WatchBackoff = 500 * time.Millisecond
	w := startWatch(t, vps)
	vps.k.Fail("docker.routing", 1)
	vps.k.SetDocker(docker0)
	w.change()
	if !within(time.Second, func() bool { return checkRepairs(t, vps, journal.EventCommit) == 1 }) {
		_, out := w.stop()
		t.Fatalf("no repair\n%s", out)
	}
	if dockerApplied(vps) {
		t.Fatal("Docker applied despite the failure")
	}
	for range 20 {
		w.change()
		time.Sleep(10 * time.Millisecond)
	}
	if n := checkRepairs(t, vps, journal.EventBegin); n != 1 {
		_, out := w.stop()
		t.Fatalf("%d check-repair transactions during the backoff, want 1\n%s", n, out)
	}
	time.Sleep(vps.app.WatchBackoff - 100*time.Millisecond)
	w.change()
	if !within(time.Second, func() bool { return dockerApplied(vps) }) {
		_, out := w.stop()
		t.Fatalf("not applied after the backoff\n%s", out)
	}
	code, out := w.stop()
	if code != 0 || !strings.Contains(out, "meshly: watch: repaired only without the Docker networks") ||
		!strings.Contains(out, "meshly: warning: applied without the Docker networks") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// An error before any transaction, such as a read of the links that a
// burst of changes interrupted, is retried after WatchRetry, not after
// WatchBackoff: the new network works within seconds.
func TestServiceWatchRetriesAfterReadError(t *testing.T) {
	vps, _ := pair(t)
	w := startWatch(t, vps) // WatchBackoff: an hour
	vps.k.Fail("docker.bridges", 2)
	vps.k.SetDocker(docker0)
	w.change()
	if !within(time.Second, func() bool { return dockerApplied(vps) }) {
		_, out := w.stop()
		t.Fatalf("not applied after the read errors\n%s", out)
	}
	if code, out := w.stop(); code != 0 || strings.Count(out, "meshly: watch: find Docker networks: fake docker.bridges failure") != 2 {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// The lock held by a waiting invite is busy, like any other holder.
func TestLockBusy(t *testing.T) {
	for _, err := range []error{lock.ErrBusy, errorf(ExitBusy, "meshly invite is waiting for a node to join until now")} {
		if !lockBusy(err) {
			t.Errorf("lockBusy(%v) = false", err)
		}
	}
	for _, err := range []error{nil, errors.New("read links"), errorf(ExitPreflight, "x"), &engine.ApplyError{Cause: errors.New("x"), RolledBack: true}} {
		if lockBusy(err) {
			t.Errorf("lockBusy(%v) = true", err)
		}
	}
}

// The check timer's repair that succeeds only without the Docker networks
// succeeds, with a warning; doctor shows why.
func TestServiceCheckWithoutDocker(t *testing.T) {
	vps, _ := pair(t)
	vps.k.Fail("docker.routing", 1)
	vps.k.SetDocker(docker0)
	code, _, errOut := vps.run("service", "check")
	if code != 0 || !strings.Contains(errOut, "meshly: warning: applied without the Docker networks") || !strings.Contains(errOut, "fake docker.routing failure") {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if dockerApplied(vps) {
		t.Fatal("Docker applied despite the failure")
	}
	if logs := vps.must("logs"); !strings.Contains(logs, "completed without the Docker networks: ") {
		t.Fatalf("logs:\n%s", logs)
	}
	if _, d, _ := vps.run("doctor"); !strings.Contains(d, "completed without the Docker networks") {
		t.Fatalf("doctor:\n%s", d)
	}
	vps.must("service", "check")
	if !dockerApplied(vps) {
		t.Fatal("Docker not applied by the next check")
	}
}
