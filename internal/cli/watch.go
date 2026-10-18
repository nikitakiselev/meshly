package cli

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// serviceWatch is run by meshly-watch.service. It repairs drift moments
// after a change of the links or of nftables: a new Docker network, Docker
// putting its jumps above meshly's rule in FORWARD again. The check timer
// would repair the same within a minute. SIGTERM ends it with code 0.
func (a *App) serviceWatch(ctx context.Context) error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	wait, cancel := a.waitContext(ctx)
	defer cancel()
	// Subscribed before the first check, which covers what changed while
	// the watch was not running: nothing that changes during it is missed.
	// The changes of its own repair cause one more check, without drift.
	changes, err := a.Changes(wait)
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	w := &watch{a: a, ctx: ctx, wait: wait, changes: changes}
	for w.check() && w.settle() {
	}
	if w.closed && wait.Err() == nil {
		return errors.New("watch: the link and nftables events ended")
	}
	return nil
}

// watch is one run of serviceWatch.
type watch struct {
	a *App
	// ctx carries the checks: SIGTERM never cuts a repair in half.
	ctx context.Context
	// wait ends with SIGTERM.
	wait    context.Context
	changes <-chan struct{}
	closed  bool // changes was closed
}

// settle waits for a change, then until no other came for WatchQuiet, but
// no longer than WatchMax after the first. It reports whether the watch
// goes on.
func (w *watch) settle() bool {
	var quiet <-chan time.Time // nil until the first change
	var deadline time.Time
	for {
		select {
		case <-w.wait.Done():
			return false
		case <-quiet:
			return true
		case _, ok := <-w.changes:
			if !ok {
				w.closed = true
				return false
			}
			if quiet == nil {
				deadline = time.Now().Add(w.a.WatchMax)
			}
			quiet = time.After(min(w.a.WatchQuiet, time.Until(deadline)))
		}
	}
}

// check runs checkOnce, again every WatchRetry while the lock is busy or
// the check failed before a repair (a read that changes interrupted), and
// reports whether the watch goes on. A failed repair (failedRepair) is
// followed by a pause of WatchBackoff: the changes after it are mostly its
// own (rollback, safe mode, the table without the Docker networks), and
// answering them would repeat the failing transaction every second. The
// check timer retries meanwhile.
func (w *watch) check() bool {
	for {
		busy, err := w.a.checkOnce(w.ctx)
		if w.a.watchChecked != nil {
			w.a.watchChecked()
		}
		if err != nil {
			fmt.Fprintf(w.a.Stderr, "meshly: watch: %v\n", err)
		}
		switch {
		case failedRepair(err):
			return w.pause(w.a.WatchBackoff)
		case err == nil && !busy:
			return true
		}
		if !w.pause(w.a.WatchRetry) {
			return false
		}
	}
}

// pause waits for d and reports whether the watch goes on. Changes that come
// meanwhile are dropped: the check after a retry sees them, and after a
// failed repair they are left to the check timer.
func (w *watch) pause(d time.Duration) bool {
	t := time.After(d)
	for {
		select {
		case <-w.wait.Done():
			return false
		case <-t:
			return true
		case _, ok := <-w.changes:
			if !ok {
				w.closed = true
				return false
			}
		}
	}
}
