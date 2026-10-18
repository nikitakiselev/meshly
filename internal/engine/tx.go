package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/nikitakiselev/meshly/internal/fault"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/store"
)

// Op is one mutating operation.
type Op struct {
	Name  string // command name, e.g. "allow"
	Args  string // audit description without secrets
	Actor string
	// Recovery is journal.Backward (operations that grant access) or
	// journal.Forward (operations that remove access).
	Recovery string
	Base     *model.Config // last committed config (nil: none)
	Target   *model.Config // desired config (nil: remove the config)
	// Overlay is applied on top of Target; rollback and recovery use
	// Base/the saved config without it. It is never journaled.
	Overlay *Overlay
}

// Result describes a completed operation.
type Result struct {
	Steps         []Step
	ConfigChanged bool
	OpID          string
	// WithoutDocker is the failure with the Docker networks when the
	// operation was completed without them (nil: it was not).
	WithoutDocker error
}

// WithoutDockerDetail starts the journal detail of an operation completed
// without the Docker networks; the failure with them follows.
const WithoutDockerDetail = "completed without the Docker networks: "

// ApplyError is returned when applying failed. Exactly one of RolledBack
// and SafeMode is set when the system was brought to a safe state.
type ApplyError struct {
	Cause      error
	RolledBack bool
	SafeMode   bool
	Forward    bool
	Detail     error
}

func (e *ApplyError) Error() string {
	switch {
	case e.RolledBack:
		return fmt.Sprintf("%v (changes were rolled back; the previous configuration is active)", e.Cause)
	case e.SafeMode:
		msg := fmt.Sprintf("%v; meshly entered SAFE MODE: the VPN interface was removed and VPN access is closed", e.Cause)
		if e.Detail != nil {
			msg += fmt.Sprintf(" (additional errors: %v)", e.Detail)
		}
		return msg + "; run `meshly doctor` to find the cause and `meshly start` to retry now (while meshly.service is active, its check timer also retries the saved configuration every minute)"
	}
	return e.Cause.Error()
}

func (e *ApplyError) Unwrap() error { return e.Cause }

func ifnameOf(cfgs ...*model.Config) string {
	for _, c := range cfgs {
		if c != nil {
			return c.Interface.Name
		}
	}
	return model.DefaultInterface
}

// SameConfig compares configs ignoring revision and timestamp.
func SameConfig(a, b *model.Config) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, y := a.Clone(), b.Clone()
	x.Revision, y.Revision = 0, 0
	x.UpdatedAt, y.UpdatedAt = time.Time{}, time.Time{}
	bx, err1 := store.EncodeConfig(x)
	by, err2 := store.EncodeConfig(y)
	return err1 == nil && err2 == nil && bytes.Equal(bx, by)
}

// Preview computes the plan of op without changing anything.
func (e *Engine) Preview(ctx context.Context, op Op) (*Desired, []Step, error) {
	d, err := e.desired(op.Target, ifnameOf(op.Target, op.Base), op.Overlay)
	if err != nil {
		return nil, nil, err
	}
	o, err := e.Observe(ctx, d.Interface)
	if err != nil {
		return nil, nil, err
	}
	steps, err := e.Plan(d, o)
	return d, steps, err
}

// Execute runs op as a journaled transaction:
//
//	plan → journal begin → [forward ops: write-ahead target config] →
//	steps (firewall first) → verify → save config → journal commit
//
// On failure with Docker networks, the target is applied without them
// first (Result.WithoutDocker): a problem on the containers' path never
// takes the tunnel down. Otherwise, or if that fails too, backward ops
// restore the base config and forward ops are retried; if that fails too,
// SafeMode closes the VPN path.
func (e *Engine) Execute(ctx context.Context, j *journal.Journal, op Op) (*Result, error) {
	ifname := ifnameOf(op.Target, op.Base)
	changed := !SameConfig(op.Base, op.Target)
	if changed && op.Target != nil {
		var base uint64
		if op.Base != nil {
			base = op.Base.Revision
		}
		op.Target.Revision = base + 1
		op.Target.UpdatedAt = e.Now()
		if err := op.Target.Validate(); err != nil {
			return nil, fmt.Errorf("invalid target configuration: %w", err)
		}
	}
	d, err := e.desired(op.Target, ifname, op.Overlay)
	if err != nil {
		return nil, err
	}
	o, err := e.Observe(ctx, d.Interface)
	if err != nil {
		return nil, err
	}
	steps, err := e.Plan(d, o)
	if err != nil {
		return nil, err
	}
	res := &Result{Steps: steps, ConfigChanged: changed}
	if !changed && len(steps) == 0 {
		return res, nil
	}
	docker := hasDocker(d)
	opID, err := model.NewRandomID(rand.Read)
	if err != nil {
		return nil, err
	}
	res.OpID = opID
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	begin := journal.Record{
		OpID: opID, Event: journal.EventBegin, Op: op.Name, Args: op.Args, Actor: op.Actor,
		Recovery: op.Recovery, Target: op.Target, TargetAbsent: op.Target == nil,
		Interface: ifname, Plan: names,
	}
	if op.Base != nil {
		begin.BaseRevision = op.Base.Revision
	}
	if err := j.Append(begin); err != nil {
		return nil, fmt.Errorf("cannot write transaction journal, nothing changed: %w", err)
	}
	fail := func(cause error) (*Result, error) {
		if docker && !errors.Is(cause, ErrConflict) && e.withoutDocker(ctx, j, op, opID, ifname, cause) == nil {
			res.WithoutDocker = cause
			return res, nil
		}
		return res, e.fail(ctx, j, op, opID, ifname, cause)
	}
	if err := fault.Point("tx:after-begin"); err != nil {
		return fail(err)
	}
	forward := op.Recovery == journal.Forward
	if forward && changed {
		// Access-reducing operations become authoritative immediately:
		// an interruption must complete them, never undo them.
		if err := e.persist(op.Target); err != nil {
			return fail(err)
		}
	}
	hook := func(s Step) error { return fault.Point("step:" + s.Name) }
	err = e.run(ctx, steps, hook)
	if err == nil {
		err = fault.Point("tx:before-verify")
	}
	if err == nil {
		err = e.Verify(ctx, d)
	}
	if err == nil && !forward && changed {
		if err = fault.Point("tx:before-save"); err == nil {
			err = e.persist(op.Target)
		}
	}
	if err != nil {
		return fail(err)
	}
	if err := fault.Point("tx:before-commit"); err != nil {
		return fail(err)
	}
	if err := j.Append(journal.Record{OpID: opID, Event: journal.EventCommit, Op: op.Name}); err != nil {
		return res, fmt.Errorf("changes applied but the journal commit failed: %w", err)
	}
	return res, nil
}

// hasDocker reports whether d serves Docker networks.
func hasDocker(d *Desired) bool { return d.Present && len(d.Docker) > 0 }

// withoutDocker completes op after cause without the Docker networks: its
// target (with the overlay) as on a node without them, saved and committed.
// "tx:without-docker" lets tests make it fail.
func (e *Engine) withoutDocker(ctx context.Context, j *journal.Journal, op Op, opID, ifname string, cause error) error {
	e.progress("apply failed (%v); retrying without the Docker networks", cause)
	err := fault.Point("tx:without-docker")
	if err == nil {
		err = e.reconcileWithout(ctx, op.Target, ifname, op.Overlay)
	}
	if err == nil && !SameConfig(op.Base, op.Target) {
		// The failure may have preceded the save (or the write-ahead save).
		err = e.persist(op.Target)
	}
	if err != nil {
		return err
	}
	_ = j.Append(journal.Record{OpID: opID, Event: journal.EventCommit, Op: op.Name, Detail: WithoutDockerDetail + cause.Error()})
	return nil
}

// reconcileWithout applies cfg plus ov as on a node without Docker
// networks and verifies it.
func (e *Engine) reconcileWithout(ctx context.Context, cfg *model.Config, ifname string, ov *Overlay) error {
	d, err := DesiredWith(cfg, ifname, ov, Env{})
	if err == nil {
		_, err = e.reconcileTo(ctx, d, nil)
	}
	return err
}

func (e *Engine) persist(c *model.Config) error {
	if c == nil {
		return e.Paths.RemoveConfig()
	}
	return e.Paths.SaveConfig(c)
}

func (e *Engine) fail(ctx context.Context, j *journal.Journal, op Op, opID, ifname string, cause error) error {
	if errors.Is(cause, ErrConflict) {
		_ = j.Append(journal.Record{OpID: opID, Event: journal.EventRolledBack, Op: op.Name, Detail: cause.Error()})
		return cause
	}
	if op.Recovery == journal.Forward {
		e.progress("apply failed (%v); completing the access-reducing operation", cause)
		_, err := e.retry(ctx, op.Target, ifname)
		if err == nil && !SameConfig(op.Base, op.Target) {
			// The failure may have preceded the write-ahead save.
			err = e.persist(op.Target)
		}
		if err == nil {
			_ = j.Append(journal.Record{OpID: opID, Event: journal.EventCommit, Op: op.Name, Detail: "completed after retry: " + cause.Error()})
			return nil
		}
		smErr := e.SafeMode(ctx, op.Target, ifname)
		_ = j.Append(journal.Record{OpID: opID, Event: journal.EventSafeMode, Op: op.Name, Detail: errors.Join(cause, smErr).Error()})
		return &ApplyError{Cause: cause, SafeMode: true, Forward: true, Detail: smErr}
	}
	e.progress("apply failed (%v); rolling back", cause)
	_, err := e.retry(ctx, op.Base, ifname)
	if err == nil && !SameConfig(op.Base, op.Target) {
		// The target may already be saved (failure after save): the kernel
		// is back at the base, so the saved configuration must be too.
		err = e.persist(op.Base)
	}
	if err == nil {
		_ = j.Append(journal.Record{OpID: opID, Event: journal.EventRolledBack, Op: op.Name, Detail: cause.Error()})
		return &ApplyError{Cause: cause, RolledBack: true}
	} else {
		smErr := e.SafeMode(ctx, op.Base, ifname)
		_ = j.Append(journal.Record{OpID: opID, Event: journal.EventSafeMode, Op: op.Name, Detail: errors.Join(cause, err, smErr).Error()})
		return &ApplyError{Cause: cause, SafeMode: true, Detail: errors.Join(err, smErr)}
	}
}

// retry reconciles towards cfg after a failed apply ("tx:rollback" lets
// tests make the rollback itself fail and exercise safe mode).
func (e *Engine) retry(ctx context.Context, cfg *model.Config, ifname string) ([]Step, error) {
	if err := fault.Point("tx:rollback"); err != nil {
		return nil, err
	}
	return e.Reconcile(ctx, cfg, ifname, nil)
}

// RecoveryResult describes a recovered operation.
type RecoveryResult struct {
	Op   string
	OpID string
	Mode string // "completed", "rolled-forward", "rolled-back", "safe-mode"
	// WithoutDocker is as in Result.
	WithoutDocker error
}

// Recover finishes an interrupted transaction found in the journal. It is
// called before every mutating command and at service start.
func (e *Engine) Recover(ctx context.Context, j *journal.Journal) (*RecoveryResult, error) {
	inc, err := j.Incomplete()
	if err != nil || inc == nil {
		return nil, err
	}
	ifname := inc.Interface
	if ifname == "" {
		ifname = ifnameOf(inc.Target)
	}
	cur, err := e.Paths.LoadConfig()
	switch {
	case errors.Is(err, store.ErrNotInitialized):
		cur = nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		smErr := e.SafeMode(ctx, nil, ifname)
		_ = j.Append(journal.Record{OpID: inc.OpID, Event: journal.EventSafeMode, Op: inc.Op, Detail: errors.Join(err, smErr).Error()})
		return &RecoveryResult{Op: inc.Op, OpID: inc.OpID, Mode: "safe-mode"}, fmt.Errorf("recovery: cannot load config: %w", err)
	}
	committed := (inc.TargetAbsent && cur == nil) || (inc.Target != nil && cur != nil && cur.Revision == inc.Target.Revision && SameConfig(cur, inc.Target))
	target := cur
	mode := "rolled-back"
	switch {
	case committed && inc.Recovery == journal.Forward:
		// The target was written ahead; the kernel may still lag behind.
		mode = "rolled-forward"
	case committed:
		mode = "completed"
	case inc.Recovery == journal.Forward:
		mode = "rolled-forward"
		target = inc.Target
		if err := e.persist(target); err != nil {
			return nil, fmt.Errorf("recovery: %w", err)
		}
	}
	e.progress("recovering interrupted operation %q (%s)", inc.Op, mode)
	res := &RecoveryResult{Op: inc.Op, OpID: inc.OpID, Mode: mode}
	d, err := e.desired(target, ifname, nil)
	if err == nil {
		_, err = e.reconcileTo(ctx, d, nil)
	}
	// d is nil when the node's Docker networks could not be read.
	if err != nil && (d == nil || hasDocker(d)) {
		e.progress("recovery failed (%v); retrying without the Docker networks", err)
		if werr := e.reconcileWithout(ctx, target, ifname, nil); werr == nil {
			res.WithoutDocker, err = err, nil
		}
	}
	if err != nil {
		smErr := e.SafeMode(ctx, target, ifname)
		_ = j.Append(journal.Record{OpID: inc.OpID, Event: journal.EventSafeMode, Op: inc.Op, Detail: errors.Join(err, smErr).Error()})
		return &RecoveryResult{Op: inc.Op, OpID: inc.OpID, Mode: "safe-mode"}, &ApplyError{Cause: err, SafeMode: true, Detail: smErr}
	}
	detail := mode
	if res.WithoutDocker != nil {
		detail += "; " + WithoutDockerDetail + res.WithoutDocker.Error()
	}
	if err := j.Append(journal.Record{OpID: inc.OpID, Event: journal.EventRecovered, Op: inc.Op, Detail: detail}); err != nil {
		return nil, err
	}
	return res, nil
}
