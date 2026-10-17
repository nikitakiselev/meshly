// Package journal is the append-only transaction log of Meshly. Every
// mutating operation writes a "begin" record (with the full target config
// needed for recovery), phase records and a terminal record. An operation
// without a terminal record is incomplete and is recovered on the next run.
// The same records form the audit trail shown by `meshly logs`.
package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/nikitakiselev/meshly/internal/model"
	"golang.org/x/sys/unix"
)

// Event kinds.
const (
	EventBegin      = "begin"
	EventPhase      = "phase"
	EventCommit     = "commit"
	EventRolledBack = "rolled-back"
	EventSafeMode   = "safe-mode"
	EventRecovered  = "recovered"
	// EventAudit records an operation that changes no kernel state
	// (upgrade, an invite opened or closed); it never opens a transaction.
	EventAudit = "audit"
)

// Recovery direction of an operation if it is interrupted.
const (
	// Backward: restore the last committed config (operations that grant
	// access: init, invite, join, allow, start, set).
	Backward = "backward"
	// Forward: finish the operation (operations that remove access: deny,
	// revoke, stop, reset, invite-undo, join-undo) so an interruption never re-opens access.
	Forward = "forward"
)

// Record is one journal line.
type Record struct {
	Time   time.Time `json:"time"`
	OpID   string    `json:"op_id"`
	Event  string    `json:"event"`
	Op     string    `json:"op,omitempty"`
	Args   string    `json:"args,omitempty"`
	Actor  string    `json:"actor,omitempty"`
	Detail string    `json:"detail,omitempty"`

	// begin only
	Recovery     string        `json:"recovery,omitempty"`
	BaseRevision uint64        `json:"base_revision,omitempty"`
	Target       *model.Config `json:"target,omitempty"`
	// TargetAbsent means the operation removes the configuration (reset or
	// a rolled back init).
	TargetAbsent bool     `json:"target_absent,omitempty"`
	Interface    string   `json:"interface,omitempty"`
	Plan         []string `json:"plan,omitempty"`
}

// Journal appends records to a file.
type Journal struct {
	path string
	now  func() time.Time
}

// Open returns a journal at path.
func Open(path string, now func() time.Time) *Journal { return &Journal{path: path, now: now} }

const maxJournalSize = 4 << 20

// Append writes one record and fsyncs it.
func (j *Journal) Append(r Record) error {
	if r.Time.IsZero() {
		r.Time = j.now()
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	j.rotateIfNeeded()
	f, err := os.OpenFile(j.path, os.O_RDWR|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open journal: %w", err)
	}
	// A crash may have left a torn last line; start a new line so this
	// record is not glued to it (and lost with it).
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, st.Size()-1); err == nil && last[0] != '\n' {
			b = append([]byte{'\n'}, b...)
		}
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("write journal: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync journal: %w", err)
	}
	return f.Close()
}

// rotateIfNeeded keeps one previous generation. It is only called while
// the operation lock is held and never splits an open operation, because
// rotation happens before a begin record is written.
func (j *Journal) rotateIfNeeded() {
	st, err := os.Lstat(j.path)
	if err != nil || st.Size() < maxJournalSize {
		return
	}
	if inc, _ := j.Incomplete(); inc != nil {
		return
	}
	_ = os.Rename(j.path, j.path+".1")
	if d, err := os.Open(filepath.Dir(j.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// Read returns all records (current generation). A torn last line from a
// crash during append is ignored.
func (j *Journal) Read() ([]Record, error) {
	b, err := os.ReadFile(j.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			continue // torn write
		}
		out = append(out, r)
	}
	return out, nil
}

// Incomplete returns the begin record of the last operation that has no
// terminal record, or nil.
func (j *Journal) Incomplete() (*Record, error) {
	recs, err := j.Read()
	if err != nil {
		return nil, err
	}
	open := map[string]*Record{}
	var order []string
	for i := range recs {
		r := recs[i]
		switch r.Event {
		case EventBegin:
			rr := r
			open[r.OpID] = &rr
			order = append(order, r.OpID)
		case EventCommit, EventRolledBack, EventRecovered, EventSafeMode:
			delete(open, r.OpID)
		}
	}
	for i := len(order) - 1; i >= 0; i-- {
		if r, ok := open[order[i]]; ok {
			return r, nil
		}
	}
	return nil, nil
}

// Last returns the last n records (none for n <= 0).
func (j *Journal) Last(n int) ([]Record, error) {
	if n <= 0 {
		return nil, nil
	}
	recs, err := j.Read()
	if err != nil {
		return nil, err
	}
	if len(recs) > n {
		recs = recs[len(recs)-n:]
	}
	return recs, nil
}
