package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// InviteMarker tells other meshly processes that `meshly invite` is
// waiting. It never holds the code or anything derived from it.
type InviteMarker struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// InviteFile is the marker of an open invite (0600, cleared at boot with
// the rest of RuntimeDir).
func (p Paths) InviteFile() string { return filepath.Join(p.RuntimeDir, "invite.json") }

// SaveInviteMarker records an open invite.
func (p Paths) SaveInviteMarker(m InviteMarker) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return WriteAtomic(p.InviteFile(), append(b, '\n'), 0o600)
}

// LoadInviteMarker reads the marker; the error wraps fs.ErrNotExist when
// there is none.
func (p Paths) LoadInviteMarker() (*InviteMarker, error) {
	b, err := ReadFile(p.InviteFile(), 0o600, p.Owner, 4096)
	if err != nil {
		return nil, err
	}
	var m InviteMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("invite marker %s is corrupted", p.InviteFile())
	}
	return &m, nil
}

// RemoveInviteMarker deletes the marker (none is not an error).
func (p Paths) RemoveInviteMarker() error {
	if err := os.Remove(p.InviteFile()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
