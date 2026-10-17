package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/nikitakiselev/meshly/internal/model"
)

const (
	maxConfigSize = 1 << 20
	keepHistory   = 20
)

// ErrNotInitialized means there is no saved configuration.
var ErrNotInitialized = errors.New("meshly is not initialized on this node")

// LoadConfig loads and validates the desired configuration.
func (p Paths) LoadConfig() (*model.Config, error) {
	b, err := ReadFile(p.ConfigFile(), 0o644, p.Owner, maxConfigSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	return DecodeConfig(b)
}

// DecodeConfig strictly decodes and validates a config document.
func DecodeConfig(b []byte) (*model.Config, error) {
	var c model.Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		// Never include file content in the error.
		return nil, fmt.Errorf("config is not valid JSON for schema %d: %s", model.ConfigSchemaVersion, sanitizeJSONErr(err))
	}
	// More() is false before a stray ']' or '}', so ask for the next token:
	// only io.EOF means the document ended cleanly.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("config has trailing data")
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config failed validation: %w", err)
	}
	return &c, nil
}

// EncodeConfig renders a config deterministically.
func EncodeConfig(c *model.Config) ([]byte, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// SaveConfig validates and atomically writes the config, keeping a copy in
// the history directory.
func (p Paths) SaveConfig(c *model.Config) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("refusing to save invalid config: %w", err)
	}
	b, err := EncodeConfig(c)
	if err != nil {
		return err
	}
	if err := WriteAtomic(p.HistoryFile(c.Revision), b, 0o600); err != nil {
		return fmt.Errorf("write history: %w", err)
	}
	if err := WriteAtomic(p.ConfigFile(), b, 0o644); err != nil {
		return err
	}
	p.pruneHistory()
	return nil
}

// RemoveConfig deletes the config (used by reset and rollback of init).
func (p Paths) RemoveConfig() error {
	err := os.Remove(p.ConfigFile())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return SyncDir(p.ConfigDir)
}

func (p Paths) pruneHistory() {
	entries, err := os.ReadDir(p.HistoryDir())
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "meshly-") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keepHistory {
		return
	}
	sort.Slice(names, func(i, j int) bool { return revOf(names[i]) < revOf(names[j]) })
	for _, n := range names[:len(names)-keepHistory] {
		_ = os.Remove(p.HistoryDir() + "/" + n)
	}
}

func revOf(name string) uint64 {
	var r uint64
	fmt.Sscanf(name, "meshly-%d.json", &r)
	return r
}

// sanitizeJSONErr strips anything that could quote file content.
func sanitizeJSONErr(err error) string {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Sprintf("syntax error at offset %d", se.Offset)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Sprintf("wrong type for field %q", te.Field)
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field ") {
		return msg
	}
	return "invalid document"
}
