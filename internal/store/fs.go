// Package store persists Meshly configuration and secrets as versioned files
// with atomic, fsync'ed replacement and strict ownership/permission checks.
package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// Paths lists every location Meshly touches. Production code uses
// DefaultPaths; tests use a temporary root.
type Paths struct {
	ConfigDir  string // /etc/meshly            (0755, root)
	KeysDir    string // /etc/meshly/keys       (0700, root)
	StateDir   string // /var/lib/meshly        (0700, root)
	RuntimeDir string // /run/meshly            (0700, root)
	// Owner is the uid that must own every managed file (0 in production).
	Owner int
}

// DefaultPaths are the production locations.
func DefaultPaths() Paths {
	return Paths{
		ConfigDir:  "/etc/meshly",
		KeysDir:    "/etc/meshly/keys",
		StateDir:   "/var/lib/meshly",
		RuntimeDir: "/run/meshly",
		Owner:      0,
	}
}

// RootedPaths places all directories under root (for tests).
func RootedPaths(root string, owner int) Paths {
	return Paths{
		ConfigDir:  filepath.Join(root, "etc/meshly"),
		KeysDir:    filepath.Join(root, "etc/meshly/keys"),
		StateDir:   filepath.Join(root, "var/lib/meshly"),
		RuntimeDir: filepath.Join(root, "run/meshly"),
		Owner:      owner,
	}
}

func (p Paths) ConfigFile() string  { return filepath.Join(p.ConfigDir, "meshly.json") }
func (p Paths) WGKeyFile() string   { return filepath.Join(p.KeysDir, "wireguard.key") }
func (p Paths) JournalFile() string { return filepath.Join(p.StateDir, "journal.jsonl") }
func (p Paths) HistoryDir() string  { return filepath.Join(p.StateDir, "history") }
func (p Paths) LockFile() string    { return filepath.Join(p.RuntimeDir, "lock") }
func (p Paths) RuntimeFile() string { return filepath.Join(p.StateDir, "runtime.json") }
func (p Paths) HistoryFile(rev uint64) string {
	return filepath.Join(p.HistoryDir(), "meshly-"+strconv.FormatUint(rev, 10)+".json")
}

// ErrInsecure reports wrong ownership, permissions or file type.
var ErrInsecure = errors.New("insecure file or directory")

// ErrExists means an output file exists with other content.
var ErrExists = errors.New("output file exists")

// EnsureDirs creates the managed directories with the required modes and
// verifies existing ones.
func (p Paths) EnsureDirs() error {
	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{
		{p.ConfigDir, 0o755},
		{p.KeysDir, 0o700},
		{p.StateDir, 0o700},
		{p.HistoryDir(), 0o700},
		{p.RuntimeDir, 0o700},
	} {
		if err := ensureDir(d.path, d.mode, p.Owner); err != nil {
			return err
		}
	}
	return nil
}

// EnsureRuntimeDir creates the runtime directory, which holds the lock. It
// is empty after every boot until meshly runs.
func (p Paths) EnsureRuntimeDir() error { return ensureDir(p.RuntimeDir, 0o700, p.Owner) }

func ensureDir(path string, mode fs.FileMode, owner int) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		} else {
			return err
		}
	}
	return CheckDir(path, mode, owner)
}

// CheckDir verifies a managed directory: real directory (not a symlink),
// owned by owner, no permission bits beyond mode, never group/world
// writable.
func CheckDir(path string, mode fs.FileMode, owner int) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return &fs.PathError{Op: "lstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: %s is not a directory (symlinks are refused)", ErrInsecure, path)
	}
	if int(st.Uid) != owner {
		return fmt.Errorf("%w: %s is owned by uid %d, expected %d", ErrInsecure, path, st.Uid, owner)
	}
	perm := fs.FileMode(st.Mode & 0o7777)
	if perm&^mode != 0 || perm&0o022 != 0 {
		return fmt.Errorf("%w: %s has mode %04o, expected at most %04o", ErrInsecure, path, perm, mode)
	}
	return nil
}

// ReadFile reads a managed file: refuses symlinks and non-regular files,
// checks owner and maximum permissions, bounds the size.
func ReadFile(path string, maxMode fs.FileMode, owner int, maxSize int64) ([]byte, error) {
	// O_NONBLOCK: a FIFO planted at the path must not hang meshly; it is
	// then refused as not a regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrInsecure, path)
		}
		return nil, err
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInsecure, path)
	}
	if int(st.Uid) != owner {
		return nil, fmt.Errorf("%w: %s is owned by uid %d, expected %d", ErrInsecure, path, st.Uid, owner)
	}
	if perm := fs.FileMode(st.Mode & 0o7777); perm&^maxMode != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o, expected at most %04o", ErrInsecure, path, perm, maxMode)
	}
	if st.Size > maxSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxSize)
	}
	return readBounded(f, maxSize)
}

func readBounded(r io.Reader, maxSize int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxSize {
		return nil, fmt.Errorf("input is larger than %d bytes", maxSize)
	}
	return b, nil
}

// WriteAtomic replaces path with data: temp file in the same directory,
// fsync, rename, fsync of the directory. The directory must already be a
// verified managed directory.
func WriteAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	// Refuse to replace a symlink or directory planted at the target.
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		cleanup()
		return fmt.Errorf("%w: %s exists and is not a regular file", ErrInsecure, path)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so a completed rename survives power loss.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Now is the clock used for timestamps (overridable in tests).
var Now = func() time.Time { return time.Now().UTC().Truncate(time.Second) }
