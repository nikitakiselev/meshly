package store

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// knownBug marks a check that documents a defect in production code. The
// test is skipped (not failed) while the defect is present so the suite
// stays green; once the code is fixed the check runs normally.
func knownBug(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("KNOWN BUG: "+format, args...)
}

func newPaths(t *testing.T) Paths {
	t.Helper()
	p := RootedPaths(t.TempDir(), os.Getuid())
	if err := p.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	return p
}

func permOf(t *testing.T, path string) fs.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
}

func writeFile(t *testing.T, path string, data string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestPaths(t *testing.T) {
	d := DefaultPaths()
	if d.ConfigFile() != "/etc/meshly/meshly.json" || d.WGKeyFile() != "/etc/meshly/keys/wireguard.key" ||
		d.IdentityFile() != "/etc/meshly/keys/identity.key" || d.BootstrapFile() != "/var/lib/meshly/bootstrap.json" ||
		d.JournalFile() != "/var/lib/meshly/journal.jsonl" || d.LockFile() != "/run/meshly/lock" ||
		d.RuntimeFile() != "/var/lib/meshly/runtime.json" || d.HistoryFile(42) != "/var/lib/meshly/history/meshly-42.json" ||
		d.Owner != 0 {
		t.Errorf("unexpected default paths: %+v", d)
	}
	r := RootedPaths("/tmp/x", 1234)
	if r.ConfigDir != "/tmp/x/etc/meshly" || r.KeysDir != "/tmp/x/etc/meshly/keys" || r.StateDir != "/tmp/x/var/lib/meshly" ||
		r.RuntimeDir != "/tmp/x/run/meshly" || r.Owner != 1234 || r.HistoryDir() != "/tmp/x/var/lib/meshly/history" {
		t.Errorf("unexpected rooted paths: %+v", r)
	}
}

func TestEnsureDirs(t *testing.T) {
	p := newPaths(t)
	for _, d := range []struct {
		path string
		max  fs.FileMode
	}{
		{p.ConfigDir, 0o755}, {p.KeysDir, 0o700}, {p.StateDir, 0o700}, {p.HistoryDir(), 0o700}, {p.RuntimeDir, 0o700},
	} {
		st, err := os.Lstat(d.path)
		if err != nil {
			t.Fatal(err)
		}
		if !st.IsDir() {
			t.Errorf("%s is not a directory", d.path)
		}
		if perm := permOf(t, d.path); perm&^d.max != 0 || perm&0o700 != 0o700 {
			t.Errorf("%s has mode %04o, want at most %04o", d.path, perm, d.max)
		}
	}
	if perm := permOf(t, p.KeysDir); perm != 0o700 {
		t.Errorf("keys dir mode %04o, want 0700", perm)
	}
	// Idempotent.
	if err := p.EnsureDirs(); err != nil {
		t.Errorf("second EnsureDirs: %v", err)
	}
}

func TestEnsureDirsRefusesInsecure(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, p Paths)
	}{
		{"world-writable config dir", func(t *testing.T, p Paths) { must(t, os.Chmod(p.ConfigDir, 0o777)) }},
		{"group-readable keys dir", func(t *testing.T, p Paths) { must(t, os.Chmod(p.KeysDir, 0o750)) }},
		{"sticky state dir", func(t *testing.T, p Paths) { must(t, os.Chmod(p.StateDir, 0o700|fs.ModeSticky)) }},
		{"keys dir is a symlink", func(t *testing.T, p Paths) {
			real := filepath.Join(filepath.Dir(p.ConfigDir), "real-keys")
			must(t, os.Mkdir(real, 0o700))
			must(t, os.Remove(p.KeysDir))
			must(t, os.Symlink(real, p.KeysDir))
		}},
		{"runtime dir is a file", func(t *testing.T, p Paths) {
			must(t, os.Remove(p.RuntimeDir))
			writeFile(t, p.RuntimeDir, "x", 0o600)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPaths(t)
			tt.setup(t, p)
			if err := p.EnsureDirs(); !errors.Is(err, ErrInsecure) {
				t.Errorf("EnsureDirs = %v, want ErrInsecure", err)
			}
		})
	}
}

func TestEnsureDirsWrongOwner(t *testing.T) {
	p := RootedPaths(t.TempDir(), os.Getuid()+1)
	err := p.EnsureDirs()
	if !errors.Is(err, ErrInsecure) || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("EnsureDirs = %v, want ownership error", err)
	}
}

func TestCheckDirMissing(t *testing.T) {
	err := CheckDir(filepath.Join(t.TempDir(), "nope"), 0o700, os.Getuid())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("CheckDir(missing) = %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadFile(t *testing.T) {
	uid := os.Getuid()
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeFile(t, path, "hello", 0o600)

	b, err := ReadFile(path, 0o600, uid, 1024)
	if err != nil || string(b) != "hello" {
		t.Fatalf("ReadFile = %q, %v", b, err)
	}
	// A stricter mode than the maximum is fine.
	must(t, os.Chmod(path, 0o400))
	if _, err := ReadFile(path, 0o600, uid, 1024); err != nil {
		t.Errorf("0400 file refused: %v", err)
	}
	// Exactly maxSize is fine.
	if _, err := ReadFile(path, 0o600, uid, 5); err != nil {
		t.Errorf("file of exactly maxSize refused: %v", err)
	}

	link := filepath.Join(dir, "link")
	must(t, os.Symlink(path, link))
	sub := filepath.Join(dir, "sub")
	must(t, os.Mkdir(sub, 0o700))

	tests := []struct {
		name     string
		path     string
		mode     fs.FileMode // applied to path before reading (0: unchanged)
		maxMode  fs.FileMode
		owner    int
		maxSize  int64
		insecure bool
		notExist bool
	}{
		{name: "symlink", path: link, maxMode: 0o600, owner: uid, maxSize: 1024, insecure: true},
		{name: "directory", path: sub, maxMode: 0o777, owner: uid, maxSize: 1024, insecure: true},
		{name: "group writable", path: path, mode: 0o620, maxMode: 0o644, owner: uid, maxSize: 1024, insecure: true},
		{name: "world writable", path: path, mode: 0o602, maxMode: 0o644, owner: uid, maxSize: 1024, insecure: true},
		{name: "world readable secret", path: path, mode: 0o644, maxMode: 0o600, owner: uid, maxSize: 1024, insecure: true},
		{name: "executable", path: path, mode: 0o700, maxMode: 0o600, owner: uid, maxSize: 1024, insecure: true},
		{name: "setuid", path: path, mode: 0o600 | fs.ModeSetuid, maxMode: 0o600, owner: uid, maxSize: 1024, insecure: true},
		{name: "wrong owner", path: path, mode: 0o600, maxMode: 0o600, owner: uid + 1, maxSize: 1024, insecure: true},
		{name: "too large", path: path, mode: 0o600, maxMode: 0o600, owner: uid, maxSize: 4},
		{name: "missing", path: filepath.Join(dir, "missing"), maxMode: 0o600, owner: uid, maxSize: 1024, notExist: true},
	}
	for _, tt := range tests {
		if tt.mode != 0 {
			must(t, os.Chmod(tt.path, tt.mode))
		}
		_, err := ReadFile(tt.path, tt.maxMode, tt.owner, tt.maxSize)
		switch {
		case err == nil:
			t.Errorf("%s: ReadFile succeeded", tt.name)
		case tt.insecure && !errors.Is(err, ErrInsecure):
			t.Errorf("%s: ReadFile = %v, want ErrInsecure", tt.name, err)
		case tt.notExist && !errors.Is(err, fs.ErrNotExist):
			t.Errorf("%s: ReadFile = %v, want ErrNotExist", tt.name, err)
		case !tt.insecure && !tt.notExist && errors.Is(err, ErrInsecure):
			t.Errorf("%s: unexpected ErrInsecure: %v", tt.name, err)
		}
		if err != nil && strings.Contains(err.Error(), "hello") {
			t.Errorf("%s: error echoes file content: %v", tt.name, err)
		}
	}
}

func TestReadUntrusted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg")
	writeFile(t, path, "SECRET-CONTENT", 0o644)

	b, err := ReadUntrusted(path, 1024)
	if err != nil || string(b) != "SECRET-CONTENT" {
		t.Fatalf("ReadUntrusted = %q, %v", b, err)
	}
	if _, err := ReadUntrusted(path, 4); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("oversized file: %v", err)
	}

	link := filepath.Join(dir, "link")
	must(t, os.Symlink(path, link))
	if _, err := ReadUntrusted(link, 1024); !errors.Is(err, ErrInsecure) {
		t.Errorf("symlink: %v, want ErrInsecure", err)
	}
	if _, err := ReadUntrusted(dir, 1024); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory: %v", err)
	}
	if _, err := ReadUntrusted(filepath.Join(dir, "missing"), 1024); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}

	// A FIFO must be refused without blocking on open.
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadUntrusted(fifo, 1024); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadUntrusted blocked on a FIFO")
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.json")
	for _, mode := range []fs.FileMode{0o600, 0o644, 0o640} {
		data := []byte("content " + mode.String())
		if err := WriteAtomic(path, data, mode); err != nil {
			t.Fatalf("WriteAtomic(%v): %v", mode, err)
		}
		if got := readString(t, path); got != string(data) {
			t.Errorf("content = %q", got)
		}
		if got := permOf(t, path); got != mode {
			t.Errorf("mode = %04o, want %04o", got, mode)
		}
	}
	if names := dirNames(t, dir); len(names) != 1 || names[0] != "file.json" {
		t.Errorf("temporary files left behind: %v", names)
	}
	// Empty content is allowed.
	if err := WriteAtomic(path, nil, 0o600); err != nil || readString(t, path) != "" {
		t.Errorf("empty write: %v", err)
	}
}

func TestWriteAtomicRefusesNonRegularTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "original", 0o600)
	link := filepath.Join(dir, "link")
	must(t, os.Symlink(victim, link))
	sub := filepath.Join(dir, "sub")
	must(t, os.Mkdir(sub, 0o700))

	for _, target := range []string{link, sub} {
		if err := WriteAtomic(target, []byte("evil"), 0o600); !errors.Is(err, ErrInsecure) {
			t.Errorf("WriteAtomic(%s) = %v, want ErrInsecure", filepath.Base(target), err)
		}
	}
	if got := readString(t, victim); got != "original" {
		t.Errorf("symlink target modified: %q", got)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("symlink replaced: %v %v", st, err)
	}
	if names := dirNames(t, dir); len(names) != 3 {
		t.Errorf("temporary files left behind: %v", names)
	}
}

func TestWriteAtomicMissingDir(t *testing.T) {
	if err := WriteAtomic(filepath.Join(t.TempDir(), "no", "file"), []byte("x"), 0o600); err == nil {
		t.Error("WriteAtomic into a missing directory succeeded")
	}
}

func TestWriteOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invite.txt")

	if err := WriteOutput(path, []byte("first"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != "first" {
		t.Fatalf("content = %q", got)
	}
	if got := permOf(t, path); got != 0o600 {
		t.Errorf("mode = %04o", got)
	}

	// Same content: idempotent, with or without force.
	for _, force := range []bool{false, true} {
		if err := WriteOutput(path, []byte("first"), 0o600, force); err != nil {
			t.Errorf("identical re-run (force=%v): %v", force, err)
		}
	}

	// Different content without force: ErrExists, file untouched.
	err := WriteOutput(path, []byte("second"), 0o600, false)
	if !errors.Is(err, ErrExists) {
		t.Errorf("different content = %v, want ErrExists", err)
	}
	if err != nil && strings.Contains(err.Error(), "second") {
		t.Errorf("error echoes content: %v", err)
	}
	if got := readString(t, path); got != "first" {
		t.Errorf("file modified without force: %q", got)
	}

	// With force the regular file is replaced.
	if err := WriteOutput(path, []byte("second"), 0o600, true); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != "second" {
		t.Errorf("forced content = %q", got)
	}
}

func TestWriteOutputRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, "original", 0o600)
	link := filepath.Join(dir, "link")
	must(t, os.Symlink(victim, link))
	dangling := filepath.Join(dir, "dangling")
	ghost := filepath.Join(dir, "ghost")
	must(t, os.Symlink(ghost, dangling))
	sub := filepath.Join(dir, "sub")
	must(t, os.Mkdir(sub, 0o700))

	for _, target := range []string{link, dangling, sub} {
		for _, force := range []bool{false, true} {
			if err := WriteOutput(target, []byte("evil"), 0o600, force); !errors.Is(err, ErrInsecure) {
				t.Errorf("WriteOutput(%s, force=%v) = %v, want ErrInsecure", filepath.Base(target), force, err)
			}
		}
	}
	if got := readString(t, victim); got != "original" {
		t.Errorf("symlink target modified: %q", got)
	}
	if _, err := os.Lstat(ghost); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("dangling symlink target was created: %v", err)
	}
}

func TestSyncDir(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Error(err)
	}
	if err := SyncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("SyncDir(missing) succeeded")
	}
}

func TestReadBounded(t *testing.T) {
	if b, err := readBounded(bytes.NewReader([]byte("12345")), 5); err != nil || string(b) != "12345" {
		t.Errorf("readBounded(5) = %q, %v", b, err)
	}
	if _, err := readBounded(bytes.NewReader([]byte("123456")), 5); err == nil {
		t.Error("readBounded accepted 6 bytes with max 5")
	}
}
