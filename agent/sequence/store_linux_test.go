//go:build linux

package sequence

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type fileInfoWithStat struct {
	fs.FileInfo
	stat *syscall.Stat_t
}

func (info fileInfoWithStat) Sys() any { return info.stat }

func TestOpenRejectsNonEmptyLockFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".lock"), []byte("unexpected"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsPublicLockFilePermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".lock"), nil, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsPublicStatePermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	store, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := store.Reserve(t.Context(), testBootID); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := os.Chmod(filepath.Join(directory, stateName), 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsPublicDirectoryPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if _, err := Open(directory); err == nil {
		t.Fatal("Open() accepted public directory permissions")
	}
}

func TestPrivacyPredicatesRejectDifferentOwner(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("Stat() did not return syscall.Stat_t")
	}
	other := *stat
	other.Uid++
	wrapped := fileInfoWithStat{FileInfo: info, stat: &other}
	if privateDirectory(wrapped) || privateFile(wrapped) {
		t.Fatal("privacy predicates accepted a different effective owner")
	}
}

func TestParentPredicateRejectsDifferentOwner(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("Stat() did not return syscall.Stat_t")
	}
	other := *stat
	other.Uid = 1
	if other.Uid == uint32(os.Geteuid()) {
		other.Uid = 2
	}
	wrapped := fileInfoWithStat{FileInfo: info, stat: &other}
	if protectedParentInfo(wrapped) {
		t.Fatal("parent predicate accepted an untrusted owner")
	}
}

func TestOpenRejectsWritableNonStickyParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "writable-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := Open(filepath.Join(parent, "sequence")); err == nil {
		t.Fatal("Open() accepted a writable non-sticky parent")
	}
}

func TestOpenRejectsSymlinkInParentChain(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	linkedParent := filepath.Join(base, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Skipf("Symlink() unavailable: %v", err)
	}
	if _, err := Open(filepath.Join(linkedParent, "sequence")); err == nil {
		t.Fatal("Open() accepted a symlink in the parent chain")
	}
}

func TestOpenRejectsMultiplyLinkedState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	store, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := store.Reserve(t.Context(), testBootID); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := os.Link(filepath.Join(directory, stateName), filepath.Join(t.TempDir(), "linked-state")); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsMultiplyLinkedLock(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	lock := filepath.Join(directory, ".lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Link(lock, filepath.Join(t.TempDir(), "linked-lock")); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}
