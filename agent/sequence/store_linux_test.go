//go:build linux

package sequence

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

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
