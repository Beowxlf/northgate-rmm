//go:build linux

package spool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRejectsNonEmptyLockFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, ".lock"), []byte("unexpected"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory, 1<<20); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsPublicRecordPermissions(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, testID+".json")
	if err := os.WriteFile(name, []byte("not-json"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory, 1<<20); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}
