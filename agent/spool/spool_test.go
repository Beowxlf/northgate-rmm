package spool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const testID = "123e4567-e89b-42d3-a456-426614174000"

func TestQueueRoundTripAndAcknowledge(t *testing.T) {
	directory := t.TempDir()
	queue, err := Open(directory, 1<<20)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer queue.Close()
	payload := []byte(`{"type":"inventory"}`)
	if err := queue.Enqueue(context.Background(), testID, payload); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	got, err := queue.Read(context.Background(), testID)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("Read() = %q, want %q", got, payload)
	}
	if err := queue.Enqueue(context.Background(), testID, payload); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate Enqueue() error = %v", err)
	}
	if err := queue.Acknowledge(context.Background(), testID); err != nil {
		t.Fatalf("Acknowledge() error = %v", err)
	}
	if _, err := queue.Read(context.Background(), testID); err == nil {
		t.Fatal("Read() found acknowledged item")
	}
}

func TestAcknowledgeExposesUncertainDeletionOutcome(t *testing.T) {
	directory := t.TempDir()
	queue, err := Open(directory, 1<<20)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer queue.Close()
	if err := queue.Enqueue(context.Background(), testID, []byte(`{"type":"inventory"}`)); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	syncFailure := errors.New("injected directory sync failure")
	queue.sync = func(*os.Root) error { return syncFailure }
	err = queue.Acknowledge(context.Background(), testID)
	var uncertain *AcknowledgeUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("Acknowledge() error = %v, want AcknowledgeUncertainError", err)
	}
	if uncertain.ID != testID || !errors.Is(err, syncFailure) {
		t.Fatalf("Acknowledge() uncertainty = %#v, want ID %s and injected cause", uncertain, testID)
	}
	if _, statErr := os.Stat(filepath.Join(directory, testID+".json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("acknowledged item remains visible: %v", statErr)
	}
}

func TestQueueDetectsCorruption(t *testing.T) {
	directory := t.TempDir()
	queue, err := Open(directory, 1<<20)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer queue.Close()
	if err := queue.Enqueue(context.Background(), testID, []byte("original")); err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	name := filepath.Join(directory, testID+".json")
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	raw[len(raw)-2] ^= 1
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := queue.Read(context.Background(), testID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Read() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenFailsClosedOnTemporaryOrUnknownEntry(t *testing.T) {
	for _, name := range []string{"abandoned.tmp", "notes.txt"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, name), []byte("x"), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := Open(directory, 1<<20); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open() error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestOpenFailsClosedOnCorruptExistingRecord(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, testID+".json")
	if err := os.WriteFile(name, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory, 1<<20); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestOpenRejectsSecondQueueHandle(t *testing.T) {
	directory := t.TempDir()
	first, err := Open(directory, 1<<20)
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	defer first.Close()
	if _, err := Open(directory, 1<<20); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open() error = %v, want ErrLocked", err)
	}
}

func TestOpenRejectsDuplicateRecordKeys(t *testing.T) {
	directory := t.TempDir()
	name := filepath.Join(directory, testID+".json")
	raw := `{"schema_version":1,"schema_version":1,"id":"123e4567-e89b-42d3-a456-426614174000","created_at":"2026-08-30T12:00:00Z","payload":"eA==","sha256":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}`
	if err := os.WriteFile(name, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory, 1<<20); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestQueueRejectsOversizedPayloadAndCancelledContext(t *testing.T) {
	queue, err := Open(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer queue.Close()
	if err := queue.Enqueue(context.Background(), testID, make([]byte, MaxPayloadBytes+1)); err == nil {
		t.Fatal("Enqueue() accepted oversized payload")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := queue.Enqueue(ctx, testID, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Enqueue() error = %v, want context.Canceled", err)
	}
}

func TestQueueFailsClosedAtQuota(t *testing.T) {
	queue, err := Open(t.TempDir(), maxRecordBytes)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer queue.Close()
	payload := make([]byte, 60_000)
	if err := queue.Enqueue(context.Background(), testID, payload); err != nil {
		t.Fatalf("first Enqueue() error = %v", err)
	}
	secondID := "123e4567-e89b-42d3-a456-426614174001"
	if err := queue.Enqueue(context.Background(), secondID, payload); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second Enqueue() error = %v, want ErrQuotaExceeded", err)
	}
}

func TestOpenRejectsFilesystemRootBeforePermissionChange(t *testing.T) {
	root := filepath.Clean(filepath.VolumeName(t.TempDir()) + string(os.PathSeparator))
	if _, err := Open(root, 1<<20); err == nil {
		t.Fatal("Open() accepted the filesystem root")
	}
}

func TestOpenRejectsSymlinkQueueDirectory(t *testing.T) {
	parent := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(parent, "queue")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, err := Open(link, 1<<20); err == nil {
		t.Fatal("Open() accepted a symlink queue directory")
	}
}
