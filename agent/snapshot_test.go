package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/collector"
)

type memoryQueue struct {
	id      string
	payload []byte
	err     error
}

type memorySequenceStore struct {
	next int64
	err  error
}

func (store *memorySequenceStore) Reserve(_ context.Context, _ string) (int64, error) {
	if store.err != nil {
		return 0, store.err
	}
	store.next++
	return store.next, nil
}

func (queue *memoryQueue) Enqueue(_ context.Context, id string, payload []byte) error {
	if queue.err != nil {
		return queue.err
	}
	queue.id = id
	queue.payload = append([]byte(nil), payload...)
	return nil
}

type syntheticSource struct {
	diskError error
}

func (syntheticSource) ReadFile(_ context.Context, name string, _ int64) ([]byte, error) {
	switch name {
	case "/etc/os-release":
		return []byte("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n"), nil
	case "/proc/sys/kernel/random/boot_id":
		return []byte("123e4567-e89b-42d3-a456-426614174000\n"), nil
	default:
		return nil, errors.New("unexpected synthetic path")
	}
}

func (syntheticSource) Hostname(context.Context) (string, error) { return "synthetic", nil }
func (syntheticSource) Platform() string                         { return "linux" }
func (syntheticSource) Architecture() string                     { return "amd64" }
func (source syntheticSource) DiskUsage(context.Context, string) (collector.DiskUsage, error) {
	return collector.DiskUsage{TotalBytes: 10 << 30, FreeBytes: 4 << 30}, source.diskError
}

func TestSnapshotQueuesPhaseOneCompatibleInventory(t *testing.T) {
	runner, err := collector.NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	queue := &memoryQueue{}
	snapshotter, err := NewSnapshotter(runner, queue, &memorySequenceStore{})
	if err != nil {
		t.Fatalf("NewSnapshotter() error = %v", err)
	}
	ids := []string{
		"123e4567-e89b-42d3-a456-426614174001",
		"123e4567-e89b-42d3-a456-426614174002",
	}
	snapshotter.newID = func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	snapshotter.clock = func() time.Time {
		return time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	}
	result, err := snapshotter.Snapshot(
		context.Background(),
		"123e4567-e89b-42d3-a456-426614174003",
		syntheticSource{},
	)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if queue.id != result.MessageID || result.Sequence != 1 || result.Bytes != len(queue.payload) || !result.Complete {
		t.Fatalf("unexpected snapshot result: %#v", result)
	}
	var message map[string]any
	if err := json.Unmarshal(queue.payload, &message); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if message["type"] != "inventory" {
		t.Fatalf("unexpected queued message: %s", queue.payload)
	}
	envelope, ok := message["envelope"].(map[string]any)
	if !ok || envelope["sequence"] != float64(result.Sequence) {
		t.Fatalf("queued sequence does not match reservation: %s", queue.payload)
	}
}

func TestSnapshotPreservesPartialCollectionState(t *testing.T) {
	runner, err := collector.NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	queue := &memoryQueue{}
	snapshotter, err := NewSnapshotter(runner, queue, &memorySequenceStore{})
	if err != nil {
		t.Fatalf("NewSnapshotter() error = %v", err)
	}
	result, err := snapshotter.Snapshot(
		context.Background(),
		"123e4567-e89b-42d3-a456-426614174003",
		syntheticSource{diskError: errors.New("synthetic disk failure")},
	)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if result.Complete || len(result.Issues) != 1 || result.Issues[0].Code != "read_failed" {
		t.Fatalf("unexpected partial result: %#v", result)
	}
}

func TestNewUUIDProducesCanonicalVersionFourID(t *testing.T) {
	id, err := newUUID()
	if err != nil {
		t.Fatalf("newUUID() error = %v", err)
	}
	if len(id) != 36 || id[14] != '4' || (id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b') {
		t.Fatalf("newUUID() = %q", id)
	}
}

func TestSnapshotPreservesMessageIDOnQueueFailure(t *testing.T) {
	runner, err := collector.NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	queue := &memoryQueue{err: errors.New("synthetic queue failure")}
	snapshotter, err := NewSnapshotter(runner, queue, &memorySequenceStore{})
	if err != nil {
		t.Fatalf("NewSnapshotter() error = %v", err)
	}
	wantID := "123e4567-e89b-42d3-a456-426614174001"
	ids := []string{wantID, "123e4567-e89b-42d3-a456-426614174002"}
	snapshotter.newID = func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	result, err := snapshotter.Snapshot(
		context.Background(),
		"123e4567-e89b-42d3-a456-426614174003",
		syntheticSource{},
	)
	if err == nil || result.MessageID != wantID {
		t.Fatalf("Snapshot() result = %#v, error = %v", result, err)
	}
}

func TestSnapshotFailsBeforeMessageCreationWhenSequenceReservationFails(t *testing.T) {
	runner, err := collector.NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	sequenceFailure := errors.New("synthetic sequence failure")
	snapshotter, err := NewSnapshotter(
		runner,
		&memoryQueue{},
		&memorySequenceStore{err: sequenceFailure},
	)
	if err != nil {
		t.Fatalf("NewSnapshotter() error = %v", err)
	}
	result, err := snapshotter.Snapshot(
		context.Background(),
		"123e4567-e89b-42d3-a456-426614174003",
		syntheticSource{},
	)
	if !errors.Is(err, sequenceFailure) || result.MessageID != "" || result.Sequence != 0 ||
		result.Complete || len(result.Issues) != 0 || result.Bytes != 0 {
		t.Fatalf("Snapshot() result = %#v, error = %v", result, err)
	}
}
