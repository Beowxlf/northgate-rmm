package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
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

type observingSequenceStore struct {
	mu             sync.Mutex
	next           int64
	secondReserved chan struct{}
}

func (store *observingSequenceStore) ReserveAndUse(
	_ context.Context,
	_ string,
	use func(int64) error,
) (int64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.next++
	if store.next == 2 {
		close(store.secondReserved)
	}
	return store.next, use(store.next)
}

type firstBlockingQueue struct {
	mu           sync.Mutex
	calls        int
	firstEntered chan struct{}
	releaseFirst chan struct{}
}

func (queue *firstBlockingQueue) Enqueue(ctx context.Context, _ string, _ []byte) error {
	queue.mu.Lock()
	queue.calls++
	first := queue.calls == 1
	queue.mu.Unlock()
	if !first {
		return nil
	}
	close(queue.firstEntered)
	select {
	case <-queue.releaseFirst:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (store *memorySequenceStore) ReserveAndUse(
	_ context.Context,
	_ string,
	use func(int64) error,
) (int64, error) {
	if store.err != nil {
		return 0, store.err
	}
	store.next++
	return store.next, use(store.next)
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

func TestSnapshotSerializesSequenceReservationAcrossSnapshottersThroughEnqueue(t *testing.T) {
	runner, err := collector.NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	queue := &firstBlockingQueue{
		firstEntered: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	sequences := &observingSequenceStore{secondReserved: make(chan struct{})}
	snapshotter, err := NewSnapshotter(runner, queue, sequences)
	if err != nil {
		t.Fatalf("NewSnapshotter() error = %v", err)
	}
	secondSnapshotter, err := NewSnapshotter(runner, queue, sequences)
	if err != nil {
		t.Fatalf("second NewSnapshotter() error = %v", err)
	}
	results := make(chan error, 2)
	go func() {
		_, err := secondSnapshotter.Snapshot(
			context.Background(),
			"123e4567-e89b-42d3-a456-426614174003",
			syntheticSource{},
		)
		results <- err
	}()
	select {
	case <-queue.firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first snapshot did not reach queue")
	}
	go func() {
		_, err := snapshotter.Snapshot(
			context.Background(),
			"123e4567-e89b-42d3-a456-426614174003",
			syntheticSource{},
		)
		results <- err
	}()
	select {
	case <-sequences.secondReserved:
		t.Fatal("second sequence was reserved before the first enqueue completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(queue.releaseFirst)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("Snapshot() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent snapshots did not finish")
		}
	}
}
