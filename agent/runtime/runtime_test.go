package runtime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	agentcore "github.com/Beowxlf/northgate-rmm/agent"
	"github.com/Beowxlf/northgate-rmm/agent/collector"
	"github.com/Beowxlf/northgate-rmm/agent/eventlog"
	"github.com/Beowxlf/northgate-rmm/agent/protocol"
	"github.com/Beowxlf/northgate-rmm/agent/spool"
	"github.com/Beowxlf/northgate-rmm/agent/transport"
)

const testMessageID = "123e4567-e89b-42d3-a456-426614174000"

var testNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type memoryQueue struct {
	mu       sync.Mutex
	ids      []string
	payload  map[string][]byte
	rejected []string
	evicted  []string
}

func (queue *memoryQueue) ListIDs(context.Context) ([]string, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return append([]string(nil), queue.ids...), nil
}

func (queue *memoryQueue) Read(_ context.Context, id string) ([]byte, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return append([]byte(nil), queue.payload[id]...), nil
}

func (queue *memoryQueue) Acknowledge(_ context.Context, id string) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	delete(queue.payload, id)
	for index, candidate := range queue.ids {
		if candidate == id {
			queue.ids = append(queue.ids[:index], queue.ids[index+1:]...)
			break
		}
	}
	return nil
}

func (queue *memoryQueue) Quarantine(ctx context.Context, id string) (spool.QuarantineResult, error) {
	if err := queue.Acknowledge(ctx, id); err != nil {
		return spool.QuarantineResult{}, err
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.rejected = append(queue.rejected, id)
	return spool.QuarantineResult{EvictedIDs: append([]string(nil), queue.evicted...)}, nil
}

type fixedSnapshotter struct {
	result agentcore.SnapshotResult
	cancel context.CancelFunc
}

func (snapshotter fixedSnapshotter) Snapshot(
	context.Context, string, collector.Source,
) (agentcore.SnapshotResult, error) {
	if snapshotter.cancel != nil {
		snapshotter.cancel()
	}
	return snapshotter.result, nil
}

type fixedSender struct {
	err     error
	mu      sync.Mutex
	deliver []string
}

func (sender *fixedSender) Send(_ context.Context, id string, _ []byte) error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.deliver = append(sender.deliver, id)
	return sender.err
}

type rejectingSender struct {
	rejectID string
	deliver  []string
}

func (sender *rejectingSender) Send(_ context.Context, id string, _ []byte) error {
	sender.deliver = append(sender.deliver, id)
	if id == sender.rejectID {
		return &transport.DeliveryError{Code: "acknowledgement_rejected"}
	}
	return nil
}

type syntheticSource struct{}

func (syntheticSource) ReadFile(context.Context, string, int64) ([]byte, error) {
	return nil, errors.New("unused")
}
func (syntheticSource) Hostname(context.Context) (string, error) { return "unused", nil }
func (syntheticSource) Platform() string                         { return "linux" }
func (syntheticSource) Architecture() string                     { return "amd64" }
func (syntheticSource) DiskUsage(context.Context, string) (collector.DiskUsage, error) {
	return collector.DiskUsage{}, nil
}

func inventoryPayload(t *testing.T, id string, expires time.Time) []byte {
	t.Helper()
	raw, err := protocol.EncodeInventory(protocol.Envelope{
		MessageID: id, EndpointID: "123e4567-e89b-42d3-a456-426614174001",
		BootID: "123e4567-e89b-42d3-a456-426614174002", Sequence: 1,
		CreatedAt: expires.Add(-time.Minute), ExpiresAt: expires,
		CorrelationID: "123e4567-e89b-42d3-a456-426614174003", ProtocolVersion: protocol.Version,
	}, protocol.InventoryPayload{
		Platform: "linux", Architecture: "amd64", Fields: map[string]string{},
		CollectorComplete: true, SchemaVersion: protocol.InventorySchema,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRunDrainsQueueAndStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := &memoryQueue{ids: []string{testMessageID}, payload: map[string][]byte{testMessageID: inventoryPayload(t, testMessageID, testNow.Add(time.Minute))}}
	sender := &fixedSender{}
	var output bytes.Buffer
	logger, err := eventlog.New(&output)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := New(Options{
		EndpointID: "123e4567-e89b-42d3-a456-426614174001", CollectionInterval: time.Minute,
		RequestTimeout: time.Second, Snapshotter: fixedSnapshotter{
			result: agentcore.SnapshotResult{MessageID: testMessageID, Complete: true}, cancel: cancel,
		}, Queue: queue, Sender: sender, Source: syntheticSource{}, Logger: logger,
		RetryPolicy: transport.RetryPolicy{MaxAttempts: 1, InitialDelay: time.Second, MaximumDelay: time.Second},
		Now:         func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if len(sender.deliver) != 1 || sender.deliver[0] != testMessageID {
		t.Fatalf("unexpected deliveries: %v", sender.deliver)
	}
	if len(queue.ids) != 0 {
		t.Fatalf("acknowledged item remains queued: %v", queue.ids)
	}
	logs := output.String()
	for _, value := range []string{`"outcome":"started"`, `"outcome":"succeeded"`, `"outcome":"stopped"`} {
		if !strings.Contains(logs, value) {
			t.Fatalf("missing log %s in %s", value, logs)
		}
	}
}

func TestDeliveryFailurePreservesQueueAndRedactsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := &memoryQueue{ids: []string{testMessageID}, payload: map[string][]byte{testMessageID: inventoryPayload(t, testMessageID, testNow.Add(time.Minute))}}
	sender := &fixedSender{err: &transport.DeliveryError{Code: "tls_trust_failed"}}
	var output bytes.Buffer
	logger, _ := eventlog.New(&output)
	runtime, err := New(Options{
		EndpointID: "123e4567-e89b-42d3-a456-426614174001", CollectionInterval: time.Minute,
		RequestTimeout: time.Second, Snapshotter: fixedSnapshotter{
			result: agentcore.SnapshotResult{MessageID: testMessageID, Complete: true}, cancel: cancel,
		}, Queue: queue, Sender: sender, Source: syntheticSource{}, Logger: logger,
		RetryPolicy: transport.RetryPolicy{MaxAttempts: 1, InitialDelay: time.Second, MaximumDelay: time.Second},
		Now:         func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	if len(queue.ids) != 1 {
		t.Fatalf("rejected item was removed: %v", queue.ids)
	}
	logs := output.String()
	if !strings.Contains(logs, `"failure_class":"trust_failed"`) || strings.Contains(logs, "tls_trust_failed") {
		t.Fatalf("unexpected bounded log: %s", logs)
	}
}

func TestExpiredHeadIsQuarantinedAndDoesNotBlockNewerRecord(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	secondID := "123e4567-e89b-42d3-a456-426614174004"
	evictedID := "123e4567-e89b-42d3-a456-426614174005"
	queue := &memoryQueue{
		ids: []string{testMessageID, secondID},
		payload: map[string][]byte{
			testMessageID: inventoryPayload(t, testMessageID, testNow),
			secondID:      inventoryPayload(t, secondID, testNow.Add(time.Minute)),
		}, evicted: []string{evictedID},
	}
	sender := &fixedSender{}
	var output bytes.Buffer
	logger, _ := eventlog.New(&output)
	runtime, err := New(Options{
		EndpointID: "123e4567-e89b-42d3-a456-426614174001", CollectionInterval: time.Minute,
		RequestTimeout: time.Second, Snapshotter: fixedSnapshotter{
			result: agentcore.SnapshotResult{MessageID: secondID, Complete: true}, cancel: cancel,
		}, Queue: queue, Sender: sender, Source: syntheticSource{}, Logger: logger,
		RetryPolicy: transport.RetryPolicy{MaxAttempts: 1, InitialDelay: time.Second, MaximumDelay: time.Second},
		Now:         func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(queue.rejected) != 1 || queue.rejected[0] != testMessageID {
		t.Fatalf("expired record was not quarantined: %v", queue.rejected)
	}
	if len(sender.deliver) != 1 || sender.deliver[0] != secondID {
		t.Fatalf("newer record was blocked: %v", sender.deliver)
	}
	logs := output.String()
	if !strings.Contains(logs, `"message_id":"`+evictedID+`"`) ||
		!strings.Contains(logs, `"failure_class":"limit_exceeded"`) {
		t.Fatalf("rejected-evidence rollover was not audited: %s", logs)
	}
}

func TestExplicitlyRejectedHeadIsQuarantinedAndDeliveryContinues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	secondID := "123e4567-e89b-42d3-a456-426614174004"
	queue := &memoryQueue{
		ids: []string{testMessageID, secondID},
		payload: map[string][]byte{
			testMessageID: inventoryPayload(t, testMessageID, testNow.Add(time.Minute)),
			secondID:      inventoryPayload(t, secondID, testNow.Add(time.Minute)),
		},
	}
	sender := &rejectingSender{rejectID: testMessageID}
	logger, _ := eventlog.New(&bytes.Buffer{})
	runtime, err := New(Options{
		EndpointID: "123e4567-e89b-42d3-a456-426614174001", CollectionInterval: time.Minute,
		RequestTimeout: time.Second, Snapshotter: fixedSnapshotter{
			result: agentcore.SnapshotResult{MessageID: secondID, Complete: true}, cancel: cancel,
		}, Queue: queue, Sender: sender, Source: syntheticSource{}, Logger: logger,
		RetryPolicy: transport.RetryPolicy{MaxAttempts: 1, InitialDelay: time.Second, MaximumDelay: time.Second},
		Now:         func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(queue.rejected) != 1 || queue.rejected[0] != testMessageID {
		t.Fatalf("rejected record was not quarantined: %v", queue.rejected)
	}
	if len(sender.deliver) != 2 || sender.deliver[1] != secondID {
		t.Fatalf("delivery did not continue: %v", sender.deliver)
	}
}

func TestNewRejectsIncompleteOrUnboundedOptions(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("New returned %v", err)
	}
}
