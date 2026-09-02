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
	"github.com/Beowxlf/northgate-rmm/agent/transport"
)

const testMessageID = "123e4567-e89b-42d3-a456-426614174000"

type memoryQueue struct {
	mu      sync.Mutex
	ids     []string
	payload map[string][]byte
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

func TestRunDrainsQueueAndStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := &memoryQueue{ids: []string{testMessageID}, payload: map[string][]byte{testMessageID: []byte(`{"ok":true}`)}}
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
	queue := &memoryQueue{ids: []string{testMessageID}, payload: map[string][]byte{testMessageID: []byte(`{"ok":true}`)}}
	sender := &fixedSender{err: &transport.DeliveryError{Code: "tls_trust_failed"}}
	var output bytes.Buffer
	logger, _ := eventlog.New(&output)
	runtime, err := New(Options{
		EndpointID: "123e4567-e89b-42d3-a456-426614174001", CollectionInterval: time.Minute,
		RequestTimeout: time.Second, Snapshotter: fixedSnapshotter{
			result: agentcore.SnapshotResult{MessageID: testMessageID, Complete: true}, cancel: cancel,
		}, Queue: queue, Sender: sender, Source: syntheticSource{}, Logger: logger,
		RetryPolicy: transport.RetryPolicy{MaxAttempts: 1, InitialDelay: time.Second, MaximumDelay: time.Second},
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

func TestNewRejectsIncompleteOrUnboundedOptions(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("New returned %v", err)
	}
}
