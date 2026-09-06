package agent

import (
	"context"
	"github.com/Beowxlf/northgate-rmm/agent/collector"
	"github.com/Beowxlf/northgate-rmm/agent/protocol"
	"testing"
)

type heartbeatQueue struct{ payloads [][]byte }

func (q *heartbeatQueue) Enqueue(_ context.Context, _ string, p []byte) error {
	q.payloads = append(q.payloads, append([]byte(nil), p...))
	return nil
}
func TestEveryCycleQueuesHeartbeatBeforeInventory(t *testing.T) {
	r, _ := collector.NewRunner("1.0.0")
	q := &heartbeatQueue{}
	s, _ := NewSnapshotter(r, q, &memorySequenceStore{})
	for i := 0; i < 2; i++ {
		if _, err := s.Snapshot(context.Background(), "123e4567-e89b-42d3-a456-426614174003", syntheticSource{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(q.payloads) != 4 {
		t.Fatalf("expected heartbeat and inventory in each cycle, got %d", len(q.payloads))
	}
	for i, p := range q.payloads {
		m, err := protocol.DecodeMessage(p)
		if err != nil {
			t.Fatal(err)
		}
		want := "heartbeat"
		if i%2 == 1 {
			want = "inventory"
		}
		if m.Type != want || m.Envelope.Sequence != int64(i+1) {
			t.Fatalf("incorrect delivery order: %#v", m)
		}
	}
}
