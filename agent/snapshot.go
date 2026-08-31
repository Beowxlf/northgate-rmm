// Package agent composes bounded collection, protocol encoding, and durable
// local queuing. It contains no network client, listener, command runner, or
// privileged operation.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/collector"
	"github.com/Beowxlf/northgate-rmm/agent/protocol"
)

const DefaultMessageTTL = time.Minute

type Queue interface {
	Enqueue(context.Context, string, []byte) error
}

type SequenceStore interface {
	Reserve(context.Context, string) (int64, error)
}

type Snapshotter struct {
	mu         sync.Mutex
	runner     *collector.Runner
	queue      Queue
	sequences  SequenceStore
	clock      func() time.Time
	newID      func() (string, error)
	messageTTL time.Duration
}

type SnapshotResult struct {
	MessageID string
	Sequence  int64
	Complete  bool
	Issues    []collector.Issue
	Bytes     int
}

func NewSnapshotter(runner *collector.Runner, queue Queue, sequences SequenceStore) (*Snapshotter, error) {
	if runner == nil || queue == nil || sequences == nil {
		return nil, errors.New("snapshotter dependencies are required")
	}
	return &Snapshotter{
		runner:     runner,
		queue:      queue,
		sequences:  sequences,
		clock:      time.Now,
		newID:      newUUID,
		messageTTL: DefaultMessageTTL,
	}, nil
}

// Snapshot performs one collection cycle and commits the encoded message to
// the local queue. Transmission is a separate, not-yet-implemented boundary.
func (snapshotter *Snapshotter) Snapshot(
	ctx context.Context,
	endpointID string,
	source collector.Source,
) (SnapshotResult, error) {
	result, err := snapshotter.runner.Run(ctx, source)
	if err != nil {
		return SnapshotResult{}, err
	}
	bootID := result.Fields["boot.id"]
	if bootID == "" {
		return SnapshotResult{}, errors.New("boot identity is unavailable")
	}
	// The sequence and spool ordering are one local critical section. Without
	// this boundary, concurrent collectors could reserve 1 then 2 but enqueue
	// 2 first, causing the server to reject 1 as a replay.
	snapshotter.mu.Lock()
	defer snapshotter.mu.Unlock()
	sequence, err := snapshotter.sequences.Reserve(ctx, bootID)
	if err != nil {
		return SnapshotResult{}, err
	}
	messageID, err := snapshotter.newID()
	if err != nil {
		return SnapshotResult{}, err
	}
	correlationID, err := snapshotter.newID()
	if err != nil {
		return SnapshotResult{}, err
	}
	now := snapshotter.clock().UTC()
	raw, err := protocol.EncodeInventory(
		protocol.Envelope{
			MessageID:       messageID,
			EndpointID:      endpointID,
			BootID:          bootID,
			Sequence:        sequence,
			CreatedAt:       now,
			ExpiresAt:       now.Add(snapshotter.messageTTL),
			CorrelationID:   correlationID,
			ProtocolVersion: protocol.Version,
		},
		protocol.InventoryPayload{
			Platform:          result.Platform,
			Architecture:      result.Architecture,
			Fields:            result.Fields,
			CollectorComplete: result.Complete,
			SchemaVersion:     protocol.InventorySchema,
		},
	)
	if err != nil {
		return SnapshotResult{}, err
	}
	snapshotResult := SnapshotResult{
		MessageID: messageID,
		Sequence:  sequence,
		Complete:  result.Complete,
		Issues:    append([]collector.Issue(nil), result.Issues...),
		Bytes:     len(raw),
	}
	if err := snapshotter.queue.Enqueue(ctx, messageID, raw); err != nil {
		return snapshotResult, err
	}
	return snapshotResult, nil
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:32], nil
}
