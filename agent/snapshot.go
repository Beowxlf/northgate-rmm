// Package agent composes bounded collection, protocol encoding, and durable
// local queuing. It contains no network client, listener, command runner, or
// privileged operation.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/collector"
	"github.com/Beowxlf/northgate-rmm/agent/protocol"
)

const DefaultMessageTTL = time.Minute

type Queue interface {
	Enqueue(context.Context, string, []byte) error
}

type SequenceStore interface {
	// ReserveAndUse must serialize the durable reservation and callback across
	// every consumer sharing this store.
	ReserveAndUse(context.Context, string, func(int64) error) (int64, error)
}

type Snapshotter struct {
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
	var snapshotResult SnapshotResult
	_, err = snapshotter.sequences.ReserveAndUse(ctx, bootID, func(sequence int64) error {
		// The shared sequence-store boundary remains held through queue
		// publication so multiple snapshotters cannot invert delivery order.
		snapshotResult.Sequence = sequence
		messageID, err := snapshotter.newID()
		if err != nil {
			return err
		}
		correlationID, err := snapshotter.newID()
		if err != nil {
			return err
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
			return err
		}
		snapshotResult.MessageID = messageID
		snapshotResult.Complete = result.Complete
		snapshotResult.Issues = append([]collector.Issue(nil), result.Issues...)
		snapshotResult.Bytes = len(raw)
		return snapshotter.queue.Enqueue(ctx, messageID, raw)
	})
	return snapshotResult, err
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
