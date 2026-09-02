// Package runtime composes one bounded read-only agent process. It has no
// listener, command runner, remediation, file-transfer, or privileged action.
package runtime

import (
	"context"
	"errors"
	"time"

	agentcore "github.com/Beowxlf/northgate-rmm/agent"
	"github.com/Beowxlf/northgate-rmm/agent/collector"
	"github.com/Beowxlf/northgate-rmm/agent/eventlog"
	"github.com/Beowxlf/northgate-rmm/agent/protocol"
	"github.com/Beowxlf/northgate-rmm/agent/spool"
	"github.com/Beowxlf/northgate-rmm/agent/transport"
)

var (
	ErrInvalidRuntime = errors.New("runtime configuration is invalid")
	ErrRuntimeFailed  = errors.New("agent runtime failed")
	ErrLoggingFailed  = errors.New("agent event logging failed")
)

type Snapshotter interface {
	Snapshot(context.Context, string, collector.Source) (agentcore.SnapshotResult, error)
}

type Queue interface {
	ListIDs(context.Context) ([]string, error)
	Read(context.Context, string) ([]byte, error)
	Acknowledge(context.Context, string) error
	Quarantine(context.Context, string) (spool.QuarantineResult, error)
}

type Sender interface {
	Send(context.Context, string, []byte) error
}

type Logger interface {
	Emit(eventlog.Event) error
}

// Options contains the already validated process dependencies. All I/O is
// limited to the allowlisted collector source, private queue, outbound sender,
// and closed-schema logger.
type Options struct {
	EndpointID         string
	CollectionInterval time.Duration
	RequestTimeout     time.Duration
	Snapshotter        Snapshotter
	Queue              Queue
	Sender             Sender
	Source             collector.Source
	Logger             Logger
	RetryPolicy        transport.RetryPolicy
	Now                func() time.Time
}

type Runtime struct {
	options Options
}

func New(options Options) (*Runtime, error) {
	if options.EndpointID == "" || options.CollectionInterval <= 0 ||
		options.RequestTimeout <= 0 || options.RequestTimeout >= options.CollectionInterval ||
		options.Snapshotter == nil || options.Queue == nil || options.Sender == nil ||
		options.Source == nil || options.Logger == nil || options.RetryPolicy.Validate() != nil {
		return nil, ErrInvalidRuntime
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Runtime{options: options}, nil
}

// Run performs one cycle immediately and then repeats at the configured
// interval. SIGTERM/SIGINT cancellation is handled by the executable entrypoint.
// Cancellation is a normal stop; local durability or logging uncertainty fails
// closed with a sanitized sentinel.
func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil {
		return ErrInvalidRuntime
	}
	if err := runtime.emit(eventlog.Event{
		Level: eventlog.LevelInfo, Code: eventlog.CodeAgentLifecycle,
		Component: eventlog.ComponentAgent, Outcome: eventlog.OutcomeStarted,
		FailureClass: eventlog.FailureNone,
	}); err != nil {
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return runtime.stop()
		}
		if err := runtime.cycle(ctx); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
				return runtime.stop()
			}
			_ = runtime.emit(eventlog.Event{
				Level: eventlog.LevelError, Code: eventlog.CodeAgentLifecycle,
				Component: eventlog.ComponentAgent, Outcome: eventlog.OutcomeFailed,
				FailureClass: eventlog.FailureInternal,
			})
			return ErrRuntimeFailed
		}
		timer := time.NewTimer(runtime.options.CollectionInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return runtime.stop()
		case <-timer.C:
		}
	}
}

func (runtime *Runtime) cycle(ctx context.Context) error {
	blocked, err := runtime.deliver(ctx)
	if err != nil {
		return err
	}
	collectionContext, cancel := context.WithTimeout(ctx, runtime.options.RequestTimeout)
	result, snapshotErr := runtime.options.Snapshotter.Snapshot(
		collectionContext, runtime.options.EndpointID, runtime.options.Source,
	)
	cancel()
	if snapshotErr != nil {
		outcome, failure, fatal := classifyLocalState(snapshotErr)
		if err := runtime.emit(eventlog.Event{
			Level: levelFor(outcome), Code: eventlog.CodeLocalState,
			Component: eventlog.ComponentSpool, Outcome: outcome,
			FailureClass: failure, MessageID: result.MessageID,
		}); err != nil {
			return err
		}
		if fatal {
			return ErrRuntimeFailed
		}
		return nil
	}
	collectionOutcome := eventlog.OutcomeSucceeded
	collectionLevel := eventlog.LevelInfo
	if !result.Complete {
		collectionOutcome = eventlog.OutcomePartial
		collectionLevel = eventlog.LevelWarn
	}
	if err := runtime.emit(eventlog.Event{
		Level: collectionLevel, Code: eventlog.CodeCollection,
		Component: eventlog.ComponentCollector, Outcome: collectionOutcome,
		FailureClass: collectionFailure(result.Complete), MessageID: result.MessageID,
	}); err != nil {
		return err
	}
	if blocked {
		return nil
	}
	_, err = runtime.deliver(ctx)
	return err
}

func collectionFailure(complete bool) eventlog.FailureClass {
	if complete {
		return eventlog.FailureNone
	}
	return eventlog.FailureUnavailable
}

// deliver preserves queue order. A transport rejection leaves the current and
// later records durable for a later cycle; only local queue uncertainty is
// fatal to the process.
func (runtime *Runtime) deliver(ctx context.Context) (bool, error) {
	ids, err := runtime.options.Queue.ListIDs(ctx)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		payload, err := runtime.options.Queue.Read(ctx, id)
		if err != nil {
			return false, err
		}
		message, err := protocol.DecodeInventory(payload)
		if err != nil || message.Envelope.MessageID != id {
			return false, ErrRuntimeFailed
		}
		if !runtime.options.Now().UTC().Before(message.Envelope.ExpiresAt) {
			if err := runtime.quarantine(ctx, id); err != nil {
				return false, err
			}
			if err := runtime.emit(eventlog.Event{
				Level: eventlog.LevelWarn, Code: eventlog.CodeLocalState,
				Component: eventlog.ComponentSpool, Outcome: eventlog.OutcomeRejected,
				FailureClass: eventlog.FailureInvalidInput, MessageID: id,
			}); err != nil {
				return false, err
			}
			continue
		}
		deliveryContext, cancel := context.WithTimeout(ctx, runtime.options.RequestTimeout)
		err = transport.Retry(deliveryContext, runtime.options.RetryPolicy, func(attempt context.Context) error {
			return runtime.options.Sender.Send(attempt, id, payload)
		})
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			outcome, failure, terminal := classifyDelivery(err)
			if terminal {
				if quarantineErr := runtime.quarantine(ctx, id); quarantineErr != nil {
					return false, quarantineErr
				}
			}
			if emitErr := runtime.emit(eventlog.Event{
				Level: levelFor(outcome), Code: eventlog.CodeDelivery,
				Component: eventlog.ComponentTransport, Outcome: outcome,
				FailureClass: failure, MessageID: id,
			}); emitErr != nil {
				return false, emitErr
			}
			if terminal {
				continue
			}
			return true, nil
		}
		if err := runtime.options.Queue.Acknowledge(ctx, id); err != nil {
			outcome, failure, _ := classifyLocalState(err)
			if emitErr := runtime.emit(eventlog.Event{
				Level: levelFor(outcome), Code: eventlog.CodeLocalState,
				Component: eventlog.ComponentSpool, Outcome: outcome,
				FailureClass: failure, MessageID: id,
			}); emitErr != nil {
				return false, emitErr
			}
			return false, ErrRuntimeFailed
		}
		if err := runtime.emit(eventlog.Event{
			Level: eventlog.LevelInfo, Code: eventlog.CodeDelivery,
			Component: eventlog.ComponentTransport, Outcome: eventlog.OutcomeSucceeded,
			FailureClass: eventlog.FailureNone, MessageID: id,
		}); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (runtime *Runtime) quarantine(ctx context.Context, id string) error {
	result, err := runtime.options.Queue.Quarantine(ctx, id)
	for _, evictedID := range result.EvictedIDs {
		if emitErr := runtime.emit(eventlog.Event{
			Level: eventlog.LevelWarn, Code: eventlog.CodeLocalState,
			Component: eventlog.ComponentSpool, Outcome: eventlog.OutcomeRejected,
			FailureClass: eventlog.FailureLimitExceeded, MessageID: evictedID,
		}); emitErr != nil {
			return emitErr
		}
	}
	return err
}

func (runtime *Runtime) stop() error {
	return runtime.emit(eventlog.Event{
		Level: eventlog.LevelInfo, Code: eventlog.CodeAgentLifecycle,
		Component: eventlog.ComponentAgent, Outcome: eventlog.OutcomeStopped,
		FailureClass: eventlog.FailureNone,
	})
}

func (runtime *Runtime) emit(event eventlog.Event) error {
	if err := runtime.options.Logger.Emit(event); err != nil {
		return ErrLoggingFailed
	}
	return nil
}

func classifyDelivery(err error) (eventlog.Outcome, eventlog.FailureClass, bool) {
	var deliveryError *transport.DeliveryError
	if !errors.As(err, &deliveryError) {
		return eventlog.OutcomeFailed, eventlog.FailureInternal, false
	}
	switch deliveryError.Code {
	case "tls_trust_failed":
		return eventlog.OutcomeRejected, eventlog.FailureTrust, false
	case "invalid_message_id", "invalid_payload_size", "request_build_failed":
		return eventlog.OutcomeRejected, eventlog.FailureInvalidInput, false
	case "acknowledgement_rejected":
		return eventlog.OutcomeRejected, eventlog.FailureUnavailable, true
	case "acknowledgement_mismatch", "invalid_acknowledgement", "invalid_response_type", "invalid_response_size":
		return eventlog.OutcomeRejected, eventlog.FailureTrust, false
	default:
		return eventlog.OutcomeFailed, eventlog.FailureUnavailable, false
	}
}

func classifyLocalState(err error) (eventlog.Outcome, eventlog.FailureClass, bool) {
	var acknowledgeUncertain *spool.AcknowledgeUncertainError
	var commitUncertain *spool.CommitUncertainError
	var quarantineUncertain *spool.QuarantineUncertainError
	if errors.As(err, &acknowledgeUncertain) || errors.As(err, &commitUncertain) ||
		errors.As(err, &quarantineUncertain) {
		return eventlog.OutcomeUncertain, eventlog.FailureStateUncertain, true
	}
	if errors.Is(err, spool.ErrQuotaExceeded) {
		return eventlog.OutcomeRejected, eventlog.FailureLimitExceeded, false
	}
	if errors.Is(err, spool.ErrCorrupt) {
		return eventlog.OutcomeFailed, eventlog.FailureIntegrity, true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return eventlog.OutcomeFailed, eventlog.FailureUnavailable, false
	}
	return eventlog.OutcomeFailed, eventlog.FailureInternal, true
}

func levelFor(outcome eventlog.Outcome) eventlog.Level {
	switch outcome {
	case eventlog.OutcomeRejected, eventlog.OutcomeUncertain, eventlog.OutcomePartial:
		return eventlog.LevelWarn
	case eventlog.OutcomeFailed:
		return eventlog.LevelError
	default:
		return eventlog.LevelInfo
	}
}
