// Package eventlog emits bounded structured agent events from a closed schema.
// It deliberately accepts no free-form message, error, URL, hostname, or
// endpoint data fields.
package eventlog

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"
)

const (
	SchemaVersion  = 1
	MaxRecordBytes = 1024
)

var (
	ErrInvalidEvent = errors.New("event is outside the logging schema")
	ErrWriteEvent   = errors.New("write structured event")
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type Code string

const (
	CodeAgentLifecycle Code = "agent_lifecycle"
	CodeCollection     Code = "inventory_collection"
	CodeDelivery       Code = "inventory_delivery"
	CodeLocalState     Code = "local_state"
)

type Component string

const (
	ComponentAgent     Component = "agent"
	ComponentCollector Component = "collector"
	ComponentIdentity  Component = "identity"
	ComponentSequence  Component = "sequence"
	ComponentSpool     Component = "spool"
	ComponentTransport Component = "transport"
)

type Outcome string

const (
	OutcomeStarted   Outcome = "started"
	OutcomeStopped   Outcome = "stopped"
	OutcomeSucceeded Outcome = "succeeded"
	OutcomePartial   Outcome = "partial"
	OutcomeFailed    Outcome = "failed"
	OutcomeRejected  Outcome = "rejected"
	OutcomeUncertain Outcome = "uncertain"
)

type FailureClass string

const (
	FailureNone             FailureClass = "none"
	FailureInvalidInput     FailureClass = "invalid_input"
	FailureUnavailable      FailureClass = "unavailable"
	FailureLimitExceeded    FailureClass = "limit_exceeded"
	FailurePermissionDenied FailureClass = "permission_denied"
	FailureIntegrity        FailureClass = "integrity_failed"
	FailureTrust            FailureClass = "trust_failed"
	FailureStateUncertain   FailureClass = "state_uncertain"
	FailureInternal         FailureClass = "internal"
)

// Event contains only allowlisted metadata. CorrelationID and MessageID must be
// canonical UUIDs when present; callers cannot attach arbitrary attributes.
type Event struct {
	Level         Level
	Code          Code
	Component     Component
	Outcome       Outcome
	FailureClass  FailureClass
	CorrelationID string
	MessageID     string
}

type record struct {
	SchemaVersion int          `json:"schema_version"`
	Timestamp     string       `json:"timestamp"`
	Level         Level        `json:"level"`
	Code          Code         `json:"code"`
	Component     Component    `json:"component"`
	Outcome       Outcome      `json:"outcome"`
	FailureClass  FailureClass `json:"failure_class"`
	CorrelationID string       `json:"correlation_id,omitempty"`
	MessageID     string       `json:"message_id,omitempty"`
}

// Logger serializes complete newline-delimited JSON records to one writer.
type Logger struct {
	mu     sync.Mutex
	writer io.Writer
	now    func() time.Time
	failed bool
}

func New(writer io.Writer) (*Logger, error) {
	return NewWithClock(writer, time.Now)
}

// NewWithClock permits deterministic tests while preserving the same schema.
func NewWithClock(writer io.Writer, now func() time.Time) (*Logger, error) {
	if writer == nil || now == nil {
		return nil, ErrInvalidEvent
	}
	return &Logger{writer: writer, now: now}, nil
}

// Emit validates the closed event schema before producing one bounded JSON
// line. It never records raw operating-system or transport error text.
func (logger *Logger) Emit(event Event) error {
	if logger == nil || !validEvent(event) {
		return ErrInvalidEvent
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if logger.failed {
		return ErrWriteEvent
	}

	timestamp := logger.now().UTC()
	if timestamp.Year() < 1 || timestamp.Year() > 9999 {
		return ErrInvalidEvent
	}
	wire := record{
		SchemaVersion: SchemaVersion,
		Timestamp:     timestamp.Format(time.RFC3339Nano),
		Level:         event.Level,
		Code:          event.Code,
		Component:     event.Component,
		Outcome:       event.Outcome,
		FailureClass:  event.FailureClass,
		CorrelationID: event.CorrelationID,
		MessageID:     event.MessageID,
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded)+1 > MaxRecordBytes {
		return ErrInvalidEvent
	}
	encoded = append(encoded, '\n')

	if err := writeAll(logger.writer, encoded); err != nil {
		logger.failed = true
		return ErrWriteEvent
	}
	return nil
}

func validEvent(event Event) bool {
	if !oneOf(event.Level, LevelInfo, LevelWarn, LevelError) ||
		!oneOf(event.Code, CodeAgentLifecycle, CodeCollection, CodeDelivery, CodeLocalState) ||
		!oneOf(event.Component, ComponentAgent, ComponentCollector, ComponentIdentity,
			ComponentSequence, ComponentSpool, ComponentTransport) ||
		!oneOf(event.Outcome, OutcomeStarted, OutcomeStopped, OutcomeSucceeded,
			OutcomePartial, OutcomeFailed, OutcomeRejected, OutcomeUncertain) ||
		!oneOf(event.FailureClass, FailureNone, FailureInvalidInput, FailureUnavailable,
			FailureLimitExceeded, FailurePermissionDenied, FailureIntegrity, FailureTrust,
			FailureStateUncertain, FailureInternal) {
		return false
	}
	if (event.Outcome == OutcomeStarted || event.Outcome == OutcomeStopped ||
		event.Outcome == OutcomeSucceeded) != (event.FailureClass == FailureNone) {
		return false
	}
	if (event.Outcome == OutcomeUncertain) != (event.FailureClass == FailureStateUncertain) {
		return false
	}
	if !validLevelOutcome(event.Level, event.Outcome) || !validCodeComponentOutcome(event) {
		return false
	}
	return validOptionalUUID(event.CorrelationID) && validOptionalUUID(event.MessageID)
}

func validLevelOutcome(level Level, outcome Outcome) bool {
	switch outcome {
	case OutcomeStarted, OutcomeStopped, OutcomeSucceeded:
		return level == LevelInfo
	case OutcomePartial, OutcomeRejected, OutcomeUncertain:
		return level == LevelWarn
	case OutcomeFailed:
		return level == LevelError
	default:
		return false
	}
}

func validCodeComponentOutcome(event Event) bool {
	switch event.Code {
	case CodeAgentLifecycle:
		return event.Component == ComponentAgent &&
			oneOf(event.Outcome, OutcomeStarted, OutcomeStopped, OutcomeFailed)
	case CodeCollection:
		return event.Component == ComponentCollector &&
			oneOf(event.Outcome, OutcomeSucceeded, OutcomePartial, OutcomeFailed)
	case CodeDelivery:
		return event.Component == ComponentTransport &&
			oneOf(event.Outcome, OutcomeSucceeded, OutcomeFailed, OutcomeRejected, OutcomeUncertain)
	case CodeLocalState:
		return oneOf(event.Component, ComponentIdentity, ComponentSequence, ComponentSpool) &&
			oneOf(event.Outcome, OutcomeSucceeded, OutcomeFailed, OutcomeRejected, OutcomeUncertain)
	default:
		return false
	}
}

func validOptionalUUID(value string) bool {
	return value == "" || uuidPattern.MatchString(value)
}

func oneOf[T comparable](value T, allowed ...T) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
