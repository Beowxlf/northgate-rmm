package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, time.August, 31, 15, 4, 5, 123, time.FixedZone("test", -5*60*60))

func validEventFixture() Event {
	return Event{
		Level:         LevelInfo,
		Code:          CodeDelivery,
		Component:     ComponentTransport,
		Outcome:       OutcomeSucceeded,
		FailureClass:  FailureNone,
		CorrelationID: "123e4567-e89b-42d3-a456-426614174000",
		MessageID:     "123e4567-e89b-42d3-a456-426614174001",
	}
}

func TestEmitProducesBoundedClosedSchema(t *testing.T) {
	var output bytes.Buffer
	logger, err := NewWithClock(&output, func() time.Time { return fixedTime })
	if err != nil {
		t.Fatalf("NewWithClock() error = %v", err)
	}
	if err := logger.Emit(validEventFixture()); err != nil {
		t.Fatalf("Emit() error = %v", err)
	}
	if output.Len() > MaxRecordBytes || !bytes.HasSuffix(output.Bytes(), []byte("\n")) {
		t.Fatalf("invalid record framing: %q", output.Bytes())
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	wantKeys := []string{"schema_version", "timestamp", "level", "code", "component", "outcome", "failure_class", "correlation_id", "message_id"}
	if len(got) != len(wantKeys) {
		t.Fatalf("unexpected field count: %#v", got)
	}
	for _, key := range wantKeys {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing field %q: %#v", key, got)
		}
	}
	if got["timestamp"] != "2026-08-31T20:04:05.000000123Z" {
		t.Fatalf("timestamp = %q", got["timestamp"])
	}
}

func TestEmitRejectsSecretBearingOrFreeFormValues(t *testing.T) {
	secretShaped := []string{
		"Bearer-not-a-log-field",
		"api_key=not-a-log-field",
		"https://user:credential@rmm.invalid/",
		"line-one\nline-two",
	}
	for _, value := range secretShaped {
		var output bytes.Buffer
		logger, err := NewWithClock(&output, func() time.Time { return fixedTime })
		if err != nil {
			t.Fatal(err)
		}
		event := validEventFixture()
		event.CorrelationID = value
		if err := logger.Emit(event); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("Emit(%q) error = %v, want ErrInvalidEvent", value, err)
		}
		if output.Len() != 0 {
			t.Fatalf("rejected value reached output: %q", output.Bytes())
		}
	}
}

func TestEmitEnforcesOutcomeAndFailureConsistency(t *testing.T) {
	for _, mutate := range []func(*Event){
		func(event *Event) { event.Outcome = OutcomeFailed },
		func(event *Event) { event.FailureClass = FailureInternal },
		func(event *Event) { event.Level = Level("debug") },
		func(event *Event) { event.Level = LevelError },
		func(event *Event) { event.Component = ComponentCollector },
		func(event *Event) { event.Code = CodeAgentLifecycle },
	} {
		logger, _ := NewWithClock(io.Discard, func() time.Time { return fixedTime })
		event := validEventFixture()
		mutate(&event)
		if err := logger.Emit(event); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("Emit() error = %v, want ErrInvalidEvent for %#v", err, event)
		}
	}
}

func TestEmitAllowsUncertainDeliveryWithoutRawError(t *testing.T) {
	var output bytes.Buffer
	logger, _ := NewWithClock(&output, func() time.Time { return fixedTime })
	event := validEventFixture()
	event.Level = LevelWarn
	event.Outcome = OutcomeUncertain
	event.FailureClass = FailureStateUncertain
	if err := logger.Emit(event); err != nil {
		t.Fatalf("Emit() error = %v", err)
	}
	if !strings.Contains(output.String(), `"outcome":"uncertain"`) ||
		strings.Contains(output.String(), "private-detail") {
		t.Fatalf("unexpected uncertain-delivery record: %q", output.String())
	}
}

func TestEmitBindsUncertainOutcomeAndFailureClass(t *testing.T) {
	for _, event := range []Event{
		{
			Level: LevelWarn, Code: CodeDelivery, Component: ComponentTransport,
			Outcome: OutcomeUncertain, FailureClass: FailureInternal,
		},
		{
			Level: LevelError, Code: CodeDelivery, Component: ComponentTransport,
			Outcome: OutcomeFailed, FailureClass: FailureStateUncertain,
		},
	} {
		logger, _ := NewWithClock(io.Discard, func() time.Time { return fixedTime })
		if err := logger.Emit(event); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("Emit() error = %v, want ErrInvalidEvent for %#v", err, event)
		}
	}
}

func TestEmitSerializesConcurrentRecords(t *testing.T) {
	var output bytes.Buffer
	logger, _ := NewWithClock(&output, func() time.Time { return fixedTime })
	const writers = 32
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := logger.Emit(validEventFixture()); err != nil {
				t.Errorf("Emit() error = %v", err)
			}
		}()
	}
	wait.Wait()
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != writers {
		t.Fatalf("record count = %d, want %d", len(lines), writers)
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("interleaved JSON record: %q", line)
		}
	}
}

func TestEmitReturnsSanitizedWriteSentinel(t *testing.T) {
	logger, _ := NewWithClock(failingWriter{}, func() time.Time { return fixedTime })
	err := logger.Emit(validEventFixture())
	if !errors.Is(err, ErrWriteEvent) || strings.Contains(err.Error(), "private-detail") {
		t.Fatalf("Emit() error = %q", err)
	}
}

func FuzzEmit(f *testing.F) {
	f.Add("agent", "123e4567-e89b-42d3-a456-426614174000")
	f.Add("api_key=not-a-log-field", "line-one\nline-two")
	f.Fuzz(func(t *testing.T, component, correlationID string) {
		var output bytes.Buffer
		logger, _ := NewWithClock(&output, func() time.Time { return fixedTime })
		event := validEventFixture()
		event.Component = Component(component)
		event.CorrelationID = correlationID
		err := logger.Emit(event)
		if err == nil && (output.Len() > MaxRecordBytes || !json.Valid(bytes.TrimSpace(output.Bytes()))) {
			t.Fatalf("successful emit produced invalid output: %q", output.Bytes())
		}
	})
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("private-detail: %w", io.ErrClosedPipe)
}
