package transport

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryUsesBoundedExponentialBackoff(t *testing.T) {
	policy := RetryPolicy{MaxAttempts: 4, InitialDelay: 100 * time.Millisecond, MaximumDelay: time.Second}
	attempts := 0
	var delays []time.Duration
	err := retryWith(
		context.Background(),
		policy,
		func(context.Context) error {
			attempts++
			if attempts < 3 {
				return &DeliveryError{Code: "synthetic", Retryable: true}
			}
			return nil
		},
		bytes.NewReader(make([]byte, 16)),
		func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	)
	if err != nil || attempts != 3 {
		t.Fatalf("retryWith() attempts = %d, error = %v", attempts, err)
	}
	want := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond}
	if len(delays) != len(want) || delays[0] != want[0] || delays[1] != want[1] {
		t.Fatalf("retryWith() delays = %v, want %v", delays, want)
	}
}

func TestRetryStopsOnPermanentErrorAndAttemptLimit(t *testing.T) {
	policy := RetryPolicy{MaxAttempts: 3, InitialDelay: 100 * time.Millisecond, MaximumDelay: time.Second}
	for _, test := range []struct {
		name       string
		retryable  bool
		wantTrials int
	}{
		{name: "permanent", retryable: false, wantTrials: 1},
		{name: "transient", retryable: true, wantTrials: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			err := retryWith(
				context.Background(),
				policy,
				func(context.Context) error {
					attempts++
					return &DeliveryError{Code: "synthetic", Retryable: test.retryable}
				},
				bytes.NewReader(make([]byte, 24)),
				func(context.Context, time.Duration) error { return nil },
			)
			if err == nil || attempts != test.wantTrials {
				t.Fatalf("retryWith() attempts = %d, error = %v", attempts, err)
			}
		})
	}
}

func TestRetryStopsOnContextAndEntropyFailure(t *testing.T) {
	policy := RetryPolicy{MaxAttempts: 2, InitialDelay: 100 * time.Millisecond, MaximumDelay: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempted := false
	err := retryWith(ctx, policy, func(context.Context) error {
		attempted = true
		return nil
	}, bytes.NewReader(nil), func(context.Context, time.Duration) error { return nil })
	if !errors.Is(err, context.Canceled) || attempted {
		t.Fatalf("retryWith() attempted = %t, error = %v", attempted, err)
	}

	err = retryWith(
		context.Background(),
		policy,
		func(context.Context) error { return &DeliveryError{Code: "synthetic", Retryable: true} },
		bytes.NewReader(nil),
		func(context.Context, time.Duration) error { return nil },
	)
	if err == nil || IsRetryable(err) {
		t.Fatalf("retryWith() entropy error = %v", err)
	}
}

func TestRetryPolicyRejectsUnboundedValues(t *testing.T) {
	tests := []RetryPolicy{
		{},
		{MaxAttempts: MaxRetryAttempts + 1, InitialDelay: MinRetryDelay, MaximumDelay: MaxRetryDelay},
		{MaxAttempts: 1, InitialDelay: MinRetryDelay - 1, MaximumDelay: MaxRetryDelay},
		{MaxAttempts: 1, InitialDelay: time.Second, MaximumDelay: MinRetryDelay},
		{MaxAttempts: 1, InitialDelay: MinRetryDelay, MaximumDelay: MaxRetryDelay + 1},
	}
	for _, policy := range tests {
		if err := policy.Validate(); err == nil {
			t.Fatalf("Validate() accepted %#v", policy)
		}
	}
}
