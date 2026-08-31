package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	MaxRetryAttempts = 8
	MinRetryDelay    = 100 * time.Millisecond
	MaxRetryDelay    = 5 * time.Minute
)

// RetryPolicy bounds delivery attempts and applies equal jitter within an
// exponentially increasing delay cap. It never retries a permanent result.
type RetryPolicy struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaximumDelay time.Duration
}

func (policy RetryPolicy) Validate() error {
	if policy.MaxAttempts < 1 || policy.MaxAttempts > MaxRetryAttempts {
		return errors.New("retry attempts are outside the supported range")
	}
	if policy.InitialDelay < MinRetryDelay || policy.MaximumDelay > MaxRetryDelay ||
		policy.InitialDelay > policy.MaximumDelay {
		return errors.New("retry delay is outside the supported range")
	}
	return nil
}

// Retry runs operation at most MaxAttempts times. Context cancellation,
// permanent delivery errors, entropy failure, and timer failure stop retries.
func Retry(ctx context.Context, policy RetryPolicy, operation func(context.Context) error) error {
	return retryWith(ctx, policy, operation, rand.Reader, waitForDelay)
}

func retryWith(
	ctx context.Context,
	policy RetryPolicy,
	operation func(context.Context) error,
	random io.Reader,
	wait func(context.Context, time.Duration) error,
) error {
	if operation == nil || random == nil || wait == nil {
		return errors.New("retry dependencies are required")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	delay := policy.InitialDelay
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = operation(ctx)
		if lastErr == nil || !IsRetryable(lastErr) || attempt == policy.MaxAttempts {
			return lastErr
		}
		jittered, err := jitter(random, delay)
		if err != nil {
			return fmt.Errorf("generate retry delay: %w", err)
		}
		if err := wait(ctx, jittered); err != nil {
			return err
		}
		if delay > policy.MaximumDelay/2 {
			delay = policy.MaximumDelay
		} else {
			delay *= 2
			if delay > policy.MaximumDelay {
				delay = policy.MaximumDelay
			}
		}
	}
	return lastErr
}

func jitter(random io.Reader, delay time.Duration) (time.Duration, error) {
	var raw [8]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return 0, err
	}
	half := delay / 2
	span := uint64(delay - half)
	return half + time.Duration(binary.BigEndian.Uint64(raw[:])%(span+1)), nil
}

func waitForDelay(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
