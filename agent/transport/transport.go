// Package transport defines the bounded outbound-only mTLS handoff boundary.
// It contains no listener, enrollment grant handling, identity persistence, or
// endpoint command capability.
package transport

import "context"

// Sender transmits one already bounded protocol message. Implementations must
// use authenticated outbound transport and are gated separately.
type Sender interface {
	Send(context.Context, string, []byte) error
}
