// Package transport defines the outbound-only handoff boundary. Phase 2 source
// development intentionally provides no network implementation or listener.
package transport

import "context"

// Sender transmits one already bounded protocol message. Implementations must
// use authenticated outbound transport and are gated separately.
type Sender interface {
	Send(context.Context, []byte) error
}
