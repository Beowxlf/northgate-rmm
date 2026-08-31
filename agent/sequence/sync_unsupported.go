//go:build !linux

package sequence

import "os"

// Phase 2 qualifies Linux only. Other platforms make no durability claim.
func syncDirectory(*os.Root) error { return nil }
