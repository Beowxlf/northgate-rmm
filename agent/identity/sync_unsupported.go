//go:build !linux && !windows

package identity

import "os"

// Phase 2 qualifies Linux only. Other platforms retain source-test portability
// but make no directory-durability claim until a native implementation exists.
func syncDirectory(*os.Root) error { return nil }
