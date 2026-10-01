//go:build !linux && !windows

package identity

import "io/fs"

// Phase 2 qualifies Linux only. Other platforms retain source-test portability
// but do not make an operational filesystem-permission claim.
func privateDirectory(fs.FileInfo, ...string) bool { return true }
func privateFile(fs.FileInfo, ...string) bool      { return true }
