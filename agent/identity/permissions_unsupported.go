//go:build !linux

package identity

import "io/fs"

// Phase 2 qualifies Linux only. Other platforms retain source-test portability
// but do not make an operational filesystem-permission claim.
func privateDirectory(fs.FileInfo) bool { return true }
func privateFile(fs.FileInfo) bool      { return true }
