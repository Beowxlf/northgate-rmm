//go:build !linux

package spool

import "os"

// Phase 2 qualifies Linux only. Other platforms retain source-test portability
// but do not make a durability claim until their native directory sync exists.
func syncDirectory(*os.Root) error   { return nil }
func syncPathDirectory(string) error { return nil }
