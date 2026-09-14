//go:build !linux && !windows

package spool

import "io/fs"

// Non-Linux filesystems do not expose Unix permission bits consistently. Their
// source-test shim makes no operational privacy claim.
func privateRecord(fs.FileInfo, ...string) bool { return true }
