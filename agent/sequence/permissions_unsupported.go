//go:build !linux && !windows

package sequence

import "io/fs"

// Non-Linux filesystems retain source-test portability only.
func privateDirectory(fs.FileInfo, ...string) bool { return true }
func privateFile(fs.FileInfo, ...string) bool      { return true }
