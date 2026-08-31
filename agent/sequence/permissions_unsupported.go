//go:build !linux

package sequence

import "io/fs"

// Non-Linux filesystems retain source-test portability only.
func privateDirectory(fs.FileInfo) bool { return true }
func privateFile(fs.FileInfo) bool      { return true }
