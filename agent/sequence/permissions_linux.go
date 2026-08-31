//go:build linux

package sequence

import "io/fs"

func privateDirectory(info fs.FileInfo) bool { return info.Mode().Perm()&0o077 == 0 }
func privateFile(info fs.FileInfo) bool      { return info.Mode().Perm()&0o077 == 0 }
