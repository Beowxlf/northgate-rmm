//go:build linux

package spool

import "io/fs"

func privateRecord(info fs.FileInfo, _ ...string) bool {
	return info.Mode().Perm()&0o077 == 0
}
