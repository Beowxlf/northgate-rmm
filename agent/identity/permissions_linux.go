//go:build linux

package identity

import (
	"io/fs"
	"os"
	"syscall"
)

func privateDirectory(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().Perm()&0o077 == 0 && stat.Uid == uint32(os.Geteuid())
}

func privateFile(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().Perm()&0o077 == 0 && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}
