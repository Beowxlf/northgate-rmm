//go:build linux

package sequence

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// protectedParentPath verifies every existing directory that controls name
// resolution to the store. Root and the effective agent UID are trusted path
// owners. A writable ancestor is accepted only with the sticky bit, which
// prevents other writers from replacing entries they do not own.
func protectedParentPath(path string) bool {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return false
	}
	current := string(os.PathSeparator)
	if !protectedParentDirectory(current) {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(clean, current), string(os.PathSeparator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		if !protectedParentDirectory(current) {
			return false
		}
	}
	return true
}

func protectedParentDirectory(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return protectedParentInfo(info)
}

func protectedParentInfo(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return false
	}
	return info.Mode().Perm()&0o022 == 0 || info.Mode()&os.ModeSticky != 0
}
