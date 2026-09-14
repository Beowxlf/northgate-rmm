//go:build windows

package identity

import (
	"github.com/Beowxlf/northgate-rmm/agent/internal/platformfs"
	"io/fs"
)

func privateDirectory(_ fs.FileInfo, paths ...string) bool {
	return len(paths) == 1 && platformfs.Validate(paths[0], true) == nil
}
func privateFile(_ fs.FileInfo, paths ...string) bool {
	return len(paths) == 1 && platformfs.Validate(paths[0], true) == nil
}
