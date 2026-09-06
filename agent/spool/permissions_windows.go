//go:build windows

package spool

import (
	"github.com/Beowxlf/northgate-rmm/agent/internal/platformfs"
	"io/fs"
)

func privateRecord(_ fs.FileInfo, paths ...string) bool {
	return len(paths) == 1 && platformfs.ValidateSpoolRecord(paths[0]) == nil
}
