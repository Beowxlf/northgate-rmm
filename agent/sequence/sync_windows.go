//go:build windows

package sequence

import (
	"github.com/Beowxlf/northgate-rmm/agent/internal/platformfs"
	"os"
)

func syncDirectory(root *os.Root) error { return platformfs.Sync(root) }
