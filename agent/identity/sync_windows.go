//go:build windows

package identity

import (
	"github.com/Beowxlf/northgate-rmm/agent/internal/platformfs"
	"os"
)

func syncDirectory(root *os.Root) error { return platformfs.Sync(root) }
