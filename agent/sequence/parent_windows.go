//go:build windows

package sequence

import "github.com/Beowxlf/northgate-rmm/agent/internal/platformfs"

func protectedParentPath(path string) bool { return platformfs.Ancestors(path) == nil }
