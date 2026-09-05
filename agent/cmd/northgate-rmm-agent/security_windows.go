//go:build windows

package main

import (
	"github.com/Beowxlf/northgate-rmm/agent/internal/platformfs"
	"io/fs"
)

func validatePlatformState(path string) error               { return platformfs.ValidateTree(path) }
func validatePrivateInput(path string, _ fs.FileInfo) error { return platformfs.Validate(path, true) }
