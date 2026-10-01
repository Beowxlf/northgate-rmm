//go:build !windows

package main

import (
	"errors"
	"io/fs"
)

func validatePlatformState(string) error { return nil }
func validatePrivateInput(_ string, info fs.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("private input permissions are too broad")
	}
	return nil
}
