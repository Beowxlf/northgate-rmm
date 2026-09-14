//go:build !windows

package management

import (
	"context"
	"errors"
)

func setCredentialPassword(context.Context, Config, []byte) error {
	return errors.New("credential rotation requires Windows")
}
func verifyCredentialPassword(context.Context, Config, []byte) error {
	return errors.New("credential rotation requires Windows")
}
