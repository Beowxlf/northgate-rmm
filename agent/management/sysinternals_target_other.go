//go:build !windows

package management

import "errors"

func sysinternalsDefaultTarget() (string, error) {
	return "", errors.New("sysinternals requires Windows")
}
