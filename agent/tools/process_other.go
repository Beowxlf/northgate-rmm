//go:build !windows

package tools

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}
