// Package tools exposes fixed installed capabilities; capture authorization stays in Wxlfgar.
package tools

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
)

func Binary() string {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\NorthGateWxlfgar\wulfgar.exe`
	}
	return "/usr/local/libexec/northgate-wxlfgar/wulfgar"
}
func Inventory(output io.Writer) int {
	state := "not_installed"
	if info, e := os.Stat(Binary()); e == nil && info.Mode().IsRegular() {
		state = "installed_requires_authenticated_probe"
	}
	if json.NewEncoder(output).Encode(map[string]any{"schema": 1, "tools": []map[string]string{{"name": "wxlfgar", "state": state, "capability": "network_capture"}}}) != nil {
		return 1
	}
	return 0
}
func Capture(ctx context.Context, input io.Reader, output io.Writer) int {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, Binary(), "--rmm")
	cmd.Stdin = io.LimitReader(input, 16385)
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	hideWindow(cmd)
	if cmd.Run() != nil {
		return 1
	}
	return 0
}
