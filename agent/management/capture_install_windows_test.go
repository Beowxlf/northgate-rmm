//go:build windows

package management

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCaptureInstallerHiddenAncestors(t *testing.T) {
	// Exercise the actual non-mutating installer path check on Windows. ProgramData
	// is hidden, so Test-Path succeeds while Get-Item without -Force can fail.
	script := strings.Split(captureWindows, "$signature=")[0] + "\n[Console]::Out.Write('validated')"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedScript(script))
	cmd.Stdin = strings.NewReader("{}")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "validated") {
		t.Fatalf("hidden ancestor check failed: %v %s", err, output)
	}
}
