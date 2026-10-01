//go:build windows

package management

import (
	"context"
	_ "embed"
	"encoding/json"
	templates "github.com/Beowxlf/northgate-rmm/agent/packaging/tools"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed capture_install_windows.ps1
var captureWindows string

func platformInstallCapture(ctx context.Context, j Job, c Config, binary, configuration string) Result {
	installer := filepath.Join(filepath.Dir(binary), "Install-Wxlfgar.ps1")
	if e := os.WriteFile(installer, []byte(templates.Windows), 0600); e != nil {
		return safeResultError("Cannot stage capture installer")
	}
	raw, _ := json.Marshal(map[string]string{"binary": binary, "sha256": text(j, "sha256"), "configuration": configuration, "signer": c.UpdateSigner, "installer": installer, "identity": c.IdentityFile})
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedScript(captureWindows))
	cmd.Stdin = strings.NewReader(string(raw))
	return runCommand(ctx, cmd, MaxOutput)
}
