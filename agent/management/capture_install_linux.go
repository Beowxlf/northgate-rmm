//go:build linux

package management

import (
	"context"
	_ "embed"
	templates "github.com/Beowxlf/northgate-rmm/agent/packaging/tools"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed capture_install_linux.sh
var captureLinux string

func platformInstallCapture(ctx context.Context, j Job, c Config, binary, configuration string) Result {
	directory := filepath.Dir(binary)
	for name, content := range map[string]string{"install-linux.sh": templates.Linux, "northgate-wxlfgar.service": templates.Service, "setup.sh": captureLinux} {
		if e := os.WriteFile(filepath.Join(directory, name), []byte(content), 0700); e != nil {
			return safeResultError("Cannot stage capture installer")
		}
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(directory, "setup.sh"), binary, text(j, "sha256"), configuration)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return runCommand(ctx, cmd, MaxOutput)
}
