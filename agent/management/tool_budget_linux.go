//go:build linux

package management

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

func runBudgetedTool(ctx context.Context, j Job, c Config, m ToolManifest, args []string) Result {
	if _, e := exec.LookPath("systemd-run"); e != nil {
		return safeResultError("Unsupported runtime: systemd resource controls are required for optional tools")
	}
	unit := "northgate-tool-" + j.ID
	binary := filepath.Join(toolsRoot(c), m.ID, m.Entrypoint)
	all := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=" + unit, "--property=Type=exec", "--property=CPUQuota=" + fmt.Sprint(m.Budget.CPUPercent) + "%", "--property=MemoryMax=" + fmt.Sprint(m.Budget.MemoryMiB) + "M", "--property=TasksMax=32", "--property=IOWeight=20", "--property=Nice=10", "--property=RuntimeMaxSec=" + fmt.Sprint(m.Budget.Seconds), "--property=KillMode=control-group", "--property=NoNewPrivileges=yes", "--property=WorkingDirectory=" + filepath.Join(toolsRoot(c), m.ID), "--", binary}
	all = append(all, args...)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go enforceToolDisk(runCtx, cancel, filepath.Join(toolsRoot(c), m.ID), int64(m.Budget.DiskMiB)<<20)
	defer func() {
		stop, cancelStop := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelStop()
		_ = exec.CommandContext(stop, "/usr/bin/systemctl", "stop", unit).Run()
	}()
	return runCommand(runCtx, exec.CommandContext(runCtx, "/usr/bin/systemd-run", all...), m.Budget.OutputKiB*1024)
}
