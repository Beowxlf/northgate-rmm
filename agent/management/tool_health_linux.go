//go:build linux

package management

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func startupObservation(ctx context.Context, c Config) Result {
	records := []map[string]string{}
	for _, folder := range []string{"/etc/systemd/system", "/etc/cron.d", "/etc/init.d"} {
		entries, e := os.ReadDir(folder)
		if e != nil {
			records = append(records, map[string]string{"path": folder, "state": "unavailable"})
			continue
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return safeResultError("Startup observation cancelled")
			}
			if len(records) >= 500 {
				break
			}
			path := filepath.Join(folder, entry.Name())
			target, _ := os.Readlink(path)
			records = append(records, map[string]string{"path": path, "symlink_target": target})
		}
	}
	b, _ := json.Marshal(records)
	return Result{State: "completed", Exit: 0, Output: string(b), Identity: executionIdentity()}
}

func hostHealth(c Config) map[string]any {
	result := map[string]any{}
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && (f[0] == "MemTotal:" || f[0] == "MemAvailable:") {
				n, _ := strconv.ParseUint(f[1], 10, 64)
				result[strings.TrimSuffix(f[0], ":")] = n * 1024
			}
		}
	}
	if b, e := os.ReadFile("/proc/stat"); e == nil {
		f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		var total, idle uint64
		for i, s := range f[1:] {
			if i >= 8 {
				break
			}
			n, _ := strconv.ParseUint(s, 10, 64)
			total += n
			if i == 3 || i == 4 {
				idle += n
			}
		}
		result["cpu_total_ticks"] = total
		result["cpu_idle_ticks"] = idle
	}
	var stat unix.Statfs_t
	if unix.Statfs(c.Root, &stat) == nil {
		result["disk_free_bytes"] = stat.Bavail * uint64(stat.Bsize)
		result["disk_total_bytes"] = stat.Blocks * uint64(stat.Bsize)
	}
	return result
}
