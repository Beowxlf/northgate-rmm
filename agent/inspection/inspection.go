// Package inspection provides fixed, read-only diagnostic collectors.
package inspection

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

const MaxBytes = 512 * 1024
const MaxRows = 2000

type Result struct {
	Actor     string              `json:"execution_identity"`
	Schema    int                 `json:"schema"`
	Category  string              `json:"category"`
	Platform  string              `json:"platform"`
	Version   string              `json:"agent_version"`
	Collected string              `json:"collected_at"`
	Duration  int64               `json:"duration_ms"`
	ExitCode  int                 `json:"exit_code"`
	Status    string              `json:"status"`
	Error     string              `json:"error"`
	Records   []map[string]string `json:"records"`
}

type limitedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := MaxBytes - b.Len()
	if n > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

var linux = map[string][]string{
	"processes": {"/usr/bin/ps", "-eo", "pid=,ppid=,user=,comm="},
	"services":  {"/usr/bin/systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"},
	"network":   {"/usr/bin/ss", "-H", "-tuan"},
	"users":     {"/usr/bin/getent", "passwd"},
	"software":  {"/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n"},
	"tasks":     {"/usr/bin/systemctl", "list-unit-files", "--type=timer", "--no-pager", "--no-legend"},
	"startup":   {"/usr/bin/systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"},
	"storage":   {"/usr/bin/df", "-P", "-k"},
	"health":    {"/usr/bin/systemctl", "--failed", "--no-pager", "--no-legend", "--plain"},
}
var windows = map[string]string{
	"processes": `Get-Process | ForEach-Object { @{id=[string]$_.Id;name=$_.ProcessName;session=[string]$_.SessionId} }`,
	"services":  `Get-CimInstance Win32_Service | ForEach-Object { @{id=$_.Name;name=$_.DisplayName;state=$_.State;start_mode=$_.StartMode;account=$_.StartName} }`,
	"network":   `$r=@(Get-NetTCPConnection | ForEach-Object { @{id=('TCP/'+$_.LocalAddress+'/'+$_.LocalPort+'/'+$_.RemoteAddress+'/'+$_.RemotePort);protocol='TCP';local=($_.LocalAddress+':'+$_.LocalPort);remote=($_.RemoteAddress+':'+$_.RemotePort);state=[string]$_.State;pid=[string]$_.OwningProcess} }); $r+=@(Get-NetUDPEndpoint | ForEach-Object { @{id=('UDP/'+$_.LocalAddress+'/'+$_.LocalPort);protocol='UDP';local=($_.LocalAddress+':'+$_.LocalPort);remote='';state='';pid=[string]$_.OwningProcess} }); $r`,
	"users":     `Get-LocalUser | ForEach-Object { @{id=[string]$_.SID;name=$_.Name;enabled=[string]$_.Enabled;source=[string]$_.PrincipalSource} }`,
	"software":  `Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName | ForEach-Object { @{id=$_.PSPath;name=[string]$_.DisplayName;version=[string]$_.DisplayVersion;publisher=[string]$_.Publisher} }`,
	"tasks":     `Get-ScheduledTask | ForEach-Object { @{id=($_.TaskPath+$_.TaskName);name=$_.TaskName;state=[string]$_.State;account=[string]$_.Principal.UserId} }`,
	"startup":   `$r=@();foreach($p in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) { if(Test-Path $p) { foreach($n in (Get-Item $p).GetValueNames()) { $r+=@{id=($p+'/'+$n);name=$n;location=$p} } } }; $r`,
	"storage":   `Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { @{id=$_.DeviceID;name=$_.VolumeName;size_bytes=[string]$_.Size;free_bytes=[string]$_.FreeSpace;filesystem=$_.FileSystem} }`,
	"health":    `Get-CimInstance Win32_OperatingSystem | ForEach-Object { @{id='os';name=$_.Caption;version=$_.Version;last_boot=[string]$_.LastBootUpTime.ToUniversalTime().ToString('o');free_memory_kb=[string]$_.FreePhysicalMemory;total_memory_kb=[string]$_.TotalVisibleMemorySize} }`,
}

func Collect(ctx context.Context, category, version string) (Result, error) {
	start := time.Now()
	r := Result{Schema: 1, Category: category, Platform: runtime.GOOS, Version: version, Collected: start.UTC().Format(time.RFC3339Nano), Status: "ok", Records: []map[string]string{}}
	if _, ok := linux[category]; !ok {
		return r, errors.New("unsupported inspection category")
	}
	if actor, err := user.Current(); err == nil {
		r.Actor = actor.Username
	} else {
		r.Actor = "unknown"
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		script := `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);$rows=@(& {` + windows[category] + `});ConvertTo-Json -InputObject $rows -Depth 4 -Compress`
		units := utf16.Encode([]rune(script))
		raw := make([]byte, len(units)*2)
		for i, u := range units {
			binary.LittleEndian.PutUint16(raw[i*2:], u)
		}
		cmd = exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	} else if runtime.GOOS == "linux" {
		args := linux[category]
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	} else {
		return r, errors.New("unsupported inspection platform")
	}
	var out, stderr limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	r.Duration = time.Since(start).Milliseconds()
	if err != nil {
		r.Status = "error"
		r.ExitCode = -1
		if cmd.ProcessState != nil {
			r.ExitCode = cmd.ProcessState.ExitCode()
		}
		r.Error = "Collector failed or permission denied; collection is not a complete system view."
		if ctx.Err() != nil {
			r.Error = "Collector timed out."
		}
		return r, nil
	}
	if out.exceeded {
		r.Status = "partial"
		r.Error = "Output limit reached; do not use as a complete baseline."
	}
	if runtime.GOOS == "windows" {
		if json.Unmarshal(bytes.TrimPrefix(out.Bytes(), []byte{239, 187, 191}), &r.Records) != nil {
			r.Status = "error"
			r.Error = "Collector returned invalid JSON."
			r.Records = []map[string]string{}
		}
	} else {
		r.Records = parseLinux(category, out.String())
	}
	if len(r.Records) > MaxRows {
		r.Records = r.Records[:MaxRows]
		r.Status = "partial"
		r.Error = "Row limit reached; do not use as a complete baseline."
	}
	return r, nil
}
func Write(ctx context.Context, category, version string, output io.Writer) int {
	r, err := Collect(ctx, category, version)
	if err != nil {
		return 2
	}
	if json.NewEncoder(output).Encode(r) != nil {
		return 1
	}
	return 0
}
func parseLinux(category, output string) []map[string]string {
	rows := []map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		r := map[string]string{}
		switch category {
		case "processes":
			if len(f) < 4 {
				continue
			}
			r = map[string]string{"id": f[0], "parent_pid": f[1], "user": f[2], "name": strings.Join(f[3:], " ")}
		case "users":
			p := strings.Split(line, ":")
			if len(p) < 7 {
				continue
			}
			r = map[string]string{"id": p[0], "uid": p[2], "gid": p[3], "home": p[5], "shell": p[6]}
		case "network":
			if len(f) < 6 {
				continue
			}
			r = map[string]string{"id": f[0] + "/" + f[4] + "/" + f[5], "protocol": f[0], "state": f[1], "local": f[4], "remote": f[5]}
		case "software":
			p := strings.Split(line, "\t")
			if len(p) < 3 || p[2] != "installed" {
				continue
			}
			r = map[string]string{"id": p[0], "version": p[1], "state": p[2]}
		case "storage":
			if len(f) < 6 || f[0] == "Filesystem" {
				continue
			}
			r = map[string]string{"id": f[5], "filesystem": f[0], "size_kb": f[1], "used_kb": f[2], "available_kb": f[3], "used_percent": f[4]}
		case "tasks", "startup":
			if len(f) < 2 {
				continue
			}
			r = map[string]string{"id": f[0], "state": f[1]}
		default:
			if len(f) < 4 {
				continue
			}
			r = map[string]string{"id": f[0], "load": f[1], "active": f[2], "state": f[3], "description": strings.Join(f[4:], " ")}
		}
		rows = append(rows, r)
	}
	return rows
}
