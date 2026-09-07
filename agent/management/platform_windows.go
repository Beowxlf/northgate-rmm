//go:build windows

package management

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Beowxlf/northgate-rmm/agent/internal/platformfs"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

//go:embed windows_actions.ps1
var windowsActions string

func defaultConfig() string { return `C:\ProgramData\NorthGateRMMManagement\config.json` }
func requirePrivileged() error {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil || u.User.Sid.String() != "S-1-5-18" {
		return errors.New("management worker requires LocalSystem")
	}
	return nil
}
func executionIdentity() string { return `NT AUTHORITY\SYSTEM` }

var bootOnce sync.Once
var bootIdentifier string

func bootID() string {
	bootOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		b, e := cmd.Output()
		if e == nil {
			bootIdentifier = strings.TrimSpace(string(b))
		}
	})
	return bootIdentifier
}
func captureInstalled() bool {
	_, e := os.Stat(`C:\Program Files\NorthGateWxlfgar\wulfgar.exe`)
	return e == nil
}
func platformRecoveryStatus() map[string]any {
	return map[string]any{"managed_account": "ng-rmm-recovery", "status": "query recovery metadata"}
}
func platformCapabilities() map[string]any {
	_, winget := exec.LookPath("winget.exe")
	_, bitlocker := os.Stat(`C:\Windows\System32\WindowsPowerShell\v1.0\Modules\BitLocker`)
	_, dumpcap := os.Stat(`C:\Program Files\Wireshark\dumpcap.exe`)
	_, npcap := os.Stat(`C:\Windows\System32\drivers\npcap.sys`)
	return map[string]any{"shell": true, "files": true, "services": true, "processes": true, "logs": true, "posture": true, "recovery": true, "bitlocker": bitlocker == nil, "isolation": true, "packages": winget == nil, "dumpcap": dumpcap == nil, "npcap_driver_installed": npcap == nil, "package_requirement": "WinGet must be installed and callable under SYSTEM"}
}
func validateWorkerPaths(path string, c Config) error {
	for _, p := range []string{path, c.Roots, filepath.Dir(path)} {
		if e := platformfs.Validate(p, true); e != nil {
			return e
		}
	}
	if _, e := os.Stat(c.Root); e == nil {
		return platformfs.Validate(c.Root, true)
	}
	return nil
}
func encodedScript(text string) string {
	units := utf16.Encode([]rune(text))
	b := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[i*2:], u)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		kill := exec.CommandContext(ctx, `C:\Windows\System32\taskkill.exe`, "/PID", fmt.Sprint(cmd.Process.Pid), "/T", "/F")
		kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = kill.Run()
		return cmd.Process.Kill()
	}
}
func scriptCommand(ctx context.Context, path string) *exec.Cmd {
	// The signed job and pinned script digest authorize this private script file.
	// Limit execution-policy handling to this child; never change machine policy.
	return exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
}
func platformAction(ctx context.Context, j Job, c Config) Result {
	binary, _ := os.Executable()
	v := map[string]any{"action": j.Action, "params": j.Params, "root": c.Root, "server_ip": c.ServerIP, "job": j.ID, "binary": binary, "config": defaultConfig()}
	b, _ := json.Marshal(v)
	cmd := exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedScript(windowsActions))
	cmd.Stdin = strings.NewReader(string(b))
	return runCommand(ctx, cmd, MaxOutput)
}

type windowsTerminal struct {
	input, output         *os.File
	console, process, job windows.Handle
	once                  sync.Once
	waitOnce              sync.Once
	waitErr               error
}

func openTerminal(ctx context.Context, columns, rows int) (terminal, error) {
	inputRead, inputWrite, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	outputRead, outputWrite, e := os.Pipe()
	if e != nil {
		inputRead.Close()
		inputWrite.Close()
		return nil, e
	}
	t := &windowsTerminal{input: inputWrite, output: outputRead}
	failed := true
	defer func() {
		inputRead.Close()
		outputWrite.Close()
		if failed {
			t.Close()
		}
	}()
	if e = windows.CreatePseudoConsole(windows.Coord{X: int16(columns), Y: int16(rows)}, windows.Handle(inputRead.Fd()), windows.Handle(outputWrite.Fd()), 0, &t.console); e != nil {
		return nil, e
	}
	attrs, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		return nil, e
	}
	defer attrs.Delete()
	// PSEUDOCONSOLE takes the opaque handle value, not a Go pointer to it.
	// Keep the native integer as uintptr all the way into the Windows call.
	updateAttribute := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	ok, _, callErr := updateAttribute.Call(uintptr(unsafe.Pointer(attrs.List())), 0,
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(t.console), unsafe.Sizeof(t.console), 0, 0)
	runtime.KeepAlive(attrs)
	if ok == 0 {
		return nil, callErr
	}
	// Null standard handles select ConPTY; do not inherit the service/test host's redirected pipes.
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES}, ProcThreadAttributeList: attrs.List()}
	app, _ := windows.UTF16PtrFromString(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
	command, _ := windows.UTF16PtrFromString(`powershell.exe -NoLogo -NoProfile`)
	info := windows.ProcessInformation{}
	if e = windows.CreateProcess(app, command, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_SUSPENDED, nil, nil, &startup.StartupInfo, &info); e != nil {
		return nil, e
	}
	t.process = info.Process
	defer windows.CloseHandle(info.Thread)
	t.job, e = windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, e
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(t.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return nil, e
	}
	if e = windows.AssignProcessToJobObject(t.job, t.process); e != nil {
		return nil, e
	}
	if _, e = windows.ResumeThread(info.Thread); e != nil {
		return nil, e
	}
	failed = false
	return t, nil
}
func (t *windowsTerminal) Read(b []byte) (int, error)  { return t.output.Read(b) }
func (t *windowsTerminal) Write(b []byte) (int, error) { return t.input.Write(b) }
func (t *windowsTerminal) Resize(c, r int) error {
	return windows.ResizePseudoConsole(t.console, windows.Coord{X: int16(c), Y: int16(r)})
}
func (t *windowsTerminal) Close() error {
	t.once.Do(func() {
		if t.job != 0 {
			_ = windows.TerminateJobObject(t.job, 1)
			windows.CloseHandle(t.job)
		}
		if t.process != 0 {
			_ = windows.TerminateProcess(t.process, 1)
		}
		// Drain/close the output before closing ConPTY, which may otherwise block.
		t.input.Close()
		t.output.Close()
		if t.console != 0 {
			windows.ClosePseudoConsole(t.console)
		}
		if t.process != 0 {
			_ = t.Wait()
			windows.CloseHandle(t.process)
		}
	})
	return nil
}
func (t *windowsTerminal) Wait() error {
	t.waitOnce.Do(func() {
		_, e := windows.WaitForSingleObject(t.process, windows.INFINITE)
		if e == nil {
			var code uint32
			e = windows.GetExitCodeProcess(t.process, &code)
			if code != 0 {
				e = errors.New("terminal exited with error")
			}
		}
		t.waitErr = e
	})
	return t.waitErr
}
func scheduleUpdate(ctx context.Context, j Job, c Config, path string) Result {
	return platformScheduleUpdate(ctx, j, c, path)
}
