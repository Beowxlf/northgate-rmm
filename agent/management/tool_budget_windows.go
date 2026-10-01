//go:build windows

package management

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func runBudgetedTool(ctx context.Context, j Job, c Config, m ToolManifest, args []string) Result {
	result := Result{State: "failed", Exit: -1, Identity: executionIdentity()}
	if m.ID == "sysinternals" && text(j, "profile") == "trust" {
		if len(args) != 7 {
			return safeResultError("Invalid trust inspection recipe")
		}
		path, release, err := pinSysinternalsTrustFile(c, args[len(args)-1])
		if err != nil {
			return safeResultError(err.Error())
		}
		defer release()
		args = append(append([]string{}, args[:len(args)-1]...), path)
	}
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return safeResultError("Cannot create tool resource boundary")
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_JOB_MEMORY | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	limits.BasicLimitInformation.ActiveProcessLimit = 32
	limits.JobMemoryLimit = uintptr(m.Budget.MemoryMiB) << 20
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return safeResultError("Cannot enforce tool memory budget")
	}
	cpu := struct {
		Flags uint32
		Rate  uint32
	}{1 | 4, uint32(m.Budget.CPUPercent * 100)}
	if _, e = windows.SetInformationJobObject(job, 15, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); e != nil {
		return safeResultError("Cannot enforce tool CPU budget")
	}
	var read, write windows.Handle
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if e = windows.CreatePipe(&read, &write, &sa, 0); e != nil {
		return safeResultError("Cannot create output channel")
	}
	defer func() {
		if write != 0 {
			windows.CloseHandle(write)
		}
	}()
	if e = windows.SetHandleInformation(read, windows.HANDLE_FLAG_INHERIT, 0); e != nil {
		windows.CloseHandle(read)
		return safeResultError("Cannot protect output channel")
	}
	output := os.NewFile(uintptr(read), "tool-output")
	defer output.Close()
	nul, _ := windows.UTF16PtrFromString("NUL")
	input, e := windows.CreateFile(nul, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		return safeResultError("Cannot create input channel")
	}
	defer windows.CloseHandle(input)
	binary := filepath.Join(toolsRoot(c), m.ID, m.Entrypoint)
	if m.ID == "sysinternals" && text(j, "profile") == "trust" {
		binary = filepath.Join(toolsRoot(c), m.ID, "sigcheck.exe")
	}
	app, _ := windows.UTF16PtrFromString(binary)
	command, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{binary}, args...)))
	directory, _ := windows.UTF16PtrFromString(filepath.Join(toolsRoot(c), m.ID))
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Flags: windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE, StdInput: input, StdOutput: write, StdErr: write}
	pi := windows.ProcessInformation{}
	if e = windows.CreateProcess(app, command, nil, nil, true, windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.BELOW_NORMAL_PRIORITY_CLASS, nil, directory, &startup, &pi); e != nil {
		return safeResultError("Tool cannot launch; verify runtime dependencies")
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	defer windows.TerminateJobObject(job, 1)
	if e = windows.AssignProcessToJobObject(job, pi.Process); e != nil {
		windows.TerminateProcess(pi.Process, 1)
		return safeResultError("Cannot attach tool resource boundary")
	}
	buffer := &boundedOutput{limit: m.Budget.OutputKiB * 1024}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(buffer, output); close(done) }()
	if _, e = windows.ResumeThread(pi.Thread); e != nil {
		return safeResultError("Cannot start bounded tool")
	}
	windows.CloseHandle(write)
	write = 0
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go enforceToolDisk(runCtx, cancel, filepath.Join(toolsRoot(c), m.ID), int64(m.Budget.DiskMiB)<<20)
	for {
		status, _ := windows.WaitForSingleObject(pi.Process, 100)
		if status == windows.WAIT_OBJECT_0 {
			break
		}
		if runCtx.Err() != nil {
			windows.TerminateJobObject(job, 1)
			result.State = "cancelled"
			result.Error = "Tool cancelled or exceeded its resource/time budget"
			break
		}
	}
	var exit uint32
	_ = windows.GetExitCodeProcess(pi.Process, &exit)
	result.Exit = int(exit)
	windows.TerminateJobObject(job, 1)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		output.Close()
		<-done
	}
	decoded, expanded := decodeWindowsToolOutput(m.ID, buffer.String(), min(m.Budget.OutputKiB*1024, MaxOutput))
	result.Output = decoded
	result.Truncated = buffer.truncated || expanded
	if result.State != "cancelled" {
		if exit == 0 {
			result.State = "completed"
		} else {
			result.Error = "Tool exited unsuccessfully; review bounded output"
		}
	}
	return result
}
