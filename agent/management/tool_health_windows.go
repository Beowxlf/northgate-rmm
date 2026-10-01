//go:build windows

package management

import (
	"context"
	"golang.org/x/sys/windows"
	"os/exec"
	"unsafe"
)

func startupObservation(ctx context.Context, c Config) Result {
	script := `$ErrorActionPreference='Stop';$items=@();foreach($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')){if(Test-Path -LiteralPath $path){$key=Get-Item -LiteralPath $path;foreach($name in $key.GetValueNames()){$items+=@{type='registry';path=$path;name=$name;command=[string]$key.GetValue($name)}}}};$items+=@(Get-ScheduledTask|Sort-Object TaskPath,TaskName|Select-Object -First 400 TaskPath,TaskName,State);$items|ConvertTo-Json -Depth 4 -Compress`
	return runCommand(ctx, exec.CommandContext(ctx, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedScript(script)), 128<<10)
}

func hostHealth(c Config) map[string]any {
	result := map[string]any{}
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	memory := struct {
		Length, Load                                                                         uint32
		Total, Available, PageTotal, PageAvailable, VirtualTotal, VirtualAvailable, Extended uint64
	}{}
	memory.Length = uint32(unsafe.Sizeof(memory))
	if ok, _, _ := kernel.NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&memory))); ok != 0 {
		result["MemTotal"] = memory.Total
		result["MemAvailable"] = memory.Available
	}
	var idle, user, system windows.Filetime
	if ok, _, _ := kernel.NewProc("GetSystemTimes").Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&system)), uintptr(unsafe.Pointer(&user))); ok != 0 {
		ticks := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
		result["cpu_total_ticks"] = ticks(user) + ticks(system)
		result["cpu_idle_ticks"] = ticks(idle)
	}
	path, _ := windows.UTF16PtrFromString(c.Root)
	var free, total, available uint64
	if ok, _, _ := kernel.NewProc("GetDiskFreeSpaceExW").Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&available)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free))); ok != 0 {
		result["disk_free_bytes"] = available
		result["disk_total_bytes"] = total
	}
	return result
}
