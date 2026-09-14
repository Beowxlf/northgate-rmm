//go:build windows

package collector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OSVersion uses the native version API; no shell or registry enumeration.
func (NativeSource) OSVersion(ctx context.Context) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v := windows.RtlGetVersion()
	return map[string]string{"os.id": "windows", "os.version_id": fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)}, nil
}

// BootID derives a protocol UUID from the kernel boot timestamp, stable across
// agent restarts. Query failure remains unknown instead of inventing a boot.
func (NativeSource) BootID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var info struct {
		BootTime      int64
		CurrentTime   int64
		TimeZoneBias  int64
		TimeZoneID    uint32
		Reserved      uint32
		BootTimeBias  uint64
		SleepTimeBias uint64
	}
	var returned uint32
	if err := windows.NtQuerySystemInformation(3, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &returned); err != nil {
		return "", err
	}
	if returned < 8 || info.BootTime <= 0 {
		return "", ErrMalformed
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("northgate-windows-boot:%d", info.BootTime)))
	digest[6] = (digest[6] & 15) | 0x50
	digest[8] = (digest[8] & 63) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16]), nil
}

func (NativeSource) DiskUsage(ctx context.Context, name string) (DiskUsage, error) {
	if name != "/" {
		return DiskUsage{}, ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return DiskUsage{}, err
	}
	directory, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return DiskUsage{}, err
	}
	root, err := windows.UTF16PtrFromString(filepath.VolumeName(directory) + `\`)
	if err != nil {
		return DiskUsage{}, err
	}
	var free, total, allFree uint64
	if err := windows.GetDiskFreeSpaceEx(root, &free, &total, &allFree); err != nil {
		return DiskUsage{}, err
	}
	return DiskUsage{TotalBytes: total, FreeBytes: free}, nil
}
