//go:build windows

package management

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func sysinternalsDefaultTarget() (string, error) {
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", errors.New("Cannot resolve the Windows directory")
	}
	return filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`), nil
}

func trustFinalPath(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		return "", errors.New("Cannot resolve the selected file")
	}
	path := strings.TrimPrefix(windows.UTF16ToString(buffer[:n]), `\\?\`)
	if err = validateWindowsTrustPath(path); err != nil {
		return "", err
	}
	return path, nil
}

// Keep parents immovable and the inspected file read-only until the bounded
// child exits. Checking a path with Stat alone leaves a replace-before-launch
// race, including replacement by a junction or by a newly oversized file.
func pinSysinternalsTrustFile(c Config, path string) (string, func(), error) {
	handles := []windows.Handle{}
	closeAll := func() {
		for i := len(handles) - 1; i >= 0; i-- {
			windows.CloseHandle(handles[i])
		}
		handles = nil
	}
	reject := func(message string) (string, func(), error) {
		closeAll()
		return "", func() {}, errors.New(message)
	}
	if err := validateWindowsTrustPath(path); err != nil {
		return reject(err.Error())
	}
	drive, _ := windows.UTF16PtrFromString(path[:3])
	if windows.GetDriveType(drive) != windows.DRIVE_FIXED {
		return reject("Trust inspection requires a local fixed drive")
	}
	parts := strings.Split(path[3:], `\`)
	current := path[:3]
	var target windows.Handle
	for index := -1; index < len(parts); index++ {
		if index >= 0 {
			current = filepath.Join(current, parts[index])
		}
		isFile := index == len(parts)-1
		access, share := uint32(windows.FILE_READ_ATTRIBUTES), uint32(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
		if isFile {
			access, share = windows.GENERIC_READ, windows.FILE_SHARE_READ
		}
		name, _ := windows.UTF16PtrFromString(current)
		handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return reject("Cannot pin the selected file or its parent directories")
		}
		handles = append(handles, handle)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return reject("Reparse paths are not permitted for trust inspection")
		}
		if isFile {
			kind, err := windows.GetFileType(handle)
			size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
			if err != nil || kind != windows.FILE_TYPE_DISK || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || size > 64<<20 {
				return reject("Select one regular file no larger than 64 MiB")
			}
			target = handle
		} else if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return reject("Invalid parent directory")
		}
	}
	actual, err := trustFinalPath(target)
	if err != nil {
		return reject(err.Error())
	}
	for _, protected := range []string{c.Root, filepath.Dir(c.IdentityFile)} {
		if !filepath.IsAbs(protected) {
			return reject("Worker private directories are not configured")
		}
		name, err := windows.UTF16PtrFromString(protected)
		if err != nil {
			return reject("Worker private directory is invalid")
		}
		handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return reject("Cannot resolve worker private directories")
		}
		handles = append(handles, handle)
		resolved, err := trustFinalPath(handle)
		if err != nil || within(strings.ToLower(resolved), strings.ToLower(actual)) {
			return reject("Select a file outside worker identity/state")
		}
	}
	return actual, closeAll, nil
}
