//go:build windows

package spool

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

type fileLock struct {
	file *os.File
}

func acquireDirectoryLock(root *os.Root) (directoryLock, error) {
	file, err := root.OpenFile(".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	fileInfo, fileErr := file.Stat()
	pathInfo, pathErr := root.Lstat(".lock")
	if fileErr != nil || pathErr != nil || !fileInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(fileInfo, pathInfo) || fileInfo.Size() != 0 {
		file.Close()
		return nil, ErrCorrupt
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &fileLock{file: file}, nil
}

func (lock *fileLock) Close() error {
	return lock.file.Close()
}
