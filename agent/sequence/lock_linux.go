//go:build linux

package sequence

import (
	"errors"
	"os"
	"syscall"
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
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(fileInfo, pathInfo) ||
		!privateFile(fileInfo) || fileInfo.Size() != 0 {
		file.Close()
		return nil, ErrCorrupt
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &fileLock{file: file}, nil
}

func (lock *fileLock) Close() error {
	return errors.Join(syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN), lock.file.Close())
}
