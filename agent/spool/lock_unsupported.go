//go:build !linux

package spool

import (
	"os"
	"sync"
)

var developmentLocks = struct {
	sync.Mutex
	open map[string]struct{}
}{open: make(map[string]struct{})}

type developmentLock struct {
	name string
}

func acquireDirectoryLock(root *os.Root) (directoryLock, error) {
	name := root.Name()
	developmentLocks.Lock()
	defer developmentLocks.Unlock()
	if _, exists := developmentLocks.open[name]; exists {
		return nil, ErrLocked
	}
	developmentLocks.open[name] = struct{}{}
	return &developmentLock{name: name}, nil
}

func (lock *developmentLock) Close() error {
	developmentLocks.Lock()
	defer developmentLocks.Unlock()
	delete(developmentLocks.open, lock.name)
	return nil
}
