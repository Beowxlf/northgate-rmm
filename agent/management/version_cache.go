package management

import (
	"os"
	"sync"
	"time"
)

type versionEntry struct {
	file    os.FileInfo
	checked time.Time
	value   string
}
type versionCache struct {
	mu      sync.Mutex
	entries map[string]versionEntry
}

var installedVersions versionCache

// Version strings are display metadata, never update/signature authority.
// Refresh on file replacement/modification, after 30 seconds, or after a failed
// probe. This avoids spawning unchanged binaries after every quick operation.
func (c *versionCache) get(path string, probe func(string) string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		delete(c.entries, path)
		return ""
	}
	old, ok := c.entries[path]
	if ok && os.SameFile(old.file, info) && old.file.Size() == info.Size() && old.file.ModTime().Equal(info.ModTime()) && time.Since(old.checked) < 30*time.Second {
		return old.value
	}
	value := probe(path)
	if value == "" {
		delete(c.entries, path)
		return ""
	}
	if c.entries == nil || len(c.entries) >= 8 {
		c.entries = make(map[string]versionEntry)
	}
	c.entries[path] = versionEntry{file: info, checked: time.Now(), value: value}
	return value
}
