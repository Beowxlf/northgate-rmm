//go:build !windows

package platformfs

// Unix ownership and durability checks remain in each native storage adapter.
func Protect(string) error { return nil }
