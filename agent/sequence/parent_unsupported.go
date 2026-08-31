//go:build !linux

package sequence

// Phase 2 qualifies Linux only. Other platforms make no path-ownership claim.
func protectedParentPath(string) bool { return true }
