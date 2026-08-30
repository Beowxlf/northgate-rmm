//go:build !linux

package collector

import "context"

func (NativeSource) DiskUsage(context.Context, string) (DiskUsage, error) {
	return DiskUsage{}, ErrUnsupported
}
