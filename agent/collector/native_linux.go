//go:build linux

package collector

import (
	"context"
	"math/bits"
	"syscall"
)

func (NativeSource) DiskUsage(ctx context.Context, name string) (DiskUsage, error) {
	if err := ctx.Err(); err != nil {
		return DiskUsage{}, err
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(name, &stat); err != nil {
		return DiskUsage{}, err
	}
	if stat.Bsize <= 0 {
		return DiskUsage{}, ErrMalformed
	}
	blockSize := uint64(stat.Bsize)
	totalHigh, totalLow := bits.Mul64(stat.Blocks, blockSize)
	freeHigh, freeLow := bits.Mul64(stat.Bavail, blockSize)
	if totalHigh != 0 || freeHigh != 0 {
		return DiskUsage{}, ErrLimitExceeded
	}
	return DiskUsage{TotalBytes: totalLow, FreeBytes: freeLow}, nil
}
