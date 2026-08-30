//go:build linux

package collector

import (
	"context"
	"errors"
	"testing"
)

func TestNativeDiskUsageRejectsNonRootPath(t *testing.T) {
	_, err := (NativeSource{}).DiskUsage(context.Background(), "/tmp")
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DiskUsage() error = %v, want ErrUnsupported", err)
	}
}
