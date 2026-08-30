package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
)

// NativeSource performs only fixed-path reads requested by allowlisted
// collectors. It never invokes a shell or subprocess.
type NativeSource struct{}

var allowedSourceFiles = map[string]int64{
	"/etc/os-release":                 MaxSourceFileBytes,
	"/proc/sys/kernel/random/boot_id": 64,
}

func (NativeSource) ReadFile(ctx context.Context, name string, maxBytes int64) ([]byte, error) {
	allowedBytes, allowed := allowedSourceFiles[name]
	if !allowed {
		return nil, ErrUnsupported
	}
	if maxBytes <= 0 || maxBytes > allowedBytes {
		return nil, ErrLimitExceeded
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, ErrLimitExceeded
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (NativeSource) Hostname(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return os.Hostname()
}

func (NativeSource) Platform() string     { return runtime.GOOS }
func (NativeSource) Architecture() string { return runtime.GOARCH }
