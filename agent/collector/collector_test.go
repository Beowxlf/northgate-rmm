package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeSource struct {
	files     map[string]string
	hostname  string
	platform  string
	arch      string
	disk      DiskUsage
	diskError error
}

func (source fakeSource) ReadFile(ctx context.Context, name string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, ok := source.files[name]
	if !ok {
		return nil, errors.New("missing synthetic file")
	}
	if int64(len(value)) > maxBytes {
		return nil, ErrLimitExceeded
	}
	return []byte(value), nil
}

func (source fakeSource) Hostname(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return source.hostname, nil
}

func (source fakeSource) Platform() string     { return source.platform }
func (source fakeSource) Architecture() string { return source.arch }
func (source fakeSource) DiskUsage(context.Context, string) (DiskUsage, error) {
	return source.disk, source.diskError
}

func validSource() fakeSource {
	return fakeSource{
		files: map[string]string{
			"/etc/os-release":                 "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			"/proc/sys/kernel/random/boot_id": "123e4567-e89b-42d3-a456-426614174000\n",
		},
		hostname: "synthetic-canary",
		platform: "linux",
		arch:     "amd64",
		disk:     DiskUsage{TotalBytes: 10 << 30, FreeBytes: 4 << 30},
	}
}

func TestRunnerCollectsAllowlistedInventory(t *testing.T) {
	runner, err := NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	result, err := runner.Run(context.Background(), validSource())
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Complete || len(result.Issues) != 0 {
		t.Fatalf("unexpected partial result: %#v", result)
	}
	if result.Fields["os.id"] != "debian" || result.Fields["agent.version"] != "0.2.0" {
		t.Fatalf("missing expected fields: %#v", result.Fields)
	}
}

func TestRunnerReturnsBoundedPartialIssue(t *testing.T) {
	source := validSource()
	source.diskError = errors.New("sensitive path must not escape")
	runner, err := NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	result, err := runner.Run(context.Background(), source)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Complete || len(result.Issues) != 1 || result.Issues[0].Code != "read_failed" {
		t.Fatalf("unexpected issue result: %#v", result)
	}
	if strings.Contains(result.Issues[0].Code, "sensitive") {
		t.Fatal("issue exposed an operating-system error")
	}
}

func TestOSReleaseRejectsDuplicateAllowlistedField(t *testing.T) {
	source := validSource()
	source.files["/etc/os-release"] += "ID=other\n"
	_, err := (OSReleaseCollector{}).Collect(context.Background(), source)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("Collect() error = %v, want ErrMalformed", err)
	}
}

func TestRunnerHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner, err := NewRunner("0.2.0")
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}
	if _, err := runner.Run(ctx, validSource()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func FuzzParseOSRelease(f *testing.F) {
	f.Add([]byte("ID=debian\nVERSION_ID=\"12\"\n"))
	f.Add([]byte("ID=debian\nID=duplicate\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseOSRelease(raw)
	})
}
