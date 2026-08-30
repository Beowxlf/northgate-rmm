// Package collector implements bounded, allowlisted, read-only Linux inventory
// collection without shell execution.
package collector

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxSourceFileBytes = 4096
	MaxHostnameBytes   = 253
	MaxCollectors      = 16
	MaxResultFields    = 128
	MaxKeyBytes        = 64
	MaxValueBytes      = 512
)

var (
	ErrLimitExceeded = errors.New("collector limit exceeded")
	ErrMalformed     = errors.New("collector source is malformed")
	ErrUnsupported   = errors.New("collector is unsupported")
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	versionPattern   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	unquotedPattern  = regexp.MustCompile(`^[0-9A-Za-z._-]+$`)
	osIDPattern      = regexp.MustCompile(`^[0-9a-z._-]+$`)
	osVersionPattern = regexp.MustCompile(`^[0-9A-Za-z._~^+-]+$`)
)

type DiskUsage struct {
	TotalBytes uint64
	FreeBytes  uint64
}

// Source is the minimum read-only operating-system surface used by the
// allowlisted collectors. Tests provide a synthetic implementation.
type Source interface {
	ReadFile(context.Context, string, int64) ([]byte, error)
	Hostname(context.Context) (string, error)
	Platform() string
	Architecture() string
	DiskUsage(context.Context, string) (DiskUsage, error)
}

type Collector interface {
	Name() string
	Collect(context.Context, Source) (map[string]string, error)
}

type Issue struct {
	Collector string
	Code      string
}

type Result struct {
	Platform     string
	Architecture string
	Fields       map[string]string
	Complete     bool
	Issues       []Issue
}

type Runner struct {
	collectors []Collector
}

func NewRunner(agentVersion string) (*Runner, error) {
	agent := AgentCollector{Version: agentVersion}
	if !versionPattern.MatchString(agent.Version) {
		return nil, errors.New("agent version is invalid")
	}
	return &Runner{collectors: []Collector{
		HostCollector{},
		OSReleaseCollector{},
		BootCollector{},
		RootDiskCollector{},
		agent,
	}}, nil
}

// Run returns partial inventory when an individual collector fails. Issues use
// bounded codes and never include operating-system error strings or source data.
func (runner *Runner) Run(ctx context.Context, source Source) (Result, error) {
	if len(runner.collectors) == 0 || len(runner.collectors) > MaxCollectors {
		return Result{}, errors.New("collector set is outside the supported range")
	}
	result := Result{
		Platform:     source.Platform(),
		Architecture: source.Architecture(),
		Fields:       make(map[string]string),
		Complete:     true,
	}
	if result.Platform != "linux" || result.Architecture == "" || len(result.Architecture) > 32 {
		return Result{}, ErrUnsupported
	}
	for _, item := range runner.collectors {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		fields, err := item.Collect(ctx, source)
		if err != nil {
			result.Complete = false
			result.Issues = append(result.Issues, Issue{Collector: item.Name(), Code: issueCode(err)})
			continue
		}
		for key, value := range fields {
			if key == "" || len(key) > MaxKeyBytes || len(value) > MaxValueBytes {
				return Result{}, fmt.Errorf("%s returned an out-of-policy field", item.Name())
			}
			if _, exists := result.Fields[key]; exists {
				return Result{}, fmt.Errorf("%s returned duplicate field %q", item.Name(), key)
			}
			result.Fields[key] = value
			if len(result.Fields) > MaxResultFields {
				return Result{}, errors.New("inventory exceeds field limit")
			}
		}
	}
	return result, nil
}

func issueCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, ErrLimitExceeded):
		return "limit_exceeded"
	case errors.Is(err, ErrMalformed):
		return "malformed_source"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	default:
		return "read_failed"
	}
}

type HostCollector struct{}

func (HostCollector) Name() string { return "host" }

func (HostCollector) Collect(ctx context.Context, source Source) (map[string]string, error) {
	hostname, err := source.Hostname(ctx)
	if err != nil {
		return nil, err
	}
	if hostname == "" || hostname != strings.TrimSpace(hostname) ||
		len(hostname) > MaxHostnameBytes || !validText(hostname) {
		return nil, ErrMalformed
	}
	return map[string]string{
		"host.hostname":     hostname,
		"host.platform":     source.Platform(),
		"host.architecture": source.Architecture(),
	}, nil
}

type OSReleaseCollector struct{}

func (OSReleaseCollector) Name() string { return "os_release" }

func (OSReleaseCollector) Collect(ctx context.Context, source Source) (map[string]string, error) {
	raw, err := source.ReadFile(ctx, "/etc/os-release", MaxSourceFileBytes)
	if err != nil {
		return nil, err
	}
	values, err := parseOSRelease(raw)
	if err != nil {
		return nil, err
	}
	if !osIDPattern.MatchString(values["ID"]) || !osVersionPattern.MatchString(values["VERSION_ID"]) {
		return nil, ErrMalformed
	}
	result := map[string]string{
		"os.id":         values["ID"],
		"os.version_id": values["VERSION_ID"],
	}
	if values["PRETTY_NAME"] != "" {
		result["os.pretty_name"] = values["PRETTY_NAME"]
	}
	return result, nil
}

func parseOSRelease(raw []byte) (map[string]string, error) {
	if !utf8.Valid(raw) {
		return nil, ErrMalformed
	}
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 256), MaxSourceFileBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, ErrMalformed
		}
		if key != "ID" && key != "VERSION_ID" && key != "PRETTY_NAME" {
			continue
		}
		if _, exists := result[key]; exists {
			return nil, ErrMalformed
		}
		decoded, err := decodeOSReleaseValue(value)
		if err != nil || len(decoded) > MaxValueBytes || !validText(decoded) {
			return nil, ErrMalformed
		}
		result[key] = decoded
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan os-release: %w", err)
	}
	return result, nil
}

func validText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func decodeOSReleaseValue(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", ErrMalformed
	}
	quote := byte(0)
	body := value
	if value[0] == '\'' || value[0] == '"' {
		quote = value[0]
		if len(value) < 2 || value[len(value)-1] != quote {
			return "", ErrMalformed
		}
		body = value[1 : len(value)-1]
	} else if !unquotedPattern.MatchString(value) {
		return "", ErrMalformed
	}
	if quote == '\'' {
		if strings.ContainsRune(body, '\'') {
			return "", ErrMalformed
		}
		return body, nil
	}

	var decoded strings.Builder
	decoded.Grow(len(body))
	for index := 0; index < len(body); index++ {
		character := body[index]
		if quote != 0 && character == quote {
			return "", ErrMalformed
		}
		if character != '\\' {
			decoded.WriteByte(character)
			continue
		}
		if index+1 >= len(body) {
			return "", ErrMalformed
		}
		index++
		escaped := body[index]
		switch escaped {
		case '$', '"', '\\', '`':
			decoded.WriteByte(escaped)
		default:
			// Shell-style double quoting preserves a backslash before a
			// non-special character instead of interpreting Go/C escapes.
			decoded.WriteByte('\\')
			decoded.WriteByte(escaped)
		}
	}
	return decoded.String(), nil
}

type BootCollector struct{}

func (BootCollector) Name() string { return "boot" }

func (BootCollector) Collect(ctx context.Context, source Source) (map[string]string, error) {
	raw, err := source.ReadFile(ctx, "/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return nil, err
	}
	bootID := strings.TrimSpace(string(raw))
	if !uuidPattern.MatchString(bootID) {
		return nil, ErrMalformed
	}
	return map[string]string{"boot.id": bootID}, nil
}

type RootDiskCollector struct{}

func (RootDiskCollector) Name() string { return "root_disk" }

func (RootDiskCollector) Collect(ctx context.Context, source Source) (map[string]string, error) {
	usage, err := source.DiskUsage(ctx, "/")
	if err != nil {
		return nil, err
	}
	if usage.TotalBytes == 0 || usage.FreeBytes > usage.TotalBytes {
		return nil, ErrMalformed
	}
	return map[string]string{
		"root_disk.total_bytes": strconv.FormatUint(usage.TotalBytes, 10),
		"root_disk.free_bytes":  strconv.FormatUint(usage.FreeBytes, 10),
	}, nil
}

type AgentCollector struct {
	Version string
}

func (AgentCollector) Name() string { return "agent" }

func (collector AgentCollector) Collect(context.Context, Source) (map[string]string, error) {
	if !versionPattern.MatchString(collector.Version) {
		return nil, ErrMalformed
	}
	return map[string]string{
		"agent.version":          collector.Version,
		"agent.inventory_schema": "1",
	}, nil
}
