// Package config decodes the bounded, non-secret runtime configuration for the
// Linux read-only agent.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

const (
	MaxEncodedBytes             = 16 * 1024
	MinCollectionInterval       = time.Minute
	MaxCollectionInterval       = 24 * time.Hour
	MinRequestTimeout           = time.Second
	MaxRequestTimeout           = time.Minute
	MinSpoolBytes         int64 = 1 << 20
	MaxSpoolBytes         int64 = 64 << 20
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Config contains only non-secret settings. Identity keys and enrollment
// grants belong to a separate protected store.
type Config struct {
	EndpointID         string        `json:"endpoint_id"`
	ControlPlaneURL    string        `json:"control_plane_url"`
	StateDirectory     string        `json:"state_directory"`
	CollectionInterval time.Duration `json:"-"`
	RequestTimeout     time.Duration `json:"-"`
	MaxSpoolBytes      int64         `json:"max_spool_bytes"`
}

type wireConfig struct {
	EndpointID         string `json:"endpoint_id"`
	ControlPlaneURL    string `json:"control_plane_url"`
	StateDirectory     string `json:"state_directory"`
	CollectionInterval string `json:"collection_interval"`
	RequestTimeout     string `json:"request_timeout"`
	MaxSpoolBytes      int64  `json:"max_spool_bytes"`
}

// Decode accepts exactly one JSON object, rejects unknown fields, and enforces
// the Linux agent's resource and destination bounds.
func Decode(reader io.Reader) (Config, error) {
	limited := io.LimitReader(reader, MaxEncodedBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if len(raw) == 0 {
		return Config{}, errors.New("configuration is empty")
	}
	if len(raw) > MaxEncodedBytes {
		return Config{}, errors.New("configuration exceeds size limit")
	}
	if err := strictjson.Validate(raw); err != nil {
		return Config{}, fmt.Errorf("validate configuration JSON: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire wireConfig
	if err := decoder.Decode(&wire); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Config{}, err
	}

	collectionInterval, err := time.ParseDuration(wire.CollectionInterval)
	if err != nil {
		return Config{}, errors.New("collection_interval is invalid")
	}
	requestTimeout, err := time.ParseDuration(wire.RequestTimeout)
	if err != nil {
		return Config{}, errors.New("request_timeout is invalid")
	}
	result := Config{
		EndpointID:         wire.EndpointID,
		ControlPlaneURL:    wire.ControlPlaneURL,
		StateDirectory:     wire.StateDirectory,
		CollectionInterval: collectionInterval,
		RequestTimeout:     requestTimeout,
		MaxSpoolBytes:      wire.MaxSpoolBytes,
	}
	if err := result.Validate(); err != nil {
		return Config{}, err
	}
	return result, nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing configuration data: %w", err)
	}
	return errors.New("configuration contains multiple JSON values")
}

// Validate rejects ambiguous identity, destination, path, and resource values.
func (cfg Config) Validate() error {
	if !uuidPattern.MatchString(cfg.EndpointID) {
		return errors.New("endpoint_id must be a canonical lowercase UUID")
	}
	if !utf8.ValidString(cfg.ControlPlaneURL) {
		return errors.New("control_plane_url contains invalid UTF-8")
	}
	if strings.Contains(cfg.ControlPlaneURL, "#") {
		return errors.New("control_plane_url must not contain a fragment delimiter")
	}
	if strings.Contains(cfg.ControlPlaneURL, "%") {
		return errors.New("control_plane_url must not contain percent escapes")
	}
	parsed, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("control_plane_url must be an absolute HTTPS URL")
	}
	hostname := parsed.Hostname()
	if hostname == "" || !utf8.ValidString(hostname) || containsControl(hostname) ||
		!validControlPlaneHostname(hostname) {
		return errors.New("control_plane_url contains an invalid hostname")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return errors.New("control_plane_url contains an empty port")
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return errors.New("control_plane_url contains an invalid port")
		}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("control_plane_url must not contain userinfo, query, or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("control_plane_url must not contain an application path")
	}
	if !utf8.ValidString(cfg.StateDirectory) {
		return errors.New("state_directory contains invalid UTF-8")
	}
	if cfg.StateDirectory == "/" || !path.IsAbs(cfg.StateDirectory) || path.Clean(cfg.StateDirectory) != cfg.StateDirectory {
		return errors.New("state_directory must be an absolute clean Linux path")
	}
	if containsControl(cfg.StateDirectory) {
		return errors.New("state_directory contains a control character")
	}
	if cfg.CollectionInterval < MinCollectionInterval || cfg.CollectionInterval > MaxCollectionInterval {
		return errors.New("collection_interval is outside the supported range")
	}
	if cfg.RequestTimeout < MinRequestTimeout || cfg.RequestTimeout > MaxRequestTimeout {
		return errors.New("request_timeout is outside the supported range")
	}
	if cfg.RequestTimeout >= cfg.CollectionInterval {
		return errors.New("request_timeout must be shorter than collection_interval")
	}
	if cfg.MaxSpoolBytes < MinSpoolBytes || cfg.MaxSpoolBytes > MaxSpoolBytes {
		return errors.New("max_spool_bytes is outside the supported range")
	}
	return nil
}

func validControlPlaneHostname(hostname string) bool {
	if net.ParseIP(hostname) != nil {
		return true
	}
	if len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}
