// Package config decodes the bounded, non-secret runtime configuration for the
// Linux read-only agent.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
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
	if err := rejectDuplicateFields(raw); err != nil {
		return Config{}, err
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

func rejectDuplicateFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := checkJSONValue(decoder); err != nil {
		return fmt.Errorf("validate configuration fields: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("validate trailing configuration data: %w", err)
		}
		return fmt.Errorf("configuration contains trailing token %v", token)
	}
	return nil
}

func checkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := checkJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim(map[json.Delim]byte{'{': '}', '[': ']'}[delimiter]) {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
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
	parsed, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("control_plane_url must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("control_plane_url must not contain userinfo, query, or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("control_plane_url must not contain an application path")
	}
	if cfg.StateDirectory == "/" || !path.IsAbs(cfg.StateDirectory) || path.Clean(cfg.StateDirectory) != cfg.StateDirectory {
		return errors.New("state_directory must be an absolute clean Linux path")
	}
	if strings.ContainsRune(cfg.StateDirectory, '\x00') {
		return errors.New("state_directory contains a NUL byte")
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
