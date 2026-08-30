package config

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const validConfig = `{
  "endpoint_id": "123e4567-e89b-42d3-a456-426614174000",
  "control_plane_url": "https://rmm.invalid/",
  "state_directory": "/var/lib/northgate-rmm",
  "collection_interval": "5m",
  "request_timeout": "15s",
  "max_spool_bytes": 1048576
}`

func TestDecodeValidConfig(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if cfg.CollectionInterval != 5*time.Minute || cfg.RequestTimeout != 15*time.Second {
		t.Fatalf("unexpected durations: %#v", cfg)
	}
}

func TestDecodeRejectsUnknownAndTrailingData(t *testing.T) {
	tests := []string{
		strings.Replace(validConfig, "\n}", ",\n  \"token\": \"secret\"\n}", 1),
		strings.Replace(validConfig, "\n}", ",\n  \"endpoint_id\": \"123e4567-e89b-42d3-a456-426614174000\"\n}", 1),
		validConfig + ` {}`,
	}
	for _, input := range tests {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("Decode() accepted invalid input: %s", input)
		}
	}
}

func TestDecodeRejectsUnsafeDestinationsAndBounds(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{"http", "https://rmm.invalid/", "http://rmm.invalid/"},
		{"userinfo", "https://rmm.invalid/", "https://user@rmm.invalid/"},
		{"query", "https://rmm.invalid/", "https://rmm.invalid/?token=x"},
		{"empty query", "https://rmm.invalid/", "https://rmm.invalid?"},
		{"invalid port", "https://rmm.invalid/", "https://rmm.invalid:99999/"},
		{"relative state", "/var/lib/northgate-rmm", "state"},
		{"root state", "/var/lib/northgate-rmm", "/"},
		{"control in state", "/var/lib/northgate-rmm", "/var/lib/northgate\\nspool"},
		{"small spool", "1048576", "1024"},
		{"fast collection", "5m", "1s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := strings.Replace(validConfig, test.old, test.new, 1)
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("Decode() accepted unsafe configuration")
			}
		})
	}
}

func TestDecodeRejectsOversizedInput(t *testing.T) {
	input := strings.Repeat("x", MaxEncodedBytes+1)
	if _, err := Decode(strings.NewReader(input)); err == nil {
		t.Fatal("Decode() accepted oversized configuration")
	}
}

func TestDecodeRejectsInvalidUTF8(t *testing.T) {
	raw := []byte(validConfig)
	raw[len(raw)-3] = 0xff
	if _, err := Decode(bytes.NewReader(raw)); err == nil {
		t.Fatal("Decode() accepted invalid UTF-8")
	}
}

func TestValidateRejectsInvalidUTF8StateDirectory(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	cfg.StateDirectory = "/tmp/" + string([]byte{0xff})
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an invalid UTF-8 state directory")
	}
}

func TestValidateRejectsInvalidControlPlaneURL(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	tests := []string{
		"https://exa" + string([]byte{0xff}) + "mple.invalid/",
		"https://%FF/",
		"https://rmm.invalid:99999/",
		"https://rmm.invalid:0/",
		"https://rmm.invalid:/",
	}
	for _, controlPlaneURL := range tests {
		cfg.ControlPlaneURL = controlPlaneURL
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate() accepted invalid control-plane URL %q", controlPlaneURL)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(validConfig))
	f.Add([]byte(`{"endpoint_id":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = Decode(bytes.NewReader(raw))
	})
}
