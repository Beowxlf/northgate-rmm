package management

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Explicit maintenance qualification, never invoked by ordinary unit tests.
func TestCaptureDependencyRepairCanary(t *testing.T) {
	host, _ := os.Hostname()
	if runtime.GOOS != "linux" || strings.ToLower(host) != "ng-rmm-can01" || os.Getenv("NORTHGATE_CAPTURE_SETUP_QUALIFICATION") != "NG-RMM-CAN01" {
		t.Skip("requires explicit Linux capture canary authorization")
	}
	c, err := loadConfig(defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err = validateWorkerPaths(defaultConfig(), c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile("/etc/northgate-wxlfgar/config.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture map[string]string
	if err = json.Unmarshal(before, &capture); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("/var/tmp/northgate-management-deploy/wxlfgar-linux-release.json")
	if err != nil {
		t.Fatal(err)
	}
	var entry struct {
		Manifest  ReleaseManifest `json:"manifest"`
		URL       string          `json:"url"`
		Signature string          `json:"signature"`
	}
	if err = json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	j := jobForTest("capture.install", map[string]any{"url": entry.URL, "sha256": entry.Manifest.SHA256, "version": entry.Manifest.Version, "signature": entry.Signature, "public_key": capture["public_key"]})
	result := installCapture(ctx, j, c)
	if result.State != "completed" {
		t.Fatalf("dependency repair failed: %s", result.Output)
	}
	after, err := os.ReadFile("/etc/northgate-wxlfgar/config.json")
	if err != nil || string(before) != string(after) {
		t.Fatal("existing capture configuration changed")
	}
	t.Log("Signed catalog download and dependency repair completed; existing configuration preserved")
}
