package management

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestCaptureInstallRejectsUntrustedInputs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	manifest := ReleaseManifest{Component: "wxlfgar", Platform: runtime.GOOS, SHA256: strings.Repeat("a", 64), Version: "0.2.0"}
	b, _ := json.Marshal(manifest)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte("NorthGate-Release-v1\x00"), b...)))
	config := Config{UpdateKey: base64.StdEncoding.EncodeToString(pub), Server: "https://management.test:9443", Root: t.TempDir()}
	for _, test := range []struct{ name, key, url, signature string }{
		{"foreign host", base64.StdEncoding.EncodeToString(make([]byte, 32)), "https://other.test/v1/management/releases/" + manifest.SHA256, sig},
		{"unsigned", base64.StdEncoding.EncodeToString(make([]byte, 32)), "https://management.test:9443/v1/management/releases/" + manifest.SHA256, "invalid"},
		{"bad key", "bad", "https://management.test:9443/v1/management/releases/" + manifest.SHA256, sig},
	} {
		t.Run(test.name, func(t *testing.T) {
			j := jobForTest("capture.install", map[string]any{"url": test.url, "sha256": manifest.SHA256, "version": manifest.Version, "signature": test.signature, "public_key": test.key})
			r := installCapture(context.Background(), j, config)
			if r.State != "failed" {
				t.Fatal("Untrusted installation accepted")
			}
		})
	}
	config.UpdateKey = base64.StdEncoding.EncodeToString([]byte{1})
	if verifyRelease(config, manifest, sig) == nil {
		t.Fatal("Invalid release key accepted")
	}
}
