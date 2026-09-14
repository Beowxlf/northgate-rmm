package management

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

// Installation uses the same release authority and enrollment TLS as updates.
// Existing installations are only repaired at their current version; updates remain separate.
func installCapture(ctx context.Context, j Job, c Config) Result {
	m := ReleaseManifest{Component: "wxlfgar", Platform: runtime.GOOS, SHA256: text(j, "sha256"), Version: text(j, "version")}
	if e := verifyRelease(c, m, text(j, "signature")); e != nil {
		return safeResultError(e.Error())
	}
	key, e := base64.StdEncoding.DecodeString(text(j, "public_key"))
	if e != nil || len(key) != 32 {
		return safeResultError("Invalid capture signing key")
	}
	u, e := url.Parse(text(j, "url"))
	base, _ := url.Parse(c.Server)
	if e != nil || u.Scheme != "https" || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/v1/management/releases/"+m.SHA256 {
		return safeResultError("Capture package must come from the pinned catalog")
	}
	if captureInstalled() && installedVersion("wxlfgar") != m.Version {
		return safeResultError("Existing Wxlfgar version differs; use a reviewed component update first")
	}
	directory, e := os.MkdirTemp(c.Root, "capture-install-")
	if e != nil {
		return safeResultError("Cannot stage capture installation")
	}
	defer os.RemoveAll(directory)
	client, e := client(c)
	if e != nil {
		return safeResultError("Enrollment TLS unavailable")
	}
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return safeResultError("Invalid package request")
	}
	response, e := client.Do(req)
	if e != nil {
		return safeResultError("Capture package download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return safeResultError("Capture package unavailable")
	}
	binary := filepath.Join(directory, "wulfgar")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	file, e := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return safeResultError("Cannot stage capture binary")
	}
	digest := sha256.New()
	size, e := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, 64*1024*1024+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if e != nil || syncErr != nil || closeErr != nil || size > 64*1024*1024 || hex.EncodeToString(digest.Sum(nil)) != m.SHA256 {
		return safeResultError("Capture package integrity check failed")
	}
	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	reported := runCommand(versionCtx, exec.CommandContext(versionCtx, binary, "--version"), 1024)
	cancel()
	if reported.State != "completed" || regexp.MustCompile(`\b\d+\.\d+\.\d+(?:-lab\.\d+)?\b`).FindString(reported.Output) != m.Version {
		return safeResultError("Capture binary version differs from its signed manifest")
	}
	config := map[string]string{"endpoint_id": c.Endpoint, "identity_id": c.Identity, "public_key": text(j, "public_key")}
	raw, _ := json.Marshal(config)
	configuration := filepath.Join(directory, "config.json")
	if e = os.WriteFile(configuration, raw, 0600); e != nil {
		return safeResultError("Cannot stage capture configuration")
	}
	return platformInstallCapture(ctx, j, c, binary, configuration)
}
