package management

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ReleaseManifest struct {
	Component string `json:"component"`
	Platform  string `json:"platform"`
	SHA256    string `json:"sha256"`
	Version   string `json:"version"`
}
type UpdatePlan struct {
	Job       string          `json:"job"`
	Config    string          `json:"config"`
	Binary    string          `json:"binary"`
	Manifest  ReleaseManifest `json:"manifest"`
	Signature string          `json:"signature"`
	Created   int64           `json:"created"`
}

func versionParts(v string) ([]int, error) {
	match := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:-lab\.(\d+))?$`).FindStringSubmatch(v)
	if match == nil {
		return nil, errors.New("invalid release version")
	}
	parts := []int{}
	for _, s := range match[1:] {
		if s == "" {
			s = "2147483647"
		}
		n, e := strconv.Atoi(s)
		if e != nil {
			return nil, e
		}
		parts = append(parts, n)
	}
	return parts, nil
}
func newer(candidate, installed string) bool {
	a, e := versionParts(candidate)
	if e != nil {
		return false
	}
	b, e := versionParts(installed)
	if e != nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
func verifyRelease(c Config, m ReleaseManifest, sig string) error {
	if m.Platform != runtime.GOOS || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(m.SHA256) {
		return errors.New("invalid release platform or digest")
	}
	if _, e := versionParts(m.Version); e != nil {
		return e
	}
	if m.Component != "agent" && m.Component != "worker" && m.Component != "wxlfgar" {
		return errors.New("invalid release component")
	}
	key, e := base64.StdEncoding.DecodeString(c.UpdateKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid release authority key")
	}
	signature, e := base64.StdEncoding.DecodeString(sig)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(m)
	if !ed25519.Verify(key, append([]byte("NorthGate-Release-v1\x00"), b...), signature) {
		return errors.New("release authority signature rejected")
	}
	return nil
}
func installUpdate(ctx context.Context, j Job, c Config) Result {
	manifest := ReleaseManifest{Component: text(j, "component"), Platform: runtime.GOOS, SHA256: text(j, "sha256"), Version: text(j, "version")}
	if e := verifyRelease(c, manifest, text(j, "signature")); e != nil {
		return safeResultError(e.Error())
	}
	installed := map[string]string{}
	if b, e := readBounded(filepath.Join(c.Root, "versions.json"), 4096); e == nil {
		_ = json.Unmarshal(b, &installed)
	}
	if manifest.Component == "worker" {
		installed["worker"] = Version
	}
	actual := installedVersion(manifest.Component)
	if actual == "" {
		return safeResultError("Installed component version unavailable; reconcile installation first")
	}
	if old := installed[manifest.Component]; old != "" && !newer(manifest.Version, old) {
		return safeResultError("Downgrade or replayed release rejected")
	}
	if !newer(manifest.Version, actual) {
		return safeResultError("Candidate is not newer than the installed binary")
	}
	u, e := url.Parse(text(j, "url"))
	base, _ := url.Parse(c.Server)
	if e != nil || u.Scheme != "https" || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/v1/management/releases/"+manifest.SHA256 {
		return safeResultError("Release must come from the pinned management catalog")
	}
	directory := filepath.Join(c.Root, "updates", j.ID)
	if e = os.MkdirAll(directory, 0700); e != nil {
		return safeResultError("Cannot stage release")
	}
	client, e := client(c)
	if e != nil {
		return safeResultError("Update TLS identity unavailable")
	}
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return safeResultError("Invalid release request")
	}
	response, e := client.Do(req)
	if e != nil {
		return safeResultError("Release download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return safeResultError("Release unavailable")
	}
	path := filepath.Join(directory, "candidate")
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if e != nil {
		return safeResultError("Staged release already exists; reconcile")
	}
	hash := sha256.New()
	size, e := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, 64*1024*1024+1))
	syncErr := file.Sync()
	file.Close()
	if e != nil || syncErr != nil || size > 64*1024*1024 || hex.EncodeToString(hash.Sum(nil)) != manifest.SHA256 {
		return safeResultError("Release download integrity failed")
	}
	plan := UpdatePlan{Job: j.ID, Config: defaultConfig(), Binary: path, Manifest: manifest, Signature: text(j, "signature"), Created: time.Now().Unix()}
	planPath := filepath.Join(directory, "plan.json")
	if e = saveJSON(planPath, plan); e != nil {
		return safeResultError("Cannot save update transaction")
	}
	result := scheduleUpdate(ctx, j, c, planPath)
	if result.State != "completed" {
		return result
	}
	if manifest.Component == "worker" {
		return Result{State: "handoff", Identity: executionIdentity()}
	}
	for {
		select {
		case <-ctx.Done():
			return safeResultError("Update outcome pending; reconcile transaction")
		case <-time.After(time.Second):
			if b, e := readBounded(filepath.Join(directory, "result.json"), 65536); e == nil {
				var r Result
				if json.Unmarshal(b, &r) == nil {
					return r
				}
			}
		}
	}
}
func ReleaseIsolation(ctx context.Context, path string) error {
	if e := requirePrivileged(); e != nil {
		return e
	}
	c, e := loadConfig(path)
	if e != nil {
		return e
	}
	if e = validateWorkerPaths(path, c); e != nil {
		return e
	}
	r := platformAction(ctx, Job{ID: "00000000-0000-4000-8000-000000000001", Action: "isolation.release", Params: map[string]json.RawMessage{}}, c)
	if r.State != "completed" {
		return errors.New("isolation cleanup failed")
	}
	return nil
}
func ApplyUpdate(ctx context.Context, path string) error {
	if e := requirePrivileged(); e != nil {
		return e
	}
	b, e := readBounded(path, 16384)
	if e != nil {
		return e
	}
	var p UpdatePlan
	if e = json.Unmarshal(b, &p); e != nil {
		return e
	}
	c, e := loadConfig(p.Config)
	if e != nil {
		return e
	}
	if e = validateWorkerPaths(p.Config, c); e != nil {
		return e
	}
	expected := filepath.Join(c.Root, "updates", p.Job)
	if !ID.MatchString(p.Job) || filepath.Dir(path) != expected || filepath.Dir(p.Binary) != expected || p.Created < time.Now().Add(-30*time.Minute).Unix() {
		return errors.New("invalid update transaction")
	}
	if e = verifyRelease(c, p.Manifest, p.Signature); e != nil {
		return e
	}
	data, e := readBounded(p.Binary, 64*1024*1024)
	if e != nil {
		return e
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != p.Manifest.SHA256 {
		return errors.New("candidate changed")
	}
	result := applyPlatformUpdate(ctx, p, c)
	if result.State != "completed" {
		if e = saveJSON(filepath.Join(expected, "result.json"), result); e != nil {
			return e
		}
		return errors.New("update failed; rollback attempted")
	}
	versions := map[string]string{}
	versionsPath := filepath.Join(c.Root, "versions.json")
	if b, e = readBounded(versionsPath, 4096); e == nil {
		_ = json.Unmarshal(b, &versions)
	}
	versions[p.Manifest.Component] = p.Manifest.Version
	temporary := versionsPath + "." + p.Job
	if e = saveJSON(temporary, versions); e != nil {
		return e
	}
	if e = replaceFile(temporary, versionsPath); e != nil {
		return e
	}
	return saveJSON(filepath.Join(expected, "result.json"), result)
}

func installedVersion(component string) string {
	if component == "worker" {
		return Version
	}
	paths := map[string]string{"agent": "/usr/libexec/northgate-rmm/northgate-rmm-agent", "wxlfgar": "/usr/local/libexec/northgate-wxlfgar/wulfgar"}
	if runtime.GOOS == "windows" {
		paths = map[string]string{"agent": `C:\Program Files\NorthGate RMM\northgate-rmm-agent.exe`, "wxlfgar": `C:\Program Files\NorthGateWxlfgar\wulfgar.exe`}
	}
	path := paths[component]
	if path == "" {
		return ""
	}
	return installedVersions.get(path, probeInstalledVersion)
}

var versionPattern = regexp.MustCompile(`\b\d+\.\d+\.\d+(?:-lab\.\d+)?\b`)

func probeInstalledVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	configureProcess(cmd)
	b, e := cmd.Output()
	if e != nil {
		return ""
	}
	value := versionPattern.FindString(strings.TrimSpace(string(b)))
	return value
}
