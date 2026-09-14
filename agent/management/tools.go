package management

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ToolBudget struct {
	Seconds    int `json:"seconds"`
	MemoryMiB  int `json:"memory_mib"`
	CPUPercent int `json:"cpu_percent"`
	OutputKiB  int `json:"output_kib"`
	DiskMiB    int `json:"disk_mib"`
}
type ToolManifest struct {
	Schema     int        `json:"schema"`
	ID         string     `json:"id"`
	Revision   int        `json:"revision"`
	Version    string     `json:"version"`
	Platform   string     `json:"platform"`
	Arch       string     `json:"arch"`
	SHA256     string     `json:"sha256"`
	Size       int64      `json:"size"`
	Entrypoint string     `json:"entrypoint"`
	License    string     `json:"license"`
	Source     string     `json:"source"`
	Privilege  string     `json:"privilege"`
	Budget     ToolBudget `json:"budget"`
}
type installedTool struct {
	Manifest  string            `json:"manifest"`
	Signature string            `json:"signature"`
	Files     map[string]string `json:"files"`
	Installed string            `json:"installed_at"`
}

var builtinTools = map[string]bool{"health": true, "connectivity": true, "evidence": true, "wxlfgar": true}
var toolEntries = map[string]string{"osquery": "osqueryi", "sysinternals": "autorunsc", "yara-x": "yr", "velociraptor": "velociraptor", "iperf2": "iperf", "openscap": "oscap", "nmap": "nmap"}
var toolProfiles = map[string][]string{"health": {"snapshot", "history", "changes"}, "connectivity": {"dns", "tcp", "tls"}, "evidence": {"it", "soc"}, "wxlfgar": {"readiness"}, "osquery": {"system", "processes", "users", "listening", "startup"}, "sysinternals": {"startup", "trust"}, "yara-x": {"scan"}, "velociraptor": {"collect"}, "iperf2": {"client"}, "openscap": {"assess"}, "nmap": {"connect"}}

func validTool(id string) bool {
	_, ok := toolProfiles[id]
	return ok && !(id == "sysinternals" && runtime.GOOS != "windows") && !(id == "openscap" && runtime.GOOS != "linux")
}
func toolManifest(c Config, encoded, signature string) (ToolManifest, error) {
	var m ToolManifest
	raw, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil || len(raw) > 8192 {
		return m, errors.New("invalid tool manifest")
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	if e != nil {
		return m, e
	}
	key, e := base64.StdEncoding.DecodeString(c.UpdateKey)
	if e != nil || len(key) != 32 || !ed25519.Verify(key, append([]byte("NorthGate-Tool-v1\x00"), raw...), sig) {
		return m, errors.New("tool approval signature rejected")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(&m); e != nil {
		return m, e
	}
	expected := toolEntries[m.ID]
	if runtime.GOOS == "windows" {
		expected += ".exe"
	}
	b := m.Budget
	if m.Revision < 1 || m.Revision > 1000000 {
		return m, errors.New("invalid tool revision")
	}
	if m.Schema != 1 || !validTool(m.ID) || builtinTools[m.ID] || m.Platform != runtime.GOOS || m.Arch != runtime.GOARCH || m.Entrypoint != expected || !regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`).MatchString(m.Version) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(m.SHA256) || m.Size < 1 || m.Size > 64<<20 || m.Privilege != "system" || m.License == "" || len(m.License) > 2048 || !strings.HasPrefix(m.Source, "https://") || len(m.Source) > 2048 || b.Seconds < 5 || b.Seconds > 900 || b.MemoryMiB < 64 || b.MemoryMiB > 1024 || b.CPUPercent < 1 || b.CPUPercent > 50 || b.OutputKiB < 4 || b.OutputKiB > 512 || b.DiskMiB < 16 || b.DiskMiB > 128 {
		return m, errors.New("tool metadata outside approved bounds")
	}
	return m, nil
}
func validateToolJob(j Job, c Config) error {
	if j.Action == "tool.install" || j.Action == "tool.update" {
		_, e := toolManifest(c, text(j, "manifest"), text(j, "signature"))
		return e
	}
	if j.Action == "tool.list" {
		return nil
	}
	if j.Action == "tool.artifact.read" {
		var caseID string
		if json.Unmarshal(j.Params["case_id"], &caseID) != nil || (caseID != "" && !ID.MatchString(caseID)) {
			return errors.New("artifact case must be an approved UUID or empty")
		}
		var offset, size int
		if json.Unmarshal(j.Params["offset"], &offset) != nil || json.Unmarshal(j.Params["size"], &size) != nil {
			return errors.New("artifact offset and size must be integers")
		}
		if !ID.MatchString(text(j, "artifact_id")) || integer(j, "offset") < 0 || integer(j, "offset") > 32<<20 || integer(j, "size") < 1 || integer(j, "size") > 256<<10 {
			return errors.New("invalid artifact chunk")
		}
		return nil
	}
	id := text(j, "tool_id")
	if !validTool(id) {
		return errors.New("unsupported tool/platform")
	}
	if j.Action == "tool.remove" && builtinTools[id] {
		return errors.New("built-in tools cannot be removed")
	}
	if j.Action != "tool.run" {
		return nil
	}
	matched := false
	for _, p := range toolProfiles[id] {
		if p == text(j, "profile") {
			matched = true
		}
	}
	if !matched {
		return errors.New("unsupported tool profile")
	}
	if s := text(j, "case_id"); s != "" && !ID.MatchString(s) {
		return errors.New("invalid case ID")
	}
	var inputs map[string]any
	if json.Unmarshal(j.Params["inputs"], &inputs) != nil || inputs == nil || len(j.Params["inputs"]) > 2048 {
		return errors.New("invalid tool inputs")
	}
	expected := map[string][]string{"connectivity": {"host", "port"}, "yara-x": {"path"}, "iperf2": {"host", "port"}, "nmap": {"host", "ports"}}[id]
	trust := id == "sysinternals" && text(j, "profile") == "trust"
	if trust && len(inputs) != 0 {
		expected = []string{"path"}
	}
	if len(inputs) != len(expected) {
		return errors.New("unexpected tool input")
	}
	for _, k := range expected {
		if _, ok := inputs[k]; !ok {
			return errors.New("missing tool input")
		}
	}
	if port, ok := inputs["port"]; ok {
		if _, ok := port.(float64); !ok {
			return errors.New("port must be numeric")
		}
	}
	if path, ok := inputs["path"]; ok {
		s, ok := path.(string)
		if !ok {
			return errors.New("path must be text")
		}
		if trust {
			if e := validateWindowsTrustPath(s); e != nil {
				return e
			}
		}
	}
	for _, v := range inputs {
		switch a := v.(type) {
		case string:
			if a == "" || strings.HasPrefix(a, "-") || strings.ContainsAny(a, "\x00\r\n") {
				return errors.New("invalid tool argument")
			}
		case float64:
			if a != float64(int(a)) || a < 1 || a > 65535 {
				return errors.New("invalid tool port")
			}
		default:
			return errors.New("invalid tool value")
		}
	}
	if host, ok := inputs["host"]; ok {
		s, ok := host.(string)
		if !ok || len(s) > 253 || !regexp.MustCompile(`^[A-Za-z0-9:._-]+$`).MatchString(s) {
			return errors.New("invalid host")
		}
		if id != "connectivity" {
			ip := net.ParseIP(s)
			if ip == nil || !ip.IsPrivate() {
				return errors.New("discovery and link tests require one private IP")
			}
		}
	}
	if ports, ok := inputs["ports"]; ok {
		s, ok := ports.(string)
		if !ok || !regexp.MustCompile(`^\d{1,5}(,\d{1,5}){0,15}$`).MatchString(s) {
			return errors.New("invalid port list")
		}
		for _, p := range strings.Split(s, ",") {
			n, _ := strconv.Atoi(p)
			if n < 1 || n > 65535 {
				return errors.New("invalid port")
			}
		}
	}
	return nil
}
func diagnosticJob(j Job) bool {
	if j.Action == "tool.list" || j.Action == "tool.verify" || j.Action == "tool.artifact.read" {
		return true
	}
	id := text(j, "tool_id")
	return j.Action == "tool.run" && (id == "health" || id == "connectivity" || id == "osquery")
}
func toolResult(value any) Result {
	b, e := json.Marshal(value)
	if e != nil {
		return safeResultError("cannot encode tool result")
	}
	return Result{State: "completed", Exit: 0, Identity: executionIdentity(), Output: string(b)}
}
func toolsRoot(c Config) string { return filepath.Join(c.Root, "tools") }
func readInstalled(c Config, id string) (installedTool, ToolManifest, error) {
	var v installedTool
	var m ToolManifest
	b, e := readBounded(filepath.Join(toolsRoot(c), id, "installed.json"), 128<<10)
	if e != nil {
		return v, m, e
	}
	if e = json.Unmarshal(b, &v); e != nil {
		return v, m, e
	}
	m, e = toolManifest(c, v.Manifest, v.Signature)
	if e == nil && m.ID != id {
		e = errors.New("installed identity mismatch")
	}
	return v, m, e
}
func toolReadiness(c Config, id string) map[string]any {
	if builtinTools[id] {
		return map[string]any{"id": id, "state": "ready", "builtin": true}
	}
	installed, m, e := readInstalled(c, id)
	if e != nil {
		return map[string]any{"id": id, "state": "not_installed", "detail": "Approved package not installed or metadata invalid"}
	}
	for p, digest := range installed.Files {
		actual, e := toolFileHash(filepath.Join(toolsRoot(c), id, p), 128<<20)
		if e != nil {
			return map[string]any{"id": id, "state": "needs_repair", "version": m.Version}
		}
		if actual != digest {
			return map[string]any{"id": id, "state": "needs_repair", "version": m.Version}
		}
	}
	return map[string]any{"id": id, "state": "ready", "version": m.Version, "license": m.License, "budget": m.Budget, "privilege": "system"}
}
func executeTool(ctx context.Context, j Job, c Config) Result {
	if e := validateToolJob(j, c); e != nil {
		return safeResultError(e.Error())
	}
	if j.Action == "tool.install" || j.Action == "tool.update" {
		return installTool(ctx, j, c)
	}
	if j.Action == "tool.artifact.read" {
		return readToolArtifact(j, c)
	}
	if j.Action == "tool.list" {
		r := []any{}
		for id := range toolProfiles {
			if validTool(id) {
				r = append(r, toolReadiness(c, id))
			}
		}
		return toolResult(map[string]any{"tools": r})
	}
	id := text(j, "tool_id")
	if j.Action == "tool.verify" {
		return toolResult(toolReadiness(c, id))
	}
	if j.Action == "tool.remove" {
		_, _, e := readInstalled(c, id)
		if e != nil {
			return safeResultError("Tool ownership cannot be verified; files retained")
		}
		path := filepath.Join(toolsRoot(c), id)
		if e = os.RemoveAll(path); e != nil {
			return safeResultError("Tool removal failed")
		}
		return toolResult(map[string]any{"id": id, "state": "removed", "artifacts_retained": true})
	}
	if builtinTools[id] {
		return runBuiltinTool(ctx, j, c)
	}
	if toolReadiness(c, id)["state"] != "ready" {
		return safeResultError("Tool requires approved installation or repair")
	}
	_, m, e := readInstalled(c, id)
	if e != nil {
		return safeResultError("Tool metadata unavailable")
	}
	args, e := toolArguments(j, c, m)
	if e != nil {
		return safeResultError(e.Error())
	}
	toolCtx, cancel := context.WithTimeout(ctx, time.Duration(m.Budget.Seconds)*time.Second)
	defer cancel()
	started := time.Now()
	result := runBudgetedTool(toolCtx, j, c, m, args)
	if m.ID == "osquery" && result.State == "completed" {
		recordToolObservation("osquery."+text(j, "profile"), result.Output)
	}
	if m.ID == "velociraptor" || m.ID == "openscap" {
		artifacts, artifactErr := collectToolArtifacts(j, c, m, started)
		wrapped := map[string]any{"tool_id": m.ID, "tool_version": m.Version, "profile": text(j, "profile"), "case_id": text(j, "case_id"), "output": result.Output, "artifacts": artifacts, "partial": result.State != "completed"}
		if artifactErr != nil {
			wrapped["artifact_error"] = artifactErr.Error()
			result.State = "failed"
			result.Error = "Tool ran, but evidence retention was incomplete"
		}
		b, _ := json.Marshal(wrapped)
		result.Output = string(b)
	}
	return result
}
func installTool(ctx context.Context, j Job, c Config) Result {
	m, e := toolManifest(c, text(j, "manifest"), text(j, "signature"))
	if e != nil {
		return safeResultError(e.Error())
	}
	destination := filepath.Join(toolsRoot(c), m.ID)
	existing, oldManifest, oldErr := readInstalled(c, m.ID)
	if j.Action == "tool.install" && oldErr == nil {
		if existing.Manifest == text(j, "manifest") {
			return toolResult(toolReadiness(c, m.ID))
		}
		return safeResultError("Tool exists; use update")
	}
	if j.Action == "tool.update" && oldErr != nil {
		return safeResultError("Install before updating; invalid existing metadata requires reconciliation")
	}
	if j.Action == "tool.update" && m.Revision <= oldManifest.Revision {
		return safeResultError("Tool downgrade or replay rejected")
	}
	if _, e = os.Lstat(destination); e == nil && oldErr != nil {
		return safeResultError("Unowned tool directory; retained for reconciliation")
	}
	if e = os.MkdirAll(toolsRoot(c), 0700); e != nil {
		return safeResultError("Cannot create tool store")
	}
	if size, e := treeSize(toolsRoot(c)); e != nil || size > 1<<30 {
		return safeResultError("Tool store quota reached; remove unused tools before installing")
	}
	stage, e := os.MkdirTemp(toolsRoot(c), "stage-")
	if e != nil {
		return safeResultError("Cannot stage tool")
	}
	defer os.RemoveAll(stage)
	client, e := client(c)
	if e != nil {
		return safeResultError("Catalog TLS unavailable")
	}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", c.Server+"/v1/management/releases/"+m.SHA256, nil)
	response, e := client.Do(req)
	if e != nil {
		return safeResultError("Approved artifact download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return safeResultError("Approved artifact is unavailable")
	}
	archive := filepath.Join(stage, "bundle.zip")
	f, e := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return safeResultError("Cannot stage bundle")
	}
	hash := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, hash), io.LimitReader(response.Body, m.Size+1))
	closeErr := f.Close()
	if e != nil || closeErr != nil || n != m.Size || hex.EncodeToString(hash.Sum(nil)) != m.SHA256 {
		return safeResultError("Tool package integrity failed")
	}
	payload := filepath.Join(stage, "payload")
	if e = os.Mkdir(payload, 0700); e != nil {
		return safeResultError("Cannot stage tool payload")
	}
	files, e := extractToolArchive(archive, payload, int64(m.Budget.DiskMiB)<<20)
	if e != nil {
		return safeResultError(e.Error())
	}
	if _, ok := files[m.Entrypoint]; !ok {
		return safeResultError("Approved entrypoint missing")
	}
	for _, required := range toolRequiredFiles(m.ID) {
		if _, ok := files[required]; !ok {
			return safeResultError("Required approved configuration missing: " + required)
		}
	}
	if e = saveJSON(filepath.Join(payload, "installed.json"), installedTool{text(j, "manifest"), text(j, "signature"), files, time.Now().UTC().Format(time.RFC3339)}); e != nil {
		return safeResultError("Cannot save installed manifest")
	}
	backup := filepath.Join(toolsRoot(c), "rollback", m.ID)
	if oldErr == nil {
		// Retain the previous live version outside the disposable staging tree.
		// Activation or restoration failures must never erase its recovery copy.
		if e = os.MkdirAll(filepath.Dir(backup), 0700); e != nil {
			return safeResultError("Cannot prepare tool rollback")
		}
		if e = os.RemoveAll(backup); e != nil {
			return safeResultError("Cannot retire previous tool rollback")
		}
		if e = os.Rename(destination, backup); e != nil {
			return safeResultError("Cannot stage existing tool rollback")
		}
	}
	if e = os.Rename(payload, destination); e != nil {
		if oldErr == nil {
			_ = os.Rename(backup, destination)
		}
		return safeResultError("Tool activation failed; prior version retained where possible")
	}
	return toolResult(map[string]any{"id": m.ID, "version": m.Version, "state": "installed", "phase": "verify", "next_action": "tool.verify"})
}
func toolRequiredFiles(id string) []string {
	switch id {
	case "sysinternals":
		return []string{"sigcheck.exe"}
	case "yara-x":
		return []string{"rules.yar"}
	case "velociraptor":
		return []string{"collector.yaml"}
	case "openscap":
		return []string{"profile.xml"}
	}
	return nil
}
func extractToolArchive(path, root string, maximum int64) (map[string]string, error) {
	z, e := zip.OpenReader(path)
	if e != nil {
		return nil, e
	}
	defer z.Close()
	if len(z.File) > 512 {
		return nil, errors.New("Tool bundle file limit exceeded")
	}
	files := map[string]string{}
	seen := map[string]bool{}
	var total int64
	for _, entry := range z.File {
		name := entry.Name
		clean := filepath.FromSlash(name)
		if name == "" || strings.ContainsAny(name, "\\:\x00") || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") || filepath.Clean(clean) != strings.TrimSuffix(clean, string(filepath.Separator)) || strings.EqualFold(name, "installed.json") || entry.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Unsafe tool archive path")
		}
		fold := strings.ToLower(clean)
		if seen[fold] {
			return nil, errors.New("Duplicate tool archive path")
		}
		seen[fold] = true
		if entry.FileInfo().IsDir() {
			continue
		}
		total += int64(entry.UncompressedSize64)
		if total > maximum {
			return nil, errors.New("Tool bundle disk budget exceeded")
		}
		destination := filepath.Join(root, clean)
		if e = os.MkdirAll(filepath.Dir(destination), 0700); e != nil {
			return nil, e
		}
		src, e := entry.Open()
		if e != nil {
			return nil, e
		}
		dst, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if e != nil {
			src.Close()
			return nil, e
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, int64(entry.UncompressedSize64)+1))
		src.Close()
		closeErr := dst.Close()
		if copyErr != nil || closeErr != nil || n != int64(entry.UncompressedSize64) {
			return nil, errors.New("Invalid tool archive member")
		}
		files[clean] = hex.EncodeToString(h.Sum(nil))
	}
	return files, nil
}
func toolArguments(j Job, c Config, m ToolManifest) ([]string, error) {
	var v map[string]any
	_ = json.Unmarshal(j.Params["inputs"], &v)
	base := filepath.Join(toolsRoot(c), m.ID)
	profile := text(j, "profile")
	switch m.ID {
	case "osquery":
		q := map[string]string{"system": "SELECT hostname, cpu_brand, physical_memory FROM system_info;", "processes": "SELECT pid, name, path FROM processes LIMIT 500;", "users": "SELECT uid, username, directory FROM users LIMIT 500;", "listening": "SELECT pid, port, protocol, address FROM listening_ports LIMIT 500;", "startup": "SELECT name, path, type FROM startup_items LIMIT 500;"}
		return []string{"--json", "--disable_extensions", q[profile]}, nil
	case "sysinternals":
		if profile == "startup" {
			// Logon startup metadata fits the bounded receipt without repeatedly
			// hashing DLLs or doing signature checks. Broader inventory is separate.
			return []string{"-accepteula", "-a", "l", "-c"}, nil
		}
		p, e := sysinternalsDefaultTarget()
		if e != nil {
			return nil, e
		}
		if value, ok := v["path"].(string); ok {
			p = value
		}
		if e := validateWindowsTrustPath(p); e != nil {
			return nil, e
		}
		if within(c.Root, p) || within(filepath.Dir(c.IdentityFile), p) {
			return nil, errors.New("Select a file outside worker identity/state")
		}
		return []string{"-accepteula", "-nobanner", "-r", "-c", "-h", "-e", p}, nil
	case "yara-x":
		p, _ := v["path"].(string)
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || within(c.Root, p) || within(filepath.Dir(c.IdentityFile), p) {
			return nil, errors.New("Select an absolute scan path outside worker identity/state")
		}
		return []string{"scan", "--timeout", fmt.Sprint(m.Budget.Seconds), "--threads", "1", "--skip-larger", "16777216", "--output-format", "ndjson", "--disable-console-logs", filepath.Join(base, "rules.yar"), p}, nil
	case "velociraptor":
		return []string{"--", "--embedded_config", filepath.Join(base, "collector.yaml")}, nil
	case "iperf2":
		return []string{"-c", v["host"].(string), "-p", fmt.Sprint(v["port"]), "-t", "10", "-b", "10M", "-y", "C"}, nil
	case "openscap":
		return []string{"xccdf", "eval", "--results", filepath.Join(base, "results.xml"), filepath.Join(base, "profile.xml")}, nil
	case "nmap":
		return []string{"-sT", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "30s", "--max-rate", "20", "-p", v["ports"].(string), v["host"].(string)}, nil
	}
	return nil, errors.New("Tool recipe unsupported")
}

func toolFileHash(path string, maximum int64) (string, error) {
	root, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return "", e
	}
	defer root.Close()
	info, e := root.Lstat(filepath.Base(path))
	if e != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return "", errors.New("invalid tool file")
	}
	f, e := root.Open(filepath.Base(path))
	if e != nil {
		return "", e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return "", errors.New("tool file changed")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, maximum+1))
	if e != nil || n > maximum {
		return "", errors.New("tool file hash failed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
