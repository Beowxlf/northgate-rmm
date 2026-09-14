package management

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var healthHistory = struct {
	sync.Mutex
	samples                  []map[string]any
	changes                  []map[string]any
	interfaces               string
	sampled                  time.Time
	observations             map[string]string
	root, endpoint, identity string
	persisted                time.Time
	persistenceError         string
}{}

func sampleHealth(c Config) map[string]any {
	healthHistory.Lock()
	defer healthHistory.Unlock()
	loadHealthLocked(c)
	if time.Since(healthHistory.sampled) < 30*time.Second && len(healthHistory.samples) > 0 {
		return healthHistory.samples[len(healthHistory.samples)-1]
	}
	sample := hostHealth(c)
	sample["collected_at"] = time.Now().UTC().Format(time.RFC3339)
	sample["platform"] = runtime.GOOS
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	sample["worker_heap_bytes"] = mem.HeapAlloc
	sample["worker_goroutines"] = runtime.NumGoroutine()
	if count := len(healthHistory.samples); count > 0 {
		previous := healthHistory.samples[count-1]
		total, ok := sample["cpu_total_ticks"].(uint64)
		idle, ok2 := sample["cpu_idle_ticks"].(uint64)
		oldTotal, ok3 := previous["cpu_total_ticks"].(uint64)
		oldIdle, ok4 := previous["cpu_idle_ticks"].(uint64)
		if ok && ok2 && ok3 && ok4 && total > oldTotal && idle >= oldIdle {
			sample["cpu_percent"] = 100 * (1 - float64(idle-oldIdle)/float64(total-oldTotal))
		}
	}
	interfaces := []string{}
	if values, e := net.Interfaces(); e == nil {
		for _, n := range values {
			addresses, _ := n.Addrs()
			for _, a := range addresses {
				interfaces = append(interfaces, n.Name+" "+a.String())
			}
		}
	}
	sort.Strings(interfaces)
	if len(interfaces) > 128 {
		interfaces = interfaces[:128]
		sample["interfaces_truncated"] = true
	}
	current := strings.Join(interfaces, "\n")
	sample["interfaces"] = interfaces
	if healthHistory.interfaces != "" && current != healthHistory.interfaces {
		healthHistory.changes = append(healthHistory.changes, map[string]any{"observed_at": sample["collected_at"], "kind": "network.interfaces", "before": healthHistory.interfaces, "after": current})
		if len(healthHistory.changes) > 32 {
			healthHistory.changes = healthHistory.changes[len(healthHistory.changes)-32:]
		}
	}
	healthHistory.interfaces = current
	healthHistory.samples = append(healthHistory.samples, sample)
	if len(healthHistory.samples) > 120 {
		healthHistory.samples = healthHistory.samples[1:]
	}
	healthHistory.sampled = time.Now()
	persistHealthLocked(false)
	return sample
}

func recordToolObservation(kind string, value string) {
	value = normalizedObservation(value)
	if len(value) > 32768 {
		value = value[:32768] + "[normalized observation truncated at 32 KiB]"
	}
	healthHistory.Lock()
	defer healthHistory.Unlock()
	if healthHistory.observations == nil {
		healthHistory.observations = map[string]string{}
	}
	previous, exists := healthHistory.observations[kind]
	healthHistory.observations[kind] = value
	if !exists || previous == value {
		return
	}
	beforeHash := sha256.Sum256([]byte(previous))
	afterHash := sha256.Sum256([]byte(value))
	healthHistory.changes = append(healthHistory.changes, map[string]any{"kind": kind, "observed_at": time.Now().UTC().Format(time.RFC3339), "before_sha256": hex.EncodeToString(beforeHash[:]), "after_sha256": hex.EncodeToString(afterHash[:]), "before_preview": previous[:min(len(previous), 4096)], "after_preview": value[:min(len(value), 4096)], "coverage": "observations collected by explicit jobs; not continuous event monitoring"})
	if len(healthHistory.changes) > 32 {
		healthHistory.changes = healthHistory.changes[len(healthHistory.changes)-32:]
	}
}

func collectToolArtifacts(j Job, c Config, m ToolManifest, started time.Time) ([]ToolArtifact, error) {
	result := []ToolArtifact{}
	base := filepath.Join(toolsRoot(c), m.ID)
	entries, e := os.ReadDir(base)
	if e != nil {
		return result, e
	}
	root := filepath.Join(toolsRoot(c), "artifacts")
	if e = os.MkdirAll(root, 0700); e != nil {
		return result, e
	}
	installed, _, e := readInstalled(c, m.ID)
	if e != nil {
		return result, e
	}
	for _, entry := range entries {
		if _, ok := installed.Files[entry.Name()]; ok || entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".zip") && name != "results.xml" {
			continue
		}
		info, e := entry.Info()
		if e != nil || info.ModTime().Before(started.Add(-time.Second)) {
			continue
		}
		if len(result) >= 8 {
			return result, errors.New("artifact count budget exceeded")
		}
		if size, e := treeSize(root); e != nil || size+info.Size() > 128<<20 {
			return result, errors.New("endpoint artifact quota exceeded")
		}
		content, e := readBounded(filepath.Join(base, name), 32<<20)
		if e != nil {
			return result, e
		}
		id := newArtifactID()
		if id == "" {
			return result, errors.New("artifact identity unavailable")
		}
		path := filepath.Join(root, id+".zip")
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return result, e
		}
		_, writeErr := f.Write(content)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			os.Remove(path)
			return result, errors.New("artifact write failed")
		}
		h := sha256.Sum256(content)
		kind := "application/zip"
		if name == "results.xml" {
			kind = "application/xml"
		}
		metadata := ToolArtifact{id, name, hex.EncodeToString(h[:]), int64(len(content)), kind, time.Now().UTC().Format(time.RFC3339), c.Endpoint, c.Identity, text(j, "case_id"), j.ID, m.ID, m.Version}
		if e = saveJSON(filepath.Join(root, id+".json"), metadata); e != nil {
			os.Remove(path)
			return result, e
		}
		result = append(result, metadata)
	}
	if len(result) == 0 {
		return result, errors.New("collector produced no retained archive; verify the approved configuration output directory")
	}
	return result, nil
}
func runBuiltinTool(ctx context.Context, j Job, c Config) Result {
	id, profile := text(j, "tool_id"), text(j, "profile")
	switch id {
	case "health":
		sample := sampleHealth(c)
		var checks map[string]string
		if profile == "changes" {
			checks = refreshHealthObservations(ctx, j, c)
		}
		healthHistory.Lock()
		defer healthHistory.Unlock()
		if profile == "history" {
			return toolResult(map[string]any{"samples": healthHistory.samples, "retention": "up to 120 samples persisted privately, 512 KiB state cap", "interval_seconds": 30, "last_saved_at": healthHistory.persisted.UTC().Format(time.RFC3339), "persistence_error": healthHistory.persistenceError})
		}
		if profile == "changes" {
			return toolResult(map[string]any{"changes": healthHistory.changes, "checks": checks, "coverage": "network interfaces sampled; normalized service/software/startup snapshots collected on request; persisted across worker restart"})
		}
		return toolResult(sample)
	case "connectivity":
		return connectivityTool(ctx, j)
	case "wxlfgar":
		v := platformCapabilities()
		state := "ready"
		reason := "Use Network capture for authenticated capture sessions"
		if !captureInstalled() {
			state = "not_installed"
			reason = "Install Wxlfgar from Network capture"
		} else if runtime.GOOS == "windows" && v["npcap_driver_installed"] != true {
			state = "manual_action_required"
			reason = "Npcap is absent; its free installer requires an interactive administrator session"
		} else if runtime.GOOS == "windows" && v["dumpcap"] != true {
			state = "missing_dependency"
			reason = "Wireshark dumpcap is absent"
		} else if runtime.GOOS == "linux" {
			if _, e := os.Stat("/usr/bin/dumpcap"); e != nil {
				state = "missing_dependency"
				reason = "Distribution dumpcap package is absent"
			}
		}
		return toolResult(map[string]any{"state": state, "detail": reason, "features": v, "qualification": "Readiness checks installation prerequisites; capture interface enumeration remains authoritative"})
	case "evidence":
		return evidenceTool(ctx, j, c)
	}
	return safeResultError("Built-in tool unsupported")
}
func connectivityTool(ctx context.Context, j Job) Result {
	var inputs map[string]any
	_ = json.Unmarshal(j.Params["inputs"], &inputs)
	host := inputs["host"].(string)
	port := int(inputs["port"].(float64))
	profile := text(j, "profile")
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	started := time.Now()
	result := map[string]any{"host": host, "port": port, "profile": profile, "observed_at": started.UTC().Format(time.RFC3339)}
	addresses, e := net.DefaultResolver.LookupIPAddr(probeCtx, host)
	if e != nil {
		result["outcome"] = "dns_failed"
		result["detail"] = e.Error()
		return toolResult(result)
	}
	ips := []string{}
	for _, a := range addresses {
		ips = append(ips, a.IP.String())
	}
	result["addresses"] = ips
	if profile == "dns" {
		result["outcome"] = "resolved"
		return toolResult(result)
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, e := dialer.DialContext(probeCtx, "tcp", address)
	if e != nil {
		result["outcome"] = "tcp_failed"
		result["detail"] = e.Error()
		return toolResult(result)
	}
	defer conn.Close()
	result["remote_address"] = conn.RemoteAddr().String()
	if profile == "tls" {
		secure := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if e = secure.HandshakeContext(probeCtx); e != nil {
			result["outcome"] = "tls_failed"
			result["detail"] = e.Error()
			return toolResult(result)
		}
		state := secure.ConnectionState()
		result["tls_version"] = state.Version
		if len(state.PeerCertificates) > 0 {
			result["certificate_expires"] = state.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
		}
	}
	result["outcome"] = "connected"
	result["elapsed_ms"] = time.Since(started).Milliseconds()
	return toolResult(result)
}

type ToolArtifact struct {
	ID          string `json:"artifact_id"`
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	Created     string `json:"created_at"`
	Endpoint    string `json:"endpoint_id"`
	Identity    string `json:"identity_id"`
	Case        string `json:"case_id"`
	Job         string `json:"job_id"`
	Tool        string `json:"tool_id"`
	Version     string `json:"tool_version"`
}

func newArtifactID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return ""
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func evidenceTool(ctx context.Context, j Job, c Config) Result {
	return evidenceToolWithCollector(ctx, j, c, executeJob)
}

// Keep packaging success separate from observation completeness. A useful
// archive may contain failed or truncated collectors and must disclose that.
func evidenceToolWithCollector(ctx context.Context, j Job, c Config, collect func(context.Context, Job, Config) Result) Result {
	facts := map[string]any{"health": sampleHealth(c), "capabilities": capabilities(c)}
	selected := []string{"services.list", "processes.list", "reboot.status"}
	coverage := []string{}
	outcomes := []map[string]any{}
	if text(j, "profile") == "soc" {
		selected = append(selected, "posture")
	}
	for _, action := range selected {
		if ctx.Err() != nil {
			return safeResultError("Evidence collection cancelled")
		}
		sub := j
		sub.Action = action
		sub.Params = map[string]json.RawMessage{}
		result := collect(ctx, sub, c)
		facts[action] = result
		complete := result.State == "completed" && result.Exit == 0 && result.Error == "" && !result.Truncated
		if complete {
			coverage = append(coverage, action)
		}
		outcomes = append(outcomes, map[string]any{"collector": action, "state": result.State, "exit_code": result.Exit, "truncated": result.Truncated, "complete": complete})
	}
	if ctx.Err() != nil {
		return safeResultError("Evidence collection cancelled")
	}
	partial := len(coverage) != len(selected)
	phase := "completed"
	if partial {
		phase = "partial"
	}
	collection := map[string]any{"phase": phase, "partial": partial, "coverage": coverage, "requested_coverage": selected, "collectors": outcomes}
	facts["collection"] = collection
	root := filepath.Join(toolsRoot(c), "artifacts")
	if e := os.MkdirAll(root, 0700); e != nil {
		return safeResultError("Cannot create evidence directory")
	}
	if size, e := treeSize(root); e != nil || size > 112<<20 {
		return safeResultError("Endpoint evidence quota reached; export and retain centrally before collecting more")
	}
	id := newArtifactID()
	if id == "" {
		return safeResultError("Cannot create evidence identity")
	}
	path := filepath.Join(root, id+".zip")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return safeResultError("Cannot create evidence artifact")
	}
	success := false
	defer func() {
		if !success {
			os.Remove(path)
		}
	}()
	zipWriter := zip.NewWriter(f)
	metadata := ToolArtifact{id, "northgate-" + text(j, "profile") + "-evidence.zip", "", 0, "application/zip", time.Now().UTC().Format(time.RFC3339), c.Endpoint, c.Identity, text(j, "case_id"), j.ID, "evidence", Version}
	facts["manifest"] = metadata
	for name, value := range facts {
		raw, _ := json.Marshal(value)
		if len(raw) > 2<<20 {
			zipWriter.Close()
			f.Close()
			return safeResultError("Evidence member exceeds budget")
		}
		entry, e := zipWriter.Create(name + ".json")
		if e == nil {
			_, e = entry.Write(raw)
		}
		if e != nil {
			zipWriter.Close()
			f.Close()
			return safeResultError("Evidence archive failed")
		}
	}
	if e = zipWriter.Close(); e != nil {
		f.Close()
		return safeResultError("Cannot finalize evidence")
	}
	if e = f.Close(); e != nil {
		return safeResultError("Cannot save evidence")
	}
	content, e := readBounded(path, 16<<20)
	if e != nil {
		return safeResultError("Evidence exceeds size budget")
	}
	h := sha256.Sum256(content)
	metadata.SHA256 = hex.EncodeToString(h[:])
	metadata.Size = int64(len(content))
	if e = saveJSON(filepath.Join(root, id+".json"), metadata); e != nil {
		return safeResultError("Cannot save evidence manifest")
	}
	success = true
	collection["artifacts"] = []ToolArtifact{metadata}
	collection["omissions"] = []string{"No arbitrary file contents, passwords or recovery protectors collected", "Volatile observations are not an atomic disk image"}
	return toolResult(collection)
}
func readToolArtifact(j Job, c Config) Result {
	id := text(j, "artifact_id")
	root := filepath.Join(toolsRoot(c), "artifacts")
	var metadata ToolArtifact
	b, e := readBounded(filepath.Join(root, id+".json"), 8192)
	if e != nil || json.Unmarshal(b, &metadata) != nil || metadata.ID != id || metadata.Endpoint != c.Endpoint || metadata.Identity != c.Identity {
		return safeResultError("Artifact not found for this enrollment")
	}
	// The server authorizes this case before signing the job. Keeping the case
	// binding on the worker prevents a caller from omitting or substituting it.
	if metadata.Case != text(j, "case_id") {
		return safeResultError("Artifact belongs to a different case context")
	}
	f, e := os.Open(filepath.Join(root, id+".zip"))
	if e != nil {
		return safeResultError("Artifact unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != metadata.Size {
		return safeResultError("Artifact integrity metadata changed")
	}
	offset := int64(integer(j, "offset"))
	if offset > metadata.Size {
		return safeResultError("Artifact offset outside data")
	}
	if _, e = f.Seek(offset, io.SeekStart); e != nil {
		return safeResultError("Artifact offset invalid")
	}
	data := make([]byte, min(integer(j, "size"), int(metadata.Size-offset)))
	n, e := io.ReadFull(f, data)
	if e != nil && e != io.EOF && e != io.ErrUnexpectedEOF {
		return safeResultError("Artifact read failed")
	}
	data = data[:n]
	h := sha256.Sum256(data)
	return toolResult(map[string]any{"artifact": metadata, "offset": offset, "next_offset": offset + int64(n), "eof": offset+int64(n) == metadata.Size, "data": base64.StdEncoding.EncodeToString(data), "chunk_sha256": hex.EncodeToString(h[:])})
}
func treeSize(root string) (int64, error) {
	var total int64
	count := 0
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		count++
		if count > 2048 {
			return errors.New("Tool file count budget exceeded")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("Tool symlink rejected")
		}
		if !d.IsDir() {
			i, e := d.Info()
			if e != nil {
				return e
			}
			total += i.Size()
		}
		return nil
	})
	return total, e
}
func enforceToolDisk(ctx context.Context, cancel context.CancelFunc, root string, limit int64) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if size, e := treeSize(root); e != nil || size > limit {
				cancel()
				return
			}
		}
	}
}
