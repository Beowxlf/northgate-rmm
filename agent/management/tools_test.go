package management

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestToolArtifactCaseAndEnrollmentBinding(t *testing.T) {
	c := configForTest(t)
	id := "44444444-4444-4444-8444-444444444444"
	caseID := "55555555-5555-4555-8555-555555555555"
	data := []byte("synthetic evidence")
	digest := sha256.Sum256(data)
	root := filepath.Join(toolsRoot(c), "artifacts")
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	metadata := ToolArtifact{ID: id, Case: caseID, Endpoint: c.Endpoint, Identity: c.Identity, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
	encoded, _ := json.Marshal(metadata)
	if e := os.WriteFile(filepath.Join(root, id+".json"), encoded, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, id+".zip"), data, 0600); e != nil {
		t.Fatal(e)
	}
	for _, context := range []string{"", "66666666-6666-4666-8666-666666666666", caseID} {
		job := jobForTest("tool.artifact.read", map[string]any{"artifact_id": id, "offset": 0, "size": 8, "case_id": context})
		if e := validateToolJob(job, c); e != nil {
			t.Fatal(e)
		}
		result := readToolArtifact(job, c)
		if context != caseID {
			if result.State != "failed" {
				t.Fatal("artifact case binding bypassed")
			}
			continue
		}
		var value struct {
			Data string `json:"data"`
			Hash string `json:"chunk_sha256"`
			Next int    `json:"next_offset"`
		}
		if result.State != "completed" || json.Unmarshal([]byte(result.Output), &value) != nil {
			t.Fatal(result)
		}
		chunk := sha256.Sum256(data[:8])
		if value.Data != base64.StdEncoding.EncodeToString(data[:8]) || value.Hash != hex.EncodeToString(chunk[:]) || value.Next != 8 {
			t.Fatal("incorrect resumable chunk")
		}
		c.Identity = "77777777-7777-4777-8777-777777777777"
		if readToolArtifact(job, c).State != "failed" {
			t.Fatal("changed enrollment can read old evidence")
		}
	}
}

func TestDiagnosticCompletionAndLeaseDoNotCancelTerminal(t *testing.T) {
	c := configForTest(t)
	if e := os.MkdirAll(filepath.Join(c.Root, "receipts"), 0700); e != nil {
		t.Fatal(e)
	}
	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()
	diagCtx, diagCancel := context.WithCancel(context.Background())
	defer diagCancel()
	main := Job{ID: "44444444-4444-4444-8444-444444444444", Action: "shell.start"}
	diag := jobForTest("tool.run", map[string]any{"tool_id": "health", "profile": "snapshot", "inputs": map[string]any{}, "case_id": ""})
	worker := Worker{cfg: c, job: &main, cancel: mainCancel, lease: time.Now().Add(time.Minute),
		diagnostic: &diag, diagnosticCancel: diagCancel, diagnosticLease: time.Now().Add(-time.Second), receipts: map[string]Receipt{}}
	worker.expireLease()
	if diagCtx.Err() == nil || mainCtx.Err() != nil {
		t.Fatal("diagnostic expiration affected wrong lane")
	}
	worker.execute(context.Background(), diag)
	if worker.job != &main || worker.diagnostic != nil || mainCtx.Err() != nil {
		t.Fatal("diagnostic completion cleared terminal")
	}
	if _, ok := worker.receipts[diag.ID]; !ok {
		t.Fatal("diagnostic receipt not retained")
	}
	freshDiagCtx, freshDiagCancel := context.WithCancel(context.Background())
	defer freshDiagCancel()
	worker.diagnostic = &diag
	worker.diagnosticCancel = freshDiagCancel
	worker.diagnosticLease = time.Now().Add(time.Minute)
	worker.lease = time.Now().Add(-time.Second)
	worker.expireLease()
	if mainCtx.Err() == nil || freshDiagCtx.Err() != nil {
		t.Fatal("terminal expiration affected wrong lane")
	}
}

func TestToolManifestsRejectUnapprovedAndWrongPlatform(t *testing.T) {
	c := configForTest(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c.UpdateKey = base64.StdEncoding.EncodeToString(pub)
	entry := "osqueryi"
	if runtime.GOOS == "windows" {
		entry += ".exe"
	}
	m := ToolManifest{Schema: 1, ID: "osquery", Revision: 1, Version: "5.19.0", Platform: runtime.GOOS, Arch: runtime.GOARCH, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 100, Entrypoint: entry, License: "Apache-2.0", Source: "https://osquery.io/", Privilege: "system", Budget: ToolBudget{30, 128, 10, 64, 64}}
	b, _ := json.Marshal(m)
	encoded := base64.StdEncoding.EncodeToString(b)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("NorthGate-Tool-v1\x00"), b...)))
	if _, e := toolManifest(c, encoded, signature); e != nil {
		t.Fatal(e)
	}
	if _, e := toolManifest(c, encoded, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))); e == nil {
		t.Fatal("unapproved signature accepted")
	}
	m.Platform = "plan9"
	b, _ = json.Marshal(m)
	signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("NorthGate-Tool-v1\x00"), b...)))
	if _, e := toolManifest(c, base64.StdEncoding.EncodeToString(b), signature); e == nil {
		t.Fatal("wrong platform accepted")
	}
}
func TestToolArchiveRejectsEscapeDuplicateAndBudget(t *testing.T) {
	for _, names := range [][]string{{"../escape"}, {"A", "a"}, {"installed.json"}, {"safe", "safe"}} {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		for _, name := range names {
			f, _ := z.Create(name)
			f.Write([]byte("test"))
		}
		z.Close()
		path := filepath.Join(t.TempDir(), "bundle.zip")
		os.WriteFile(path, b.Bytes(), 0600)
		if _, e := extractToolArchive(path, t.TempDir(), 100); e == nil {
			t.Fatalf("unsafe names accepted: %v", names)
		}
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, _ := z.Create("safe")
	f.Write(bytes.Repeat([]byte{1}, 100))
	z.Close()
	path := filepath.Join(t.TempDir(), "bundle.zip")
	os.WriteFile(path, b.Bytes(), 0600)
	if _, e := extractToolArchive(path, t.TempDir(), 10); e == nil {
		t.Fatal("oversized archive accepted")
	}
}
func TestToolDiagnosticLaneAndInputContracts(t *testing.T) {
	c := configForTest(t)
	j := jobForTest("tool.run", map[string]any{"tool_id": "connectivity", "profile": "tcp", "inputs": map[string]any{"host": "127.0.0.1", "port": "bad"}, "case_id": ""})
	if validateJob(j, c) == nil {
		t.Fatal("wrong port type accepted")
	}
	j = jobForTest("tool.run", map[string]any{"tool_id": "health", "profile": "snapshot", "inputs": map[string]any{}, "case_id": ""})
	if !diagnosticJob(j) || validateJob(j, c) != nil {
		t.Fatal("health diagnostic unavailable")
	}
	j.Action = "tool.install"
	if diagnosticJob(j) {
		t.Fatal("installer permitted in diagnostic lane")
	}
}
func TestToolHealthUsesCacheAndDiskWatchdogCancels(t *testing.T) {
	c := configForTest(t)
	first := sampleHealth(c)
	second := sampleHealth(c)
	if first["collected_at"] != second["collected_at"] {
		t.Fatal("health sample not cached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "large"), make([]byte, 4096), 0600)
	go enforceToolDisk(ctx, cancel, root, 1024)
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("disk budget not enforced")
	}
}

func TestToolHealthPersistsAndNormalizesObservationOrder(t *testing.T) {
	c := configForTest(t)
	sampleHealth(c)
	recordToolObservation("services.list", `[{"name":"b"},{"name":"a"}]`)
	healthHistory.Lock()
	before := len(healthHistory.changes)
	healthHistory.Unlock()
	recordToolObservation("services.list", `[{"name":"a"},{"name":"b"}]`)
	healthHistory.Lock()
	if len(healthHistory.changes) != before {
		t.Error("record ordering generated false drift")
	}
	persistHealthLocked(true)
	healthHistory.root = ""
	healthHistory.samples = nil
	healthHistory.Unlock()
	sampleHealth(c)
	healthHistory.Lock()
	defer healthHistory.Unlock()
	if len(healthHistory.samples) < 2 || healthHistory.observations["services.list"] == "" {
		t.Error("persisted history did not survive simulated worker restart")
	}
	if healthHistory.persistenceError != "" {
		t.Fatal(healthHistory.persistenceError)
	}
}
