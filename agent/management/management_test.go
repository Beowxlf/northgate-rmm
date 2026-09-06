package management

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func configForTest(t *testing.T) Config {
	t.Helper()
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	escrow, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return Config{Endpoint: "11111111-1111-4111-8111-111111111111", Identity: "22222222-2222-4222-8222-222222222222", Root: t.TempDir(), IdentityFile: filepath.Join(t.TempDir(), "identity.json"), Roots: filepath.Join(t.TempDir(), "roots.pem"), Signing: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Escrow: base64.StdEncoding.EncodeToString(escrow.PublicKey().Bytes()), UpdateKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))}
}
func jobForTest(action string, params map[string]any) Job {
	raw := map[string]json.RawMessage{}
	for k, v := range params {
		raw[k], _ = json.Marshal(v)
	}
	return Job{ID: "33333333-3333-4333-8333-333333333333", Action: action, Params: raw}
}

func TestBoundedFilesIntegrityAndOverwrite(t *testing.T) {
	c := configForTest(t)
	path := filepath.Join(t.TempDir(), "ops.txt")
	data := []byte("NorthGate synthetic data")
	hash := sha256.Sum256(data)
	job := jobForTest("files.write", map[string]any{"path": path, "data": base64.StdEncoding.EncodeToString(data), "sha256": hex.EncodeToString(hash[:]), "overwrite": false})
	if e := validateJob(job, c); e != nil {
		t.Fatal(e)
	}
	if _, e := fileAction(job); e != nil {
		t.Fatal(e)
	}
	if _, e := fileAction(job); e == nil {
		t.Fatal("implicit overwrite accepted")
	}
	read := jobForTest("files.read", map[string]any{"path": path})
	result, e := fileAction(read)
	if e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if json.Unmarshal(result, &value) != nil || value["sha256"] != hex.EncodeToString(hash[:]) {
		t.Fatal("download integrity missing")
	}
	denied := jobForTest("files.read", map[string]any{"path": filepath.Join(c.Root, "secret")})
	if validateJob(denied, c) == nil {
		t.Fatal("worker state exposed through ordinary files")
	}
	job.Params["sha256"] = json.RawMessage(`"invalid"`)
	if validateJob(job, c) == nil {
		t.Fatal("bad upload digest accepted")
	}
}

func TestSignedResponseBindingAndExpiry(t *testing.T) {
	c := configForTest(t)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	c.Signing = base64.StdEncoding.EncodeToString(public)
	value := Response{Schema: 1, Endpoint: c.Endpoint, Identity: c.Identity, Nonce: "test-nonce", Expires: time.Now().Unix() + 30}
	encode := func() Envelope {
		raw, _ := json.Marshal(value)
		return Envelope{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("NorthGate-Management-v1\x00"), raw...)))}
	}
	env := encode()
	if _, e := verify(c, env, "test-nonce"); e != nil {
		t.Fatal(e)
	}
	if _, e := verify(c, env, "replayed-nonce"); e == nil {
		t.Fatal("replayed response accepted")
	}
	value.Identity = c.Endpoint
	if _, e := verify(c, encode(), "test-nonce"); e == nil {
		t.Fatal("wrong enrollment accepted")
	}
	value.Identity = c.Identity
	value.Expires = time.Now().Unix() - 1
	if _, e := verify(c, encode(), "test-nonce"); e == nil {
		t.Fatal("expired response accepted")
	}
}

func TestIndependentReleaseSignatureAndDowngrade(t *testing.T) {
	c := configForTest(t)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	c.UpdateKey = base64.StdEncoding.EncodeToString(public)
	manifest := ReleaseManifest{Component: "worker", Platform: runtime.GOOS, SHA256: strings.Repeat("a", 64), Version: "1.1.0-lab.2"}
	raw, _ := json.Marshal(manifest)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("NorthGate-Release-v1\x00"), raw...)))
	if e := verifyRelease(c, manifest, sig); e != nil {
		t.Fatal(e)
	}
	manifest.SHA256 = strings.Repeat("b", 64)
	if verifyRelease(c, manifest, sig) == nil {
		t.Fatal("tampered release accepted")
	}
	if !newer("1.1.0", "1.1.0-lab.10") || newer("1.1.0-lab.2", "1.1.0") || newer("1.1.0", "1.1.0") {
		t.Fatal("release ordering invalid")
	}
}

func TestAcceptanceMarkerIsCreateOnceAndReceiptOpaque(t *testing.T) {
	c := configForTest(t)
	job := jobForTest("posture", nil)
	path := filepath.Join(c.Root, job.ID)
	if e := saveJSON(path, map[string]string{"state": "accepted"}); e != nil {
		t.Fatal(e)
	}
	if e := saveJSON(path, map[string]string{"state": "accepted"}); e == nil {
		t.Fatal("duplicate acceptance allowed")
	}
	encrypted, e := encryptResult(c, job.ID, Result{State: "completed", Output: "synthetic-secret"})
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(encrypted)
	if strings.Contains(string(raw), "synthetic-secret") {
		t.Fatal("plaintext receipt")
	}
}

func TestLeaseWatchdogDoesNotNeedNetworkProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := Worker{job: &Job{}, cancel: cancel, lease: time.Now().Add(-time.Second)}
	w.expireLease()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expired lease did not cancel")
	}
}

func TestTerminalInputOutputResizeAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	term, e := openTerminal(ctx, 100, 30)
	if e != nil {
		t.Fatal(e)
	}
	defer term.Close()
	if e = term.Resize(80, 24); e != nil {
		t.Fatal(e)
	}
	done := make(chan bool, 1)
	go func() {
		buffer := make([]byte, 4096)
		var output strings.Builder
		for {
			n, e := term.Read(buffer)
			output.Write(buffer[:n])
			if strings.Contains(output.String(), "NORTHGATE_TEST_RESULT_42") {
				done <- true
				return
			}
			if e != nil {
				done <- false
				return
			}
		}
	}()
	command := "printf 'NORTHGATE_TEST_RESULT_%s\\n' 42\r"
	if runtime.GOOS == "windows" {
		command = "Write-Output ('NORTHGATE_TEST_RESULT_' + (40+2))\r"
	}
	if _, e = term.Write([]byte(command)); e != nil {
		t.Fatal(e)
	}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("terminal ended before output")
		}
	case <-ctx.Done():
		t.Fatal("terminal output timed out")
	}
	if e = term.Close(); e != nil {
		t.Fatal(e)
	}
	term.Close()
}

func TestInvalidContractsNeverExecute(t *testing.T) {
	c := configForTest(t)
	for _, job := range []Job{jobForTest("service.control", map[string]any{"name": "sshd", "operation": "stop"}), jobForTest("isolation.start", map[string]any{"seconds": 900}), jobForTest("package.install", map[string]any{"name": "--help"}), jobForTest("shell.start", map[string]any{"columns": 0, "rows": 30}), jobForTest("process.stop", map[string]any{"pid": os.Getpid()})} {
		if validateJob(job, c) == nil {
			t.Fatalf("unsafe %s contract accepted", job.Action)
		}
	}
}

func TestMaximumFileReceiptFitsTransport(t *testing.T) {
	c := configForTest(t)
	path := filepath.Join(t.TempDir(), "boundary.bin")
	data := make([]byte, MaxFile)
	if _, e := rand.Read(data); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	r := executeJob(context.Background(), jobForTest("files.read", map[string]any{"path": path}), c)
	if r.State != "completed" {
		t.Fatal(r.Error)
	}
	receipt, e := encryptResult(c, "33333333-3333-4333-8333-333333333333", r)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(map[string]any{"receipts": []Receipt{receipt}})
	if len(raw) > MaxResult {
		t.Fatalf("receipt exceeds transport: %d", len(raw))
	}
}

// This qualification runs only on the explicitly authorized Linux canary.
func TestAuthorizedLinuxCanaryOperations(t *testing.T) {
	host, _ := os.Hostname()
	if runtime.GOOS != "linux" || os.Getenv("NORTHGATE_CANARY_QUALIFICATION") != "NG-RMM-CAN01" || strings.ToLower(host) != "ng-rmm-can01" {
		t.Skip("explicit Linux canary qualification only")
	}
	if e := requirePrivileged(); e != nil {
		t.Fatal(e)
	}
	c := configForTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	run := func(action string, params map[string]any) Result {
		t.Helper()
		r := executeJob(ctx, jobForTest(action, params), c)
		if r.State != "completed" || r.Exit != 0 {
			t.Fatalf("%s failed: %s", action, r.Error)
		}
		if r.Identity != "root (uid=0)" {
			t.Fatal("root execution identity missing")
		}
		return r
	}
	for _, action := range []string{"posture", "services.list", "processes.list", "reboot.status", "packages.list", "encryption.status"} {
		run(action, nil)
	}
	run("logs.read", map[string]any{"channel": "journal", "since": 5, "limit": 5})
	process := exec.CommandContext(ctx, "/bin/sleep", "60")
	if e := process.Start(); e != nil {
		t.Fatal(e)
	}
	defer process.Process.Kill()
	stat, e := os.ReadFile(filepath.Join("/proc", fmt.Sprint(process.Process.Pid), "stat"))
	if e != nil {
		t.Fatal(e)
	}
	fields := strings.Fields(string(stat)[strings.LastIndex(string(stat), ") ")+2:])
	run("process.stop", map[string]any{"pid": process.Process.Pid, "start_token": fields[19]})
	if process.Wait() == nil {
		t.Fatal("synthetic sleep was not signalled")
	}
	unit := "/run/systemd/system/rmm-qualification.service"
	f, e := os.OpenFile(unit, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString("[Unit]\nDescription=Temporary RMM qualification\n[Service]\nType=simple\nExecStart=/bin/sleep 120\n")
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		exec.Command("/usr/bin/systemctl", "stop", "rmm-qualification.service").Run()
		os.Remove(unit)
		exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
	}()
	if e = exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run(); e != nil {
		t.Fatal(e)
	}
	for _, operation := range []string{"start", "restart", "stop"} {
		run("service.control", map[string]any{"name": "rmm-qualification.service", "operation": operation})
	}
	content := "printf '%s' \"$NG_INPUT_VALUE\""
	digest := sha256.Sum256([]byte(content))
	r := run("script.run", map[string]any{"script_id": "11111111-1111-4111-8111-111111111111", "version": hex.EncodeToString(digest[:]), "content": content, "inputs": map[string]string{"VALUE": "qualification-input"}})
	if r.Output != "qualification-input" {
		t.Fatal("script inputs were not preserved")
	}
}
