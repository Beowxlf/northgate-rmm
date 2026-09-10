package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var actions = map[string][]string{
	"capture.install": {"url", "sha256", "signature", "version", "public_key"},
	"capabilities":    {}, "prerequisites.install": {}, "posture": {}, "services.list": {}, "service.control": {"name", "operation"},
	"processes.list": {}, "process.stop": {"pid", "start_token"}, "files.list": {"path"}, "files.read": {"path"},
	"files.write": {"path", "data", "sha256", "overwrite"}, "logs.read": {"channel", "since", "limit"},
	"reboot.status": {}, "reboot": {"delay"}, "packages.list": {}, "package.install": {"name"}, "package.remove": {"name"},
	"patches.scan": {}, "patches.install": {}, "encryption.status": {}, "bitlocker.escrow": {},
	"recovery.rotate": {"hours"}, "isolation.start": {"seconds"}, "isolation.release": {},
	"script.run": {"script_id", "version", "inputs", "content"}, "shell.start": {"columns", "rows"},
	"update.install": {"component", "url", "sha256", "signature", "version"},
}

func text(j Job, key string) string  { var v string; _ = json.Unmarshal(j.Params[key], &v); return v }
func integer(j Job, key string) int  { var v int; _ = json.Unmarshal(j.Params[key], &v); return v }
func boolean(j Job, key string) bool { var v bool; _ = json.Unmarshal(j.Params[key], &v); return v }
func validateJob(j Job, c Config) error {
	keys, ok := actions[j.Action]
	if !ok || len(keys) != len(j.Params) {
		return errors.New("unsupported job contract")
	}
	for _, k := range keys {
		if _, ok = j.Params[k]; !ok {
			return errors.New("missing job input")
		}
	}
	checkInt := func(key string, low, high int) bool {
		var v int
		return json.Unmarshal(j.Params[key], &v) == nil && v >= low && v <= high
	}
	name := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@+:-]{0,127}$`)
	if strings.HasPrefix(j.Action, "files.") {
		p := text(j, "path")
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\r\n") || len(p) > 1024 || p != filepath.Clean(p) {
			return errors.New("absolute clean file path required")
		}
		if within(c.Root, p) || within(filepath.Dir(c.IdentityFile), p) || strings.EqualFold(p, c.Roots) {
			return errors.New("use dedicated recovery workflows for worker identity and state")
		}
	}
	switch j.Action {
	case "service.control":
		op := text(j, "operation")
		n := strings.ToLower(text(j, "name"))
		if !name.MatchString(n) || (op != "start" && op != "stop" && op != "restart") || strings.HasPrefix(n, "northgate") || n == "sshd" || n == "ssh" {
			return errors.New("invalid or protected service")
		}
	case "process.stop":
		if !regexp.MustCompile(`^[0-9]{1,24}$`).MatchString(text(j, "start_token")) {
			return errors.New("process start token required")
		}
		if !checkInt("pid", 5, 2147483647) || integer(j, "pid") == os.Getpid() {
			return errors.New("invalid or protected process")
		}
	case "logs.read":
		if !checkInt("since", 1, 1440) || !checkInt("limit", 1, 500) {
			return errors.New("invalid log bounds")
		}
		allowed := map[string]bool{"System": true, "Application": true, "Security": true, "Sysmon": true, "Defender": true, "journal": true, "auth": true}
		if !allowed[text(j, "channel")] {
			return errors.New("unsupported log")
		}
	case "files.write":
		b, e := base64.StdEncoding.DecodeString(text(j, "data"))
		var overwrite bool
		if e != nil || len(b) > MaxFile || json.Unmarshal(j.Params["overwrite"], &overwrite) != nil {
			return errors.New("invalid upload")
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != text(j, "sha256") {
			return errors.New("upload hash mismatch")
		}
	case "reboot":
		if !checkInt("delay", 30, 300) {
			return errors.New("invalid reboot delay")
		}
	case "recovery.rotate":
		if !checkInt("hours", 1, 168) {
			return errors.New("invalid recovery lifetime")
		}
	case "isolation.start":
		if !checkInt("seconds", 30, 300) {
			return errors.New("invalid isolation lifetime")
		}
	case "shell.start":
		if !checkInt("columns", 20, 240) || !checkInt("rows", 5, 100) {
			return errors.New("invalid terminal size")
		}
	case "package.install", "package.remove":
		if !name.MatchString(text(j, "name")) || strings.HasPrefix(text(j, "name"), "-") {
			return errors.New("invalid package identifier")
		}
	case "bitlocker.escrow":
		if runtime.GOOS != "windows" {
			return errors.New("BitLocker not supported on this platform")
		}
	case "script.run":
		if !ID.MatchString(text(j, "script_id")) || len(text(j, "content")) > 32768 {
			return errors.New("invalid script")
		}
	}
	return nil
}
func within(root, path string) bool {
	rel, e := filepath.Rel(root, path)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

type boundedOutput struct {
	mu sync.Mutex
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.Len()
	if n > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
func runCommand(ctx context.Context, cmd *exec.Cmd, limit int) Result {
	output := &boundedOutput{limit: limit}
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.WaitDelay = 2 * time.Second
	configureProcess(cmd)
	e := cmd.Run()
	r := Result{State: "completed", Exit: 0, Output: output.String(), Identity: executionIdentity(), Truncated: output.truncated}
	if e != nil {
		r.State = "failed"
		r.Exit = -1
		if cmd.ProcessState != nil {
			r.Exit = cmd.ProcessState.ExitCode()
		}
		r.Error = "Operation failed; inspect bounded output"
	}
	if ctx.Err() != nil {
		r.State = "cancelled"
		r.Error = "Operation cancelled or expired"
	}
	return r
}
func executeJob(ctx context.Context, j Job, c Config) Result {
	r := Result{State: "failed", Exit: -1, Identity: executionIdentity()}
	if e := validateJob(j, c); e != nil {
		r.Error = e.Error()
		return r
	}
	if j.Action == "capabilities" {
		b, _ := json.Marshal(capabilities(c))
		return Result{State: "completed", Exit: 0, Output: string(b), Identity: executionIdentity()}
	}
	if strings.HasPrefix(j.Action, "files.") {
		b, e := fileAction(j)
		if e != nil {
			r.Error = e.Error()
			return r
		}
		return Result{State: "completed", Exit: 0, Output: string(b), Identity: executionIdentity()}
	}
	if j.Action == "update.install" {
		return installUpdate(ctx, j, c)
	}
	if j.Action == "capture.install" {
		return installCapture(ctx, j, c)
	}
	if j.Action == "script.run" {
		content := text(j, "content")
		var inputs map[string]string
		if json.Unmarshal(j.Params["inputs"], &inputs) != nil || len(inputs) > 16 {
			r.Error = "Invalid script inputs"
			return r
		}
		folder, e := os.MkdirTemp(c.Root, "script-")
		if e != nil {
			r.Error = "Cannot stage script"
			return r
		}
		defer os.RemoveAll(folder)
		extension := ".sh"
		if runtime.GOOS == "windows" {
			extension = ".ps1"
		}
		path := filepath.Join(folder, "reviewed"+extension)
		if e = os.WriteFile(path, []byte(content), 0600); e != nil {
			r.Error = "Cannot stage script"
			return r
		}
		cmd := scriptCommand(ctx, path)
		cmd.Env = append(os.Environ(), "NG_EXERCISE_ID="+j.Exercise)
		for k, v := range inputs {
			if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`).MatchString(k) || len(v) > 4096 || strings.ContainsRune(v, 0) {
				r.Error = "Invalid script input"
				return r
			}
			cmd.Env = append(cmd.Env, "NG_INPUT_"+k+"="+v)
		}
		return runCommand(ctx, cmd, MaxOutput)
	}
	return platformAction(ctx, j, c)
}
func fileAction(j Job) ([]byte, error) {
	path := text(j, "path")
	if j.Action == "files.list" {
		root, e := os.OpenRoot(path)
		if e != nil {
			return nil, e
		}
		defer root.Close()
		f, e := root.Open(".")
		if e != nil {
			return nil, e
		}
		defer f.Close()
		entries, e := f.ReadDir(501)
		if e != nil && e != io.EOF {
			return nil, e
		}
		result := []map[string]any{}
		for n, entry := range entries {
			if n == 500 {
				break
			}
			i, e := entry.Info()
			if e != nil {
				continue
			}
			result = append(result, map[string]any{"name": entry.Name(), "directory": entry.IsDir(), "size": i.Size(), "modified": i.ModTime().UTC(), "symlink": i.Mode()&os.ModeSymlink != 0})
		}
		return json.Marshal(map[string]any{"entries": result, "truncated": len(entries) > 500})
	}
	root, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer root.Close()
	name := filepath.Base(path)
	info, e := root.Lstat(name)
	if e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("regular files only")
	}
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if j.Action == "files.read" {
		if e != nil {
			return nil, e
		}
		if info.Size() > MaxFile {
			return nil, errors.New("file exceeds 16 MiB limit")
		}
		f, e := root.Open(name)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		opened, e := f.Stat()
		if e != nil || !os.SameFile(info, opened) {
			return nil, errors.New("file changed")
		}
		b, e := io.ReadAll(io.LimitReader(f, MaxFile+1))
		if e != nil || len(b) > MaxFile {
			return nil, errors.New("file changed or exceeds limit")
		}
		h := sha256.Sum256(b)
		return json.Marshal(map[string]any{"name": name, "size": len(b), "sha256": hex.EncodeToString(h[:]), "data": base64.StdEncoding.EncodeToString(b)})
	}
	if e == nil && !boolean(j, "overwrite") {
		return nil, errors.New("file exists; explicit overwrite required")
	}
	data, _ := base64.StdEncoding.DecodeString(text(j, "data"))
	staging := ".northgate-upload-" + j.ID
	f, e := root.OpenFile(staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer root.Remove(staging)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return nil, e
	}
	// An existing destination is retained as a uniquely named rollback copy.
	backup := ""
	if info != nil {
		backup = name + ".northgate-backup-" + j.ID
		if _, e = root.Lstat(backup); !os.IsNotExist(e) {
			return nil, errors.New("backup path exists")
		}
		if e = root.Rename(name, backup); e != nil {
			return nil, e
		}
	}
	if e = root.Rename(staging, name); e != nil {
		if backup != "" {
			_ = root.Rename(backup, name)
		}
		return nil, e
	}
	return json.Marshal(map[string]any{"name": name, "size": len(data), "sha256": text(j, "sha256"), "backup": backup})
}
func recoveryAccountStatus(c Config) map[string]any {
	b, e := readBounded(filepath.Join(c.Root, "recovery-account.json"), 4096)
	if e != nil {
		return map[string]any{"managed": false}
	}
	var value struct {
		Name    string `json:"name"`
		Expires string `json:"expires"`
	}
	if json.Unmarshal(b, &value) != nil {
		return map[string]any{"managed": false, "reason": "Invalid recovery metadata"}
	}
	expiry, e := time.Parse(time.RFC3339, value.Expires)
	if e != nil {
		return map[string]any{"managed": true, "reason": "Expiry could not be verified"}
	}
	return map[string]any{"managed": true, "name": value.Name, "expires": value.Expires, "expired": time.Now().After(expiry), "expires_soon": time.Until(expiry) < 24*time.Hour}
}
func replaceFile(source, destination string) error { return os.Rename(source, destination) }
func safeResultError(message string) Result {
	return Result{State: "failed", Exit: -1, Identity: executionIdentity(), Error: message}
}
func secondsSince(when time.Time) string { return fmt.Sprint(int(time.Since(when).Seconds())) }
