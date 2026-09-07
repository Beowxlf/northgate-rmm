package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type terminal interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Resize(int, int) error
	Close() error
	Wait() error
}
type Worker struct {
	cfg                      Config
	mu                       sync.Mutex
	job                      *Job
	cancel                   context.CancelFunc
	lease                    time.Time
	terminal                 terminal
	frames                   []Frame
	outputSequence, inputAck int
	receipts                 map[string]Receipt
	inventory                map[string]any
	jobsAccepted             int
}

func saveJSON(path string, value any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	return e
}
func Run(ctx context.Context, path string) error {
	if e := requirePrivileged(); e != nil {
		return e
	}
	cfg, e := loadConfig(path)
	if e != nil {
		return e
	}
	if e = validateWorkerPaths(path, cfg); e != nil {
		return e
	}
	for _, d := range []string{cfg.Root, filepath.Join(cfg.Root, "jobs"), filepath.Join(cfg.Root, "receipts")} {
		if e = os.MkdirAll(d, 0700); e != nil {
			return e
		}
		i, e := os.Lstat(d)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe worker state")
		}
	}
	w := &Worker{cfg: cfg, receipts: map[string]Receipt{}, inventory: capabilities(cfg)}
	entries, e := os.ReadDir(filepath.Join(cfg.Root, "jobs"))
	if e != nil {
		return e
	}
	if len(entries) > 10000 {
		return errors.New("job ledger full; reconcile and archive")
	}
	w.jobsAccepted = len(entries)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".ack" {
			if e = os.Remove(filepath.Join(cfg.Root, "jobs", entry.Name())); e != nil {
				return e
			}
			continue
		}
		if !ID.MatchString(entry.Name()) {
			return errors.New("unexpected job ledger entry")
		}
		receiptPath := filepath.Join(cfg.Root, "receipts", entry.Name())
		b, e := readBounded(receiptPath, MaxResult)
		var r Receipt
		if e == nil {
			if json.Unmarshal(b, &r) != nil || r.Job != entry.Name() {
				return errors.New("invalid persisted receipt")
			}
			w.receipts[r.Job] = r
			continue
		}
		marker, e := readBounded(filepath.Join(cfg.Root, "jobs", entry.Name()), 4096)
		if e != nil {
			return e
		}
		var state map[string]string
		if json.Unmarshal(marker, &state) != nil {
			return errors.New("invalid job marker")
		}
		if state["state"] == "acknowledged" {
			continue
		}
		result := Result{State: "result_unknown", Exit: -1, Identity: executionIdentity(), Error: "Worker restarted after accepting this job; it was not replayed"}
		// A separate updater writes the final transaction receipt after restarting this service.
		if _, e := os.Stat(filepath.Join(cfg.Root, "updates", entry.Name(), "plan.json")); e == nil {
			deadline := time.Now().Add(90 * time.Second)
			for time.Now().Before(deadline) {
				if b, e := readBounded(filepath.Join(cfg.Root, "updates", entry.Name(), "result.json"), 65536); e == nil {
					if json.Unmarshal(b, &result) != nil {
						return errors.New("invalid update outcome")
					}
					break
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Second):
				}
			}
		}
		r, e = encryptResult(cfg, entry.Name(), result)
		if e != nil {
			return e
		}
		if e = saveJSON(receiptPath, r); e != nil {
			return e
		}
		w.receipts[r.Job] = r
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	watchdogCtx, stopWatchdog := context.WithCancel(ctx)
	defer stopWatchdog()
	go func() {
		timer := time.NewTicker(250 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-watchdogCtx.Done():
				return
			case <-timer.C:
				w.expireLease()
			}
		}
	}()
	defer func() {
		w.mu.Lock()
		cancel, term := w.cancel, w.terminal
		w.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if term != nil {
			term.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		_ = w.poll(ctx) // No credentials, decrypted receipts or remote output in service logs.
	}
}
func (w *Worker) expireLease() {
	w.mu.Lock()
	expired := w.job != nil && time.Now().After(w.lease)
	cancel, term := w.cancel, w.terminal
	w.mu.Unlock()
	if expired {
		if cancel != nil {
			cancel()
		}
		if term != nil {
			term.Close()
		}
	}
}
func (w *Worker) poll(ctx context.Context) error {
	random := make([]byte, 24)
	if _, e := rand.Read(random); e != nil {
		return e
	}
	nonce := hex.EncodeToString(random)
	w.mu.Lock()
	receipts := []Receipt{}
	for _, r := range w.receipts {
		pendingOutput := false
		for _, frame := range w.frames {
			if frame.Job == r.Job {
				pendingOutput = true
				break
			}
		}
		if pendingOutput {
			continue
		}
		receipts = append(receipts, r)
		break
	}
	active := ""
	if w.job != nil {
		active = w.job.ID
	}
	frames := append([]Frame{}, w.frames...)
	if len(frames) > 32 {
		frames = frames[:32]
	}
	request := map[string]any{"nonce": nonce, "receipts": receipts, "active": active, "input_ack": w.inputAck, "frames": frames, "capabilities": w.inventory}
	w.mu.Unlock()
	body, e := json.Marshal(request)
	if e != nil {
		return e
	}
	client, e := client(w.cfg)
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "POST", w.cfg.Server+"/v1/management/poll", bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("management poll rejected")
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, MaxResult+1))
	if e != nil || len(raw) > MaxResult {
		return errors.New("invalid poll response")
	}
	var env Envelope
	if e = json.Unmarshal(raw, &env); e != nil {
		return e
	}
	response, e := verify(w.cfg, env, nonce)
	if e != nil {
		return e
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, id := range response.Acks {
		if _, ok := w.receipts[id]; !ok {
			continue
		}
		// Replace a non-secret marker only after the server acknowledged durable receipt.
		p := filepath.Join(w.cfg.Root, "jobs", id)
		temp := p + ".ack"
		if e = saveJSON(temp, map[string]string{"id": id, "state": "acknowledged"}); e != nil {
			return e
		}
		if e = replaceFile(temp, p); e != nil {
			return e
		}
		if e = os.Remove(filepath.Join(w.cfg.Root, "receipts", id)); e != nil {
			return e
		}
		delete(w.receipts, id)
	}
	for _, ack := range response.FrameAck {
		if len(ack) != 2 {
			continue
		}
		var id string
		var n int
		if json.Unmarshal(ack[0], &id) != nil || json.Unmarshal(ack[1], &n) != nil {
			continue
		}
		kept := w.frames[:0]
		for _, f := range w.frames {
			if f.Job != id || f.Sequence > n {
				kept = append(kept, f)
			}
		}
		w.frames = kept
	}
	for _, control := range response.Controls {
		if w.job == nil || w.job.ID != control.Job {
			continue
		}
		if control.Cancel {
			w.cancel()
			term := w.terminal
			if term != nil {
				w.mu.Unlock()
				term.Close()
				w.mu.Lock()
			}
			continue
		}
		deadline := time.UnixMilli(int64(control.Lease * 1000))
		if deadline.After(time.Now().Add(46 * time.Second)) {
			return errors.New("excessive job lease")
		}
		w.lease = deadline
		for _, input := range control.Input {
			if w.terminal == nil || input.Sequence <= w.inputAck {
				continue
			}
			if input.Sequence != w.inputAck+1 {
				return errors.New("terminal input gap")
			}
			b, e := base64.StdEncoding.DecodeString(input.Value.Data)
			if e != nil || len(b) > 16384 {
				return errors.New("invalid terminal data")
			}
			term := w.terminal
			if len(b) > 0 {
				w.mu.Unlock()
				_, e = term.Write(b)
				w.mu.Lock()
				if e != nil {
					return e
				}
			}
			if input.Value.Columns != 0 || input.Value.Rows != 0 {
				if input.Value.Columns < 20 || input.Value.Columns > 240 || input.Value.Rows < 5 || input.Value.Rows > 100 {
					return errors.New("invalid terminal resize")
				}
				if e = term.Resize(input.Value.Columns, input.Value.Rows); e != nil {
					return e
				}
			}
			w.inputAck = input.Sequence
		}
	}
	if response.Job != nil && w.job == nil {
		job := *response.Job
		if e = validateJob(job, w.cfg); e != nil {
			return e
		}
		if w.jobsAccepted >= 10000 {
			return errors.New("worker ledger full; archive before accepting more jobs")
		}
		if e = saveJSON(filepath.Join(w.cfg.Root, "jobs", job.ID), map[string]string{"id": job.ID, "state": "accepted"}); e != nil {
			return e
		}
		jobCtx, cancel := context.WithDeadline(ctx, time.UnixMilli(int64(job.Expires*1000)))
		w.jobsAccepted++
		w.job = &job
		w.cancel = cancel
		w.lease = time.Now().Add(45 * time.Second)
		w.outputSequence = 0
		w.inputAck = 0
		go w.execute(jobCtx, job)
	}
	return nil
}
func (w *Worker) execute(ctx context.Context, job Job) {
	result := Result{State: "failed", Exit: -1, Identity: executionIdentity()}
	if job.Action == "shell.start" {
		result = w.runTerminal(ctx, job)
	} else {
		result = executeJob(ctx, job, w.cfg)
	}
	if result.State == "handoff" {
		// Remain occupied until the helper stops this worker. No success is claimed early.
		select {
		case <-ctx.Done():
		case <-time.After(90 * time.Second):
		}
		return
	}
	if ctx.Err() != nil {
		result.State = "cancelled"
		result.Error = "Job cancelled or authorization lease expired"
	}
	receipt, e := encryptResult(w.cfg, job.ID, result)
	if e == nil {
		e = saveJSON(filepath.Join(w.cfg.Root, "receipts", job.ID), receipt)
	}
	inventory := capabilities(w.cfg)
	w.mu.Lock()
	defer w.mu.Unlock()
	if e == nil {
		w.receipts[job.ID] = receipt
	}
	if e != nil {
		return
	} // Remain occupied; restarting reconciles the durable acceptance marker.
	w.inventory = inventory
	if w.cancel != nil {
		w.cancel()
	}
	w.job = nil
	w.cancel = nil
	w.terminal = nil
}
func (w *Worker) runTerminal(ctx context.Context, job Job) Result {
	result := Result{State: "failed", Exit: -1, Identity: executionIdentity()}
	term, e := openTerminal(ctx, integer(job, "columns"), integer(job, "rows"))
	if e != nil {
		result.Error = "Terminal unavailable"
		return result
	}
	w.mu.Lock()
	w.terminal = term
	w.mu.Unlock()
	defer term.Close()
	go func() { <-ctx.Done(); term.Close() }()
	buffer := make([]byte, 8192)
	for {
		n, e := term.Read(buffer)
		if n > 0 {
			w.mu.Lock()
			if len(w.frames) >= 64 {
				w.mu.Unlock()
				result.Error = "Terminal output backpressure limit reached"
				return result
			}
			w.outputSequence++
			w.frames = append(w.frames, Frame{Job: job.ID, Sequence: w.outputSequence, Data: base64.StdEncoding.EncodeToString(buffer[:n])})
			w.mu.Unlock()
		}
		if e != nil {
			break
		}
	}
	if e = term.Wait(); e == nil {
		result.State = "completed"
		result.Exit = 0
	} else {
		result.Error = "Terminal process ended with an error"
	}
	return result
}
func capabilities(c Config) map[string]any {
	return map[string]any{"version": Version, "platform": runtime.GOOS, "execution_identity": executionIdentity(), "privileged": true, "boot_id": bootID(), "features": platformCapabilities(), "capture_installed": captureInstalled(), "recovery_account": recoveryAccountStatus(c), "versions": map[string]string{"worker": Version, "agent": installedVersion("agent"), "wxlfgar": installedVersion("wxlfgar")}}
}
