// Package spool provides a quota-bounded local queue with corruption-detecting
// checksums. It intentionally contains no encryption or keyed-integrity design;
// deployment remains prohibited until G2 data protection is approved.
package spool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion   = 1
	MaxPayloadBytes = 65_536
	maxRecordBytes  = 100_000
)

var (
	ErrClosed        = errors.New("spool is closed")
	ErrCorrupt       = errors.New("spool integrity check failed")
	ErrDuplicate     = errors.New("spool item already exists")
	ErrQuotaExceeded = errors.New("spool quota exceeded")
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type record struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	Payload       []byte    `json:"payload"`
	SHA256        string    `json:"sha256"`
}

type Queue struct {
	mu       sync.Mutex
	root     *os.Root
	maxBytes int64
	closed   bool
}

// Open creates or validates a private queue directory and rejects unknown,
// temporary, non-regular, or malformed entries.
func Open(directory string, maxBytes int64) (*Queue, error) {
	if maxBytes < maxRecordBytes {
		return nil, errors.New("spool quota is too small")
	}
	clean := filepath.Clean(directory)
	volumeRoot := filepath.Clean(filepath.VolumeName(clean) + string(os.PathSeparator))
	if directory == "" || !filepath.IsAbs(directory) || clean != directory || clean == volumeRoot {
		return nil, errors.New("spool directory must be a non-root absolute clean path")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create spool directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("spool directory must be a real directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect spool directory: %w", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open spool root: %w", err)
	}
	queue := &Queue{root: root, maxBytes: maxBytes}
	if _, err := queue.usageLocked(); err != nil {
		root.Close()
		return nil, err
	}
	return queue, nil
}

func (queue *Queue) Close() error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.closed {
		return nil
	}
	queue.closed = true
	return queue.root.Close()
}

// Enqueue durably writes a new item without overwriting an existing ID. Queue
// exhaustion rejects the new item; it never silently evicts evidence.
func (queue *Queue) Enqueue(ctx context.Context, id string, payload []byte) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.ready(ctx); err != nil {
		return err
	}
	if !uuidPattern.MatchString(id) {
		return errors.New("spool ID must be a canonical lowercase UUID")
	}
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return errors.New("spool payload is empty or exceeds size limit")
	}
	filename := id + ".json"
	if _, err := queue.root.Stat(filename); err == nil {
		return ErrDuplicate
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect spool item: %w", err)
	}

	digest := sha256.Sum256(payload)
	item := record{
		SchemaVersion: SchemaVersion,
		ID:            id,
		CreatedAt:     time.Now().UTC(),
		Payload:       payload,
		SHA256:        hex.EncodeToString(digest[:]),
	}
	raw, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode spool item: %w", err)
	}
	usage, err := queue.usageLocked()
	if err != nil {
		return err
	}
	if int64(len(raw)) > queue.maxBytes-usage {
		return ErrQuotaExceeded
	}

	temporary := id + ".tmp"
	file, err := queue.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary spool item: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = queue.root.Remove(temporary)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return fmt.Errorf("write spool item: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync spool item: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close spool item: %w", err)
	}
	// A hard link provides no-replace publication: concurrent writers cannot
	// replace an existing final item.
	if err := queue.root.Link(temporary, filename); err != nil {
		if _, statErr := queue.root.Stat(filename); statErr == nil {
			return ErrDuplicate
		}
		return fmt.Errorf("publish spool item: %w", err)
	}
	if err := queue.root.Remove(temporary); err != nil {
		return fmt.Errorf("remove temporary spool item: %w", err)
	}
	removeTemporary = false
	return nil
}

// Read validates the record schema, file binding, payload bound, and digest
// before returning a copy of the payload.
func (queue *Queue) Read(ctx context.Context, id string) ([]byte, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.ready(ctx); err != nil {
		return nil, err
	}
	if !uuidPattern.MatchString(id) {
		return nil, errors.New("spool ID must be a canonical lowercase UUID")
	}
	file, err := queue.root.Open(id + ".json")
	if err != nil {
		return nil, fmt.Errorf("open spool item: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read spool item: %w", err)
	}
	if len(raw) > maxRecordBytes {
		return nil, ErrCorrupt
	}
	item, err := decodeRecord(raw)
	if err != nil || item.ID != id || len(item.Payload) == 0 || len(item.Payload) > MaxPayloadBytes {
		return nil, ErrCorrupt
	}
	digest := sha256.Sum256(item.Payload)
	if item.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrCorrupt
	}
	return append([]byte(nil), item.Payload...), nil
}

// Acknowledge removes exactly one previously accepted item.
func (queue *Queue) Acknowledge(ctx context.Context, id string) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.ready(ctx); err != nil {
		return err
	}
	if !uuidPattern.MatchString(id) {
		return errors.New("spool ID must be a canonical lowercase UUID")
	}
	if err := queue.root.Remove(id + ".json"); err != nil {
		return fmt.Errorf("remove spool item: %w", err)
	}
	return nil
}

func (queue *Queue) ready(ctx context.Context) error {
	if queue.closed {
		return ErrClosed
	}
	return ctx.Err()
}

func (queue *Queue) usageLocked() (int64, error) {
	entries, err := fs.ReadDir(queue.root.FS(), ".")
	if err != nil {
		return 0, fmt.Errorf("list spool: %w", err)
	}
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || !uuidPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			return 0, ErrCorrupt
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxRecordBytes {
			return 0, ErrCorrupt
		}
		if total > queue.maxBytes-info.Size() {
			return 0, ErrQuotaExceeded
		}
		total += info.Size()
	}
	return total, nil
}

func decodeRecord(raw []byte) (record, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var item record
	if err := decoder.Decode(&item); err != nil {
		return record{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return record{}, errors.New("spool record contains trailing data")
	}
	if item.SchemaVersion != SchemaVersion || item.CreatedAt.IsZero() {
		return record{}, ErrCorrupt
	}
	return item, nil
}
