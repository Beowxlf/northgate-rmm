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

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

const (
	SchemaVersion   = 1
	MaxPayloadBytes = 65_536
	MaxEntries      = 1024
	maxRecordBytes  = 100_000
)

var (
	ErrClosed        = errors.New("spool is closed")
	ErrCorrupt       = errors.New("spool integrity check failed")
	ErrDuplicate     = errors.New("spool item already exists")
	ErrLocked        = errors.New("spool is already open")
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
	lock     directoryLock
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
	parent := filepath.Dir(directory)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("spool parent must be an existing real directory")
	}
	if _, err := os.Lstat(directory); errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create spool directory: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("inspect spool directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("spool directory must be a real directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect spool directory: %w", err)
	}
	if err := syncPathDirectory(parent); err != nil {
		return nil, fmt.Errorf("sync spool parent: %w", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open spool root: %w", err)
	}
	lock, err := acquireDirectoryLock(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	queue := &Queue{root: root, lock: lock, maxBytes: maxBytes}
	if err := syncDirectory(root); err != nil {
		lock.Close()
		root.Close()
		return nil, fmt.Errorf("sync spool directory: %w", err)
	}
	if _, _, err := queue.usageLocked(); err != nil {
		lock.Close()
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
	return errors.Join(queue.lock.Close(), queue.root.Close())
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
	usage, count, err := queue.usageLocked()
	if err != nil {
		return err
	}
	if count >= MaxEntries {
		return ErrQuotaExceeded
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
	if err := syncDirectory(queue.root); err != nil {
		return fmt.Errorf("sync spool directory: %w", err)
	}
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
	return queue.readRecordLocked(id)
}

func (queue *Queue) readRecordLocked(id string) ([]byte, error) {
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
	if err := syncDirectory(queue.root); err != nil {
		return fmt.Errorf("sync spool directory: %w", err)
	}
	return nil
}

func (queue *Queue) ready(ctx context.Context) error {
	if queue.closed {
		return ErrClosed
	}
	return ctx.Err()
}

func (queue *Queue) usageLocked() (int64, int, error) {
	entries, err := fs.ReadDir(queue.root.FS(), ".")
	if err != nil {
		return 0, 0, fmt.Errorf("list spool: %w", err)
	}
	dataEntries := make([]fs.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return 0, 0, ErrCorrupt
			}
			continue
		}
		dataEntries = append(dataEntries, entry)
	}
	if len(dataEntries) > MaxEntries {
		return 0, 0, ErrQuotaExceeded
	}
	var total int64
	for _, entry := range dataEntries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || !uuidPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			return 0, 0, ErrCorrupt
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || !privateRecord(info) ||
			info.Size() < 1 || info.Size() > maxRecordBytes {
			return 0, 0, ErrCorrupt
		}
		if total > queue.maxBytes-info.Size() {
			return 0, 0, ErrQuotaExceeded
		}
		id := strings.TrimSuffix(name, ".json")
		if _, err := queue.readRecordLocked(id); err != nil {
			return 0, 0, ErrCorrupt
		}
		total += info.Size()
	}
	return total, len(dataEntries), nil
}

func decodeRecord(raw []byte) (record, error) {
	if err := strictjson.Validate(raw); err != nil {
		return record{}, err
	}
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
