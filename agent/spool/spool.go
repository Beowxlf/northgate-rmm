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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

const (
	SchemaVersion   = 2
	MaxPayloadBytes = 65_536
	MaxEntries      = 1024
	// MaxRejectedEntries bounds exact-payload quarantine retention separately
	// from the active delivery queue. Oldest rejected records roll over first.
	MaxRejectedEntries = 128
	maxRecordBytes     = 100_000
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
	Order         uint64    `json:"order"`
	CreatedAt     time.Time `json:"created_at"`
	Payload       []byte    `json:"payload"`
	SHA256        string    `json:"sha256"`
}

type recordMetadata struct {
	ID    string
	Order uint64
	Size  int64
}

// QuarantineResult identifies rejected evidence removed by the documented
// bounded-retention rollover. Callers must emit one audit event per ID.
type QuarantineResult struct {
	EvictedIDs []string
}

// CommitUncertainError exposes the exact item ID when durable rollback cannot
// prove whether a published record may survive a crash.
type CommitUncertainError struct {
	ID    string
	Cause error
}

func (err *CommitUncertainError) Error() string {
	return fmt.Sprintf("spool commit outcome is uncertain for %s: %v", err.ID, err.Cause)
}

func (err *CommitUncertainError) Unwrap() error { return err.Cause }

// AcknowledgeUncertainError exposes the exact item ID when a removal completed
// but its directory sync failed, so recovery must reconcile whether the record
// is present after restart before transmitting it again.
type AcknowledgeUncertainError struct {
	ID    string
	Cause error
}

func (err *AcknowledgeUncertainError) Error() string {
	return fmt.Sprintf("spool acknowledgement outcome is uncertain for %s: %v", err.ID, err.Cause)
}

func (err *AcknowledgeUncertainError) Unwrap() error { return err.Cause }

// QuarantineUncertainError means an invalid or terminally rejected record was
// moved out of the delivery queue, but directory synchronization could not
// prove the move durable. Recovery must reopen and reconcile before delivery.
type QuarantineUncertainError struct {
	ID    string
	Cause error
}

func (err *QuarantineUncertainError) Error() string {
	return fmt.Sprintf("spool quarantine outcome is uncertain for %s", err.ID)
}

func (err *QuarantineUncertainError) Unwrap() error { return err.Cause }

type Queue struct {
	mu       sync.Mutex
	root     *os.Root
	rejected *os.Root
	lock     directoryLock
	sync     func(*os.Root) error
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
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open spool parent: %w", err)
	}
	defer parentRoot.Close()
	openedParentInfo, err := parentRoot.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParentInfo) {
		return nil, errors.New("spool parent changed while opening")
	}

	base := filepath.Base(directory)
	info, err := parentRoot.Lstat(base)
	if errors.Is(err, fs.ErrNotExist) {
		if err := parentRoot.Mkdir(base, 0o700); err != nil {
			return nil, fmt.Errorf("create spool directory: %w", err)
		}
		info, err = parentRoot.Lstat(base)
	} else if err != nil {
		return nil, fmt.Errorf("inspect spool directory: %w", err)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("spool directory must be a real directory")
	}
	root, err := parentRoot.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open spool root: %w", err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(info, openedInfo) {
		root.Close()
		return nil, errors.New("spool directory changed while opening")
	}
	if err := root.Chmod(".", 0o700); err != nil {
		root.Close()
		return nil, fmt.Errorf("protect spool directory: %w", err)
	}
	if err := syncDirectory(parentRoot); err != nil {
		root.Close()
		return nil, fmt.Errorf("sync spool parent: %w", err)
	}
	lock, err := acquireDirectoryLock(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	rejected, err := openRejected(root)
	if err != nil {
		lock.Close()
		root.Close()
		return nil, err
	}
	queue := &Queue{root: root, rejected: rejected, lock: lock, sync: syncDirectory, maxBytes: maxBytes}
	if err := syncDirectory(root); err != nil {
		rejected.Close()
		lock.Close()
		root.Close()
		return nil, fmt.Errorf("sync spool directory: %w", err)
	}
	if _, _, err := queue.usageLocked(); err != nil {
		rejected.Close()
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
	return errors.Join(queue.lock.Close(), queue.rejected.Close(), queue.root.Close())
}

func openRejected(root *os.Root) (*os.Root, error) {
	const name = "rejected"
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil {
			return nil, fmt.Errorf("create rejected spool directory: %w", err)
		}
		if err := syncDirectory(root); err != nil {
			return nil, fmt.Errorf("sync spool after rejected directory creation: %w", err)
		}
		info, err = root.Lstat(name)
	} else if err != nil {
		return nil, fmt.Errorf("inspect rejected spool directory: %w", err)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrCorrupt
	}
	rejected, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open rejected spool directory: %w", err)
	}
	opened, err := rejected.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		rejected.Close()
		return nil, ErrCorrupt
	}
	if err := rejected.Chmod(".", 0o700); err != nil {
		rejected.Close()
		return nil, fmt.Errorf("protect rejected spool directory: %w", err)
	}
	return rejected, nil
}

// Enqueue durably writes a new item without overwriting an existing ID. Queue
// exhaustion rejects the new item; it never silently evicts evidence.
func (queue *Queue) Enqueue(ctx context.Context, id string, payload []byte) (returnErr error) {
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

	usage, _, lastOrder, entryCount, err := queue.inventoryLocked()
	if err != nil {
		return err
	}
	if entryCount >= MaxEntries {
		return ErrQuotaExceeded
	}
	order := uint64(1)
	if lastOrder > 0 {
		if lastOrder == ^uint64(0) {
			return errors.New("spool order is exhausted")
		}
		order = lastOrder + 1
	}
	item := record{
		SchemaVersion: SchemaVersion,
		ID:            id,
		Order:         order,
		CreatedAt:     time.Now().UTC(),
		Payload:       payload,
	}
	item.SHA256 = recordDigest(item.ID, item.Order, item.Payload)
	raw, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode spool item: %w", err)
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
			cleanupErr := queue.root.Remove(temporary)
			if cleanupErr == nil {
				cleanupErr = syncDirectory(queue.root)
			}
			if cleanupErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("clean temporary spool item: %w", cleanupErr))
			}
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
		removeTemporary = false
		return queue.rollbackPublished(id, filename, temporary, fmt.Errorf("remove temporary spool item: %w", err))
	}
	removeTemporary = false
	if err := syncDirectory(queue.root); err != nil {
		return queue.rollbackPublished(id, filename, "", fmt.Errorf("sync spool directory: %w", err))
	}
	return nil
}

func (queue *Queue) rollbackPublished(id, filename, temporary string, cause error) error {
	removeFinalErr := queue.root.Remove(filename)
	if errors.Is(removeFinalErr, fs.ErrNotExist) {
		removeFinalErr = nil
	}
	var removeTemporaryErr error
	if temporary != "" {
		removeTemporaryErr = queue.root.Remove(temporary)
		if errors.Is(removeTemporaryErr, fs.ErrNotExist) {
			removeTemporaryErr = nil
		}
	}
	syncErr := syncDirectory(queue.root)
	if removeFinalErr == nil && removeTemporaryErr == nil && syncErr == nil {
		return cause
	}
	return &CommitUncertainError{
		ID:    id,
		Cause: errors.Join(cause, removeFinalErr, removeTemporaryErr, syncErr),
	}
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

// ListIDs returns a deterministic, bounded snapshot of every validated queue
// record so a restarted agent can resume delivery without retaining process
// memory. Payloads are not returned by enumeration.
func (queue *Queue) ListIDs(ctx context.Context) ([]string, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.ready(ctx); err != nil {
		return nil, err
	}
	_, records, _, _, err := queue.inventoryLocked()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(records))
	for index, item := range records {
		ids[index] = item.ID
	}
	return ids, nil
}

func (queue *Queue) readRecordLocked(id string) ([]byte, error) {
	item, err := queue.readRecordItemLocked(id)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), item.Payload...), nil
}

func (queue *Queue) readRecordItemLocked(id string) (record, error) {
	return readRecordItem(queue.root, id)
}

func readRecordItem(root *os.Root, id string) (record, error) {
	file, err := root.Open(id + ".json")
	if err != nil {
		return record{}, fmt.Errorf("open spool item: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return record{}, fmt.Errorf("read spool item: %w", err)
	}
	if len(raw) > maxRecordBytes {
		return record{}, ErrCorrupt
	}
	item, err := decodeRecord(raw)
	if err != nil || item.ID != id || len(item.Payload) == 0 || len(item.Payload) > MaxPayloadBytes {
		return record{}, ErrCorrupt
	}
	if item.SHA256 != recordDigest(item.ID, item.Order, item.Payload) {
		return record{}, ErrCorrupt
	}
	return item, nil
}

func recordDigest(id string, order uint64, payload []byte) string {
	hash := sha256.New()
	hash.Write([]byte("northgate-rmm-spool-v2\x00"))
	hash.Write([]byte(id))
	var orderBytes [8]byte
	for index := len(orderBytes) - 1; index >= 0; index-- {
		orderBytes[index] = byte(order)
		order >>= 8
	}
	hash.Write(orderBytes[:])
	hash.Write(payload)
	return hex.EncodeToString(hash.Sum(nil))
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
	if err := queue.sync(queue.root); err != nil {
		return &AcknowledgeUncertainError{
			ID:    id,
			Cause: fmt.Errorf("sync spool directory after acknowledgement: %w", err),
		}
	}
	return nil
}

// Quarantine moves one validated record out of delivery order and retains its
// exact bytes. Rejected evidence has a separate quota equal to the active byte
// quota and MaxRejectedEntries; the oldest records are durably rolled over
// before the new rejection is admitted so rejected evidence cannot poison the
// active queue forever.
func (queue *Queue) Quarantine(ctx context.Context, id string) (QuarantineResult, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if err := queue.ready(ctx); err != nil {
		return QuarantineResult{}, err
	}
	if !uuidPattern.MatchString(id) {
		return QuarantineResult{}, errors.New("spool ID must be a canonical lowercase UUID")
	}
	if _, err := queue.readRecordItemLocked(id); err != nil {
		return QuarantineResult{}, err
	}
	filename := id + ".json"
	if _, err := queue.rejected.Stat(filename); err == nil {
		return QuarantineResult{}, ErrDuplicate
	} else if !errors.Is(err, fs.ErrNotExist) {
		return QuarantineResult{}, fmt.Errorf("inspect rejected spool item: %w", err)
	}
	info, err := queue.root.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxRecordBytes {
		return QuarantineResult{}, ErrCorrupt
	}
	result, err := queue.makeRejectedRoomLocked(info.Size())
	if err != nil {
		return result, err
	}
	if err := queue.root.Rename(filename, "rejected/"+filename); err != nil {
		return result, fmt.Errorf("quarantine spool item: %w", err)
	}
	if err := queue.sync(queue.rejected); err != nil {
		return result, &QuarantineUncertainError{ID: id, Cause: err}
	}
	if err := queue.sync(queue.root); err != nil {
		return result, &QuarantineUncertainError{ID: id, Cause: err}
	}
	return result, nil
}

func (queue *Queue) makeRejectedRoomLocked(incomingBytes int64) (QuarantineResult, error) {
	total, records, _, _, err := queue.rejectedUsageLocked()
	if err != nil {
		return QuarantineResult{}, err
	}
	if incomingBytes > queue.maxBytes {
		return QuarantineResult{}, ErrQuotaExceeded
	}
	sort.Slice(records, func(left, right int) bool { return records[left].Order < records[right].Order })
	result := QuarantineResult{}
	for len(records) >= MaxRejectedEntries || total > queue.maxBytes-incomingBytes {
		oldest := records[0]
		if err := queue.rejected.Remove(oldest.ID + ".json"); err != nil {
			return result, &QuarantineUncertainError{ID: oldest.ID, Cause: err}
		}
		result.EvictedIDs = append(result.EvictedIDs, oldest.ID)
		total -= oldest.Size
		records = records[1:]
	}
	if len(result.EvictedIDs) > 0 {
		if err := queue.sync(queue.rejected); err != nil {
			return result, &QuarantineUncertainError{ID: result.EvictedIDs[len(result.EvictedIDs)-1], Cause: err}
		}
	}
	return result, nil
}

func (queue *Queue) ready(ctx context.Context) error {
	if queue.closed {
		return ErrClosed
	}
	return ctx.Err()
}

func (queue *Queue) usageLocked() (int64, int, error) {
	total, _, _, entryCount, err := queue.inventoryLocked()
	return total, entryCount, err
}

func (queue *Queue) inventoryLocked() (int64, []recordMetadata, uint64, int, error) {
	directory, err := queue.root.Open(".")
	if err != nil {
		return 0, nil, 0, 0, fmt.Errorf("list spool: %w", err)
	}
	defer directory.Close()
	entries := make([]fs.DirEntry, 0, MaxEntries+3)
	for len(entries) <= MaxEntries+2 {
		batch, readErr := directory.ReadDir(MaxEntries + 3 - len(entries))
		entries = append(entries, batch...)
		if len(entries) > MaxEntries+2 {
			return 0, nil, 0, 0, ErrQuotaExceeded
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, nil, 0, 0, fmt.Errorf("list spool: %w", readErr)
		}
		if len(batch) == 0 {
			return 0, nil, 0, 0, errors.New("list spool made no progress")
		}
	}
	dataEntries := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" {
			info, err := queue.root.Lstat(name)
			if err != nil || !info.Mode().IsRegular() {
				return 0, nil, 0, 0, ErrCorrupt
			}
			continue
		}
		if name == "rejected" {
			info, err := queue.root.Lstat(name)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return 0, nil, 0, 0, ErrCorrupt
			}
			continue
		}
		dataEntries = append(dataEntries, name)
	}
	_, _, rejectedOrders, rejectedMaxOrder, err := queue.rejectedUsageLocked()
	if err != nil {
		return 0, nil, 0, 0, err
	}
	if len(dataEntries) > MaxEntries {
		return 0, nil, 0, 0, ErrQuotaExceeded
	}
	var total int64
	records := make([]recordMetadata, 0, len(dataEntries))
	for _, name := range dataEntries {
		if !strings.HasSuffix(name, ".json") || !uuidPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			return 0, nil, 0, 0, ErrCorrupt
		}
		info, err := queue.root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || !privateRecord(info) ||
			info.Size() < 1 || info.Size() > maxRecordBytes {
			return 0, nil, 0, 0, ErrCorrupt
		}
		if total > queue.maxBytes-info.Size() {
			return 0, nil, 0, 0, ErrQuotaExceeded
		}
		id := strings.TrimSuffix(name, ".json")
		item, err := queue.readRecordItemLocked(id)
		if err != nil {
			return 0, nil, 0, 0, ErrCorrupt
		}
		if _, exists := rejectedOrders[item.Order]; exists {
			return 0, nil, 0, 0, ErrCorrupt
		}
		total += info.Size()
		records = append(records, recordMetadata{ID: id, Order: item.Order, Size: info.Size()})
	}
	sort.Slice(records, func(left, right int) bool {
		return records[left].Order < records[right].Order
	})
	for index := 1; index < len(records); index++ {
		if records[index-1].Order == records[index].Order {
			return 0, nil, 0, 0, ErrCorrupt
		}
	}
	lastOrder := rejectedMaxOrder
	if len(records) > 0 && records[len(records)-1].Order > lastOrder {
		lastOrder = records[len(records)-1].Order
	}
	return total, records, lastOrder, len(dataEntries), nil
}

func (queue *Queue) rejectedUsageLocked() (int64, []recordMetadata, map[uint64]struct{}, uint64, error) {
	directory, err := queue.rejected.Open(".")
	if err != nil {
		return 0, nil, nil, 0, ErrCorrupt
	}
	defer directory.Close()
	entries, err := directory.ReadDir(MaxRejectedEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, nil, nil, 0, ErrCorrupt
	}
	if len(entries) > MaxRejectedEntries {
		return 0, nil, nil, 0, ErrQuotaExceeded
	}
	var total int64
	records := make([]recordMetadata, 0, len(entries))
	orders := make(map[uint64]struct{}, len(entries))
	var maxOrder uint64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || !uuidPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			return 0, nil, nil, 0, ErrCorrupt
		}
		info, err := queue.rejected.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || !privateRecord(info) ||
			info.Size() < 1 || info.Size() > maxRecordBytes {
			return 0, nil, nil, 0, ErrCorrupt
		}
		id := strings.TrimSuffix(name, ".json")
		item, err := readRecordItem(queue.rejected, id)
		if err != nil {
			return 0, nil, nil, 0, ErrCorrupt
		}
		if _, exists := orders[item.Order]; exists {
			return 0, nil, nil, 0, ErrCorrupt
		}
		orders[item.Order] = struct{}{}
		if item.Order > maxOrder {
			maxOrder = item.Order
		}
		if total > queue.maxBytes-info.Size() {
			return 0, nil, nil, 0, ErrQuotaExceeded
		}
		total += info.Size()
		records = append(records, recordMetadata{ID: id, Order: item.Order, Size: info.Size()})
	}
	return total, records, orders, maxOrder, nil
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
	if item.SchemaVersion != SchemaVersion || item.Order == 0 || item.CreatedAt.IsZero() {
		return record{}, ErrCorrupt
	}
	return item, nil
}
