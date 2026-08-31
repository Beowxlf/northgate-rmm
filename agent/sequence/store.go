// Package sequence reserves crash-durable, monotonically increasing message
// sequence numbers for the current Linux kernel boot identity. It does not
// claim to resist VM snapshot or filesystem rollback; that requires the
// independently anchored design at the later update-status gate.
package sequence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

const (
	SchemaVersion = 1
	stateName     = "state.json"
	temporaryName = "state.tmp"
	maxStateBytes = 512
)

var (
	ErrClosed   = errors.New("sequence store is closed")
	ErrCorrupt  = errors.New("sequence store is corrupt")
	ErrLocked   = errors.New("sequence store is already open")
	uuidPattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
)

type wireState struct {
	SchemaVersion int    `json:"schema_version"`
	BootID        string `json:"boot_id"`
	LastSequence  int64  `json:"last_sequence"`
	SHA256        string `json:"sha256"`
}

// ReserveUncertainError means the new state became visible but its directory
// sync failed. Callers must not emit the returned sequence; recovery reopens
// the store and reserves another number, safely allowing a gap.
type ReserveUncertainError struct {
	BootID   string
	Sequence int64
	Cause    error
}

func (err *ReserveUncertainError) Error() string {
	return fmt.Sprintf("sequence reservation outcome is uncertain for boot %s at %d", err.BootID, err.Sequence)
}

func (err *ReserveUncertainError) Unwrap() error { return err.Cause }

type Store struct {
	mu     sync.Mutex
	root   *os.Root
	lock   directoryLock
	sync   func(*os.Root) error
	closed bool
}

// Open creates or validates one private sequence-state directory and holds a
// process-lifetime exclusive lock so competing agent instances cannot reserve
// the same number.
func Open(directory string) (*Store, error) {
	clean := filepath.Clean(directory)
	volumeRoot := filepath.Clean(filepath.VolumeName(clean) + string(os.PathSeparator))
	if directory == "" || !filepath.IsAbs(directory) || clean != directory || clean == volumeRoot {
		return nil, errors.New("sequence directory must be a non-root absolute clean path")
	}
	parentPath := filepath.Dir(directory)
	if !protectedParentPath(parentPath) {
		return nil, errors.New("sequence parent chain permits directory replacement")
	}
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("sequence parent must be an existing real directory")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, fmt.Errorf("open sequence parent: %w", err)
	}
	defer parent.Close()
	openedParent, err := parent.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		return nil, errors.New("sequence parent changed while opening")
	}

	base := filepath.Base(directory)
	created := false
	info, err := parent.Lstat(base)
	if errors.Is(err, fs.ErrNotExist) {
		if err := parent.Mkdir(base, 0o700); err != nil {
			return nil, fmt.Errorf("create sequence directory: %w", err)
		}
		created = true
		if err := syncDirectory(parent); err != nil {
			return nil, fmt.Errorf("sync sequence parent: %w", err)
		}
		info, err = parent.Lstat(base)
	} else if err != nil {
		return nil, fmt.Errorf("inspect sequence directory: %w", err)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("sequence directory must be a real directory")
	}
	root, err := parent.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open sequence root: %w", err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(info, openedInfo) {
		root.Close()
		return nil, errors.New("sequence directory changed while opening")
	}
	if created {
		if err := root.Chmod(".", 0o700); err != nil {
			root.Close()
			return nil, fmt.Errorf("protect sequence directory: %w", err)
		}
	}
	openedInfo, err = root.Stat(".")
	if err != nil || !privateDirectory(openedInfo) {
		root.Close()
		return nil, errors.New("sequence directory permissions are not private")
	}
	lock, err := acquireDirectoryLock(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	store := &Store{root: root, lock: lock, sync: syncDirectory}
	if err := syncDirectory(root); err != nil {
		lock.Close()
		root.Close()
		return nil, fmt.Errorf("sync sequence directory: %w", err)
	}
	if _, exists, err := store.readLocked(); err != nil {
		lock.Close()
		root.Close()
		return nil, err
	} else if !exists {
		return store, nil
	}
	return store, nil
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	return errors.Join(store.lock.Close(), store.root.Close())
}

// Reserve persists the next sequence before returning it. A new kernel boot
// identity begins at one; the current boot continues from its durable floor.
func (store *Store) Reserve(ctx context.Context, bootID string) (int64, error) {
	return store.ReserveAndUse(ctx, bootID, func(int64) error { return nil })
}

// ReserveAndUse holds the store's cross-consumer ordering boundary while use
// publishes the work associated with the reserved sequence. The callback must
// not re-enter this store. Its failure consumes the sequence and is returned to
// the caller, making gaps safe while preventing publication order inversion.
func (store *Store) ReserveAndUse(
	ctx context.Context,
	bootID string,
	use func(int64) error,
) (int64, error) {
	if use == nil {
		return 0, errors.New("sequence use callback is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	reserved, err := store.reserveLocked(ctx, bootID)
	if err != nil {
		return 0, err
	}
	if err := use(reserved); err != nil {
		return reserved, err
	}
	return reserved, nil
}

func (store *Store) reserveLocked(ctx context.Context, bootID string) (reserved int64, returnErr error) {
	if store.closed {
		return 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !uuidPattern.MatchString(bootID) {
		return 0, errors.New("boot ID must be a canonical lowercase UUID")
	}
	current, exists, err := store.readLocked()
	if err != nil {
		return 0, err
	}
	next := int64(1)
	if exists && current.BootID == bootID {
		if current.LastSequence == math.MaxInt64 {
			return 0, errors.New("sequence space is exhausted for the current boot")
		}
		next = current.LastSequence + 1
	}
	state := wireState{SchemaVersion: SchemaVersion, BootID: bootID, LastSequence: next}
	state.SHA256 = stateDigest(state.BootID, state.LastSequence)
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > maxStateBytes {
		return 0, errors.New("encode sequence state")
	}

	file, err := store.root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return 0, ErrCorrupt
		}
		return 0, fmt.Errorf("create sequence staging file: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			cleanupErr := store.root.Remove(temporaryName)
			if errors.Is(cleanupErr, fs.ErrNotExist) {
				cleanupErr = nil
			}
			if cleanupErr == nil {
				cleanupErr = store.sync(store.root)
			}
			if cleanupErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("clean sequence staging file: %w", cleanupErr))
			}
		}
	}()
	if written, err := file.Write(raw); err != nil || written != len(raw) {
		_ = file.Close()
		if err == nil {
			err = io.ErrShortWrite
		}
		return 0, fmt.Errorf("write sequence staging file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return 0, fmt.Errorf("sync sequence staging file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return 0, fmt.Errorf("protect sequence staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		return 0, fmt.Errorf("close sequence staging file: %w", err)
	}
	if err := store.root.Rename(temporaryName, stateName); err != nil {
		return 0, fmt.Errorf("publish sequence state: %w", err)
	}
	removeTemporary = false
	if err := store.sync(store.root); err != nil {
		return 0, &ReserveUncertainError{BootID: bootID, Sequence: next, Cause: err}
	}
	return next, nil
}

func (store *Store) readLocked() (wireState, bool, error) {
	directory, err := store.root.Open(".")
	if err != nil {
		return wireState{}, false, fmt.Errorf("list sequence directory: %w", err)
	}
	entries, readErr := directory.ReadDir(3)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return wireState{}, false, fmt.Errorf("list sequence directory: %w", readErr)
	}
	if closeErr != nil || len(entries) > 2 {
		return wireState{}, false, ErrCorrupt
	}
	found := false
	for _, entry := range entries {
		switch entry.Name() {
		case ".lock":
			info, err := store.root.Lstat(entry.Name())
			if err != nil || !info.Mode().IsRegular() || !privateFile(info) || info.Size() != 0 {
				return wireState{}, false, ErrCorrupt
			}
		case stateName:
			found = true
		default:
			return wireState{}, false, ErrCorrupt
		}
	}
	if !found {
		return wireState{}, false, nil
	}
	info, err := store.root.Lstat(stateName)
	if err != nil || !info.Mode().IsRegular() || !privateFile(info) || info.Size() < 1 || info.Size() > maxStateBytes {
		return wireState{}, false, ErrCorrupt
	}
	file, err := store.root.Open(stateName)
	if err != nil {
		return wireState{}, false, fmt.Errorf("open sequence state: %w", err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		file.Close()
		return wireState{}, false, ErrCorrupt
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	closeErr = file.Close()
	if readErr != nil || closeErr != nil || len(raw) > maxStateBytes {
		return wireState{}, false, ErrCorrupt
	}
	state, err := decodeState(raw)
	if err != nil {
		return wireState{}, false, ErrCorrupt
	}
	return state, true, nil
}

func decodeState(raw []byte) (wireState, error) {
	if err := strictjson.Validate(raw); err != nil {
		return wireState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state wireState
	if err := decoder.Decode(&state); err != nil {
		return wireState{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return wireState{}, errors.New("sequence state contains trailing data")
	}
	if state.SchemaVersion != SchemaVersion || !uuidPattern.MatchString(state.BootID) ||
		state.LastSequence < 1 || state.SHA256 != stateDigest(state.BootID, state.LastSequence) {
		return wireState{}, ErrCorrupt
	}
	return state, nil
}

func stateDigest(bootID string, sequence int64) string {
	hash := sha256.New()
	hash.Write([]byte("northgate-rmm-sequence-v1\x00"))
	hash.Write([]byte(bootID))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(sequence))
	hash.Write(encoded[:])
	return hex.EncodeToString(hash.Sum(nil))
}
