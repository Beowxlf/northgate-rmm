package sequence

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

const (
	testBootID  = "123e4567-e89b-42d3-a456-426614174000"
	otherBootID = "123e4567-e89b-42d3-a456-426614174001"
)

func TestStoreReservesAcrossRestartAndResetsForNewBoot(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	store, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for want := int64(1); want <= 2; want++ {
		got, err := store.Reserve(context.Background(), testBootID)
		if err != nil || got != want {
			t.Fatalf("Reserve() = %d, %v; want %d", got, err, want)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	store, err = Open(directory)
	if err != nil {
		t.Fatalf("restart Open() error = %v", err)
	}
	defer store.Close()
	if got, err := store.Reserve(context.Background(), testBootID); err != nil || got != 3 {
		t.Fatalf("post-restart Reserve() = %d, %v; want 3", got, err)
	}
	if got, err := store.Reserve(context.Background(), otherBootID); err != nil || got != 1 {
		t.Fatalf("new-boot Reserve() = %d, %v; want 1", got, err)
	}
}

func TestStoreSerializesConcurrentReservations(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "sequence"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	const count = 16
	values := make([]int, count)
	errorsSeen := make(chan error, count)
	var group sync.WaitGroup
	for index := range values {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			value, reserveErr := store.Reserve(context.Background(), testBootID)
			values[index] = int(value)
			errorsSeen <- reserveErr
		}(index)
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("Reserve() error = %v", err)
		}
	}
	sort.Ints(values)
	for index, value := range values {
		if value != index+1 {
			t.Fatalf("reservations = %v", values)
		}
	}
}

func TestReserveAndUseConsumesSequenceWhenPublicationFails(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "sequence"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	publicationFailure := errors.New("synthetic publication failure")
	value, err := store.ReserveAndUse(
		context.Background(),
		testBootID,
		func(sequence int64) error {
			if sequence != 1 {
				t.Fatalf("callback sequence = %d, want 1", sequence)
			}
			return publicationFailure
		},
	)
	if value != 1 || !errors.Is(err, publicationFailure) {
		t.Fatalf("ReserveAndUse() = %d, %v", value, err)
	}
	if value, err := store.Reserve(context.Background(), testBootID); err != nil || value != 2 {
		t.Fatalf("Reserve() after callback failure = %d, %v; want 2", value, err)
	}
	if _, err := store.ReserveAndUse(context.Background(), testBootID, nil); err == nil {
		t.Fatal("ReserveAndUse() accepted a nil callback")
	}
}

func TestReserveAndUseHoldsOrderingBoundaryThroughCallback(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "sequence"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	firstUsing := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondUsing := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		_, err := store.ReserveAndUse(context.Background(), testBootID, func(int64) error {
			close(firstUsing)
			<-releaseFirst
			return nil
		})
		results <- err
	}()
	select {
	case <-firstUsing:
	case <-time.After(time.Second):
		t.Fatal("first callback did not start")
	}
	go func() {
		_, err := store.ReserveAndUse(context.Background(), testBootID, func(int64) error {
			close(secondUsing)
			return nil
		})
		results <- err
	}()
	select {
	case <-secondUsing:
		t.Fatal("second callback started before first callback completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirst)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("ReserveAndUse() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("ReserveAndUse() calls did not finish")
		}
	}
}

func TestOpenRejectsSecondHandleAndUnknownState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	first, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open() error = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, temporaryName), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() with temporary state error = %v, want ErrCorrupt", err)
	}
}

func TestStoreRejectsCorruptState(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "sequence")
	store, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := store.Reserve(context.Background(), testBootID); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, stateName))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var state wireState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	state.LastSequence++
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, stateName), raw, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open() error = %v, want ErrCorrupt", err)
	}
}

func TestReserveReportsUncertainDirectorySync(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "sequence"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	syncFailure := errors.New("injected directory sync failure")
	store.sync = func(*os.Root) error { return syncFailure }
	value, err := store.Reserve(context.Background(), testBootID)
	var uncertain *ReserveUncertainError
	if value != 0 || !errors.As(err, &uncertain) || !errors.Is(err, syncFailure) {
		t.Fatalf("Reserve() = %d, %v; want zero and ReserveUncertainError", value, err)
	}
	if uncertain.BootID != testBootID || uncertain.Sequence != 1 {
		t.Fatalf("uncertainty = %#v", uncertain)
	}
	store.sync = syncDirectory
	if value, err := store.Reserve(context.Background(), testBootID); err != nil || value != 2 {
		t.Fatalf("Reserve() after uncertainty = %d, %v; want 2", value, err)
	}
}

func TestStoreRejectsInvalidInputAndClosedUse(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "sequence"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := store.Reserve(context.Background(), "invalid"); err == nil {
		t.Fatal("Reserve() accepted invalid boot ID")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Reserve(ctx, testBootID); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reserve() error = %v, want context.Canceled", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := store.Reserve(context.Background(), testBootID); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Reserve() error = %v, want ErrClosed", err)
	}
}

func TestOpenRejectsUnsafePaths(t *testing.T) {
	if _, err := Open("relative"); err == nil {
		t.Fatal("Open() accepted relative path")
	}
	root := filepath.Clean(filepath.VolumeName(t.TempDir()) + string(os.PathSeparator))
	if _, err := Open(root); err == nil {
		t.Fatal("Open() accepted filesystem root")
	}
	parent := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(parent, "sequence")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("Open() accepted symlink directory")
	}
}

func FuzzDecodeState(f *testing.F) {
	state := wireState{SchemaVersion: SchemaVersion, BootID: testBootID, LastSequence: 1}
	state.SHA256 = stateDigest(state.BootID, state.LastSequence)
	raw, err := json.Marshal(state)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"schema_version":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = decodeState(raw)
	})
}
