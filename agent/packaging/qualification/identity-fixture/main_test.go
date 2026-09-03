package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/identity"
)

func TestCreateFixtureProducesLoadablePrivateIdentity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "identity")
	endpointID := "00000000-0000-4000-8000-000000000002"
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	if err := createFixture(directory, endpointID, now); err != nil {
		t.Fatalf("createFixture() error = %v", err)
	}
	loaded, err := identity.Load(directory, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("identity.Load() error = %v", err)
	}
	if loaded.EndpointID != endpointID {
		t.Fatalf("EndpointID = %q, want %q", loaded.EndpointID, endpointID)
	}
	info, err := os.Stat(filepath.Join(directory, "identity.json"))
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity mode = %o, want 600", got)
	}
}
