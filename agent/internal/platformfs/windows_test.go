//go:build windows

package platformfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSpoolLinksRequireExactlyTheKnownRecoveryPair(t *testing.T) {
	root := t.TempDir()
	if err := Protect(root); err != nil {
		t.Fatal(err)
	}
	rejected := filepath.Join(root, "rejected")
	if err := os.Mkdir(rejected, 0700); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, "record.json")
	if err := os.WriteFile(active, []byte("record"), 0600); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "alias.json")
	if err := os.Link(active, external); err != nil {
		t.Fatal(err)
	}
	if ValidateSpoolRecord(active) == nil {
		t.Fatal("outside alias accepted")
	}
	if err := os.Remove(external); err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(rejected, "record.json")
	if err := os.Link(active, peer); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSpoolRecord(peer); err != nil {
		t.Fatalf("recovery pair rejected: %v", err)
	}
	if err := os.Link(active, external); err != nil {
		t.Fatal(err)
	}
	if ValidateSpoolRecord(peer) == nil {
		t.Fatal("third alias accepted")
	}
}
