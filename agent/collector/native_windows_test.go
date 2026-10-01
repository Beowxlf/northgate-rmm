//go:build windows

package collector

import (
	"context"
	"testing"
)

func TestWindowsNativeInventory(t *testing.T) {
	source := NativeSource{}
	runner, err := NewRunner("0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), source)
	if err != nil || !result.Complete || result.Platform != "windows" || result.Fields["os.id"] != "windows" {
		t.Fatalf("incomplete Windows collection: %+v %v", result.Issues, err)
	}
	second, err := source.BootID(context.Background())
	if err != nil || second != result.Fields["boot.id"] {
		t.Fatal("boot identity changed within one boot")
	}
}
