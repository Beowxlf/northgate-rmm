//go:build windows

package management

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestToolWindowsResourceBoundaryExecutesAndReturnsOutput(t *testing.T) {
	c := configForTest(t)
	root := filepath.Join(toolsRoot(c), "osquery")
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "osqueryi.exe"), data, 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := runBudgetedTool(ctx, jobForTest("tool.run", map[string]any{"profile": "system"}), c, ToolManifest{ID: "osquery", Entrypoint: "osqueryi.exe", Budget: ToolBudget{10, 128, 25, 16, 32}}, nil)
	if result.State != "completed" || result.Exit != 0 || strings.TrimSpace(result.Output) == "" {
		t.Fatalf("bounded tool failed: %+v", result)
	}
}
