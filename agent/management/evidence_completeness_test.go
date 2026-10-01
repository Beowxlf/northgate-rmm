package management

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEvidenceReportsFailedAndTruncatedCollectors(t *testing.T) {
	for _, bad := range []Result{
		{State: "failed", Exit: 1, Error: "synthetic collector failure"},
		{State: "cancelled", Exit: -1},
		{State: "completed", Exit: 0, Truncated: true},
		{State: "completed", Exit: 3},
		{State: "completed", Exit: 0, Error: "inconsistent success"},
	} {
		t.Run(bad.State+bad.Error, func(t *testing.T) {
			c := configForTest(t)
			j := jobForTest("tool.run", map[string]any{"tool_id": "evidence", "profile": "it", "case_id": ""})
			result := evidenceToolWithCollector(context.Background(), j, c, func(_ context.Context, sub Job, _ Config) Result {
				if sub.Action == "processes.list" {
					return bad
				}
				return Result{State: "completed", Exit: 0, Output: "synthetic observation"}
			})
			var summary struct {
				Phase     string         `json:"phase"`
				Partial   bool           `json:"partial"`
				Coverage  []string       `json:"coverage"`
				Requested []string       `json:"requested_coverage"`
				Artifacts []ToolArtifact `json:"artifacts"`
			}
			if result.State != "completed" || json.Unmarshal([]byte(result.Output), &summary) != nil {
				t.Fatal("useful archive was lost")
			}
			if summary.Phase != "partial" || !summary.Partial || !reflect.DeepEqual(summary.Coverage, []string{"services.list", "reboot.status"}) || len(summary.Requested) != 3 || len(summary.Artifacts) != 1 {
				t.Fatalf("misleading completeness: %s", result.Output)
			}
			archive, err := zip.OpenReader(filepath.Join(toolsRoot(c), "artifacts", summary.Artifacts[0].ID+".zip"))
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			found := false
			for _, entry := range archive.File {
				if entry.Name != "collection.json" {
					continue
				}
				r, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				raw, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					t.Fatal(err)
				}
				var inner struct {
					Partial bool   `json:"partial"`
					Phase   string `json:"phase"`
				}
				if json.Unmarshal(raw, &inner) != nil || !inner.Partial || inner.Phase != "partial" {
					t.Fatal("downloaded archive concealed partial collection")
				}
				found = true
			}
			if !found {
				t.Fatal("archive missing collection coverage")
			}
		})
	}
}

func TestEvidenceFullCollectionAndLateCancellation(t *testing.T) {
	c := configForTest(t)
	j := jobForTest("tool.run", map[string]any{"tool_id": "evidence", "profile": "soc", "case_id": ""})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collector := func(_ context.Context, _ Job, _ Config) Result { return Result{State: "completed", Exit: 0} }
	result := evidenceToolWithCollector(ctx, j, c, collector)
	var summary struct {
		Phase    string   `json:"phase"`
		Partial  bool     `json:"partial"`
		Coverage []string `json:"coverage"`
	}
	if json.Unmarshal([]byte(result.Output), &summary) != nil || summary.Partial || summary.Phase != "completed" || len(summary.Coverage) != 4 {
		t.Fatal("complete SOC collection misreported")
	}
	result = evidenceToolWithCollector(ctx, j, c, func(ctx context.Context, sub Job, c Config) Result {
		if sub.Action == "posture" {
			cancel()
		}
		return collector(ctx, sub, c)
	})
	if result.State != "failed" {
		t.Fatal("cancellation after final collector ignored")
	}
}
