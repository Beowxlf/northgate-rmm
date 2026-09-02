package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestExecutePrintsOnlyVersion(t *testing.T) {
	var output bytes.Buffer
	if code := execute(context.Background(), []string{"--version"}, &output); code != 0 {
		t.Fatalf("execute returned %d", code)
	}
	if output.String() != version+"\n" {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestExecuteRejectsUnknownOrCombinedArgumentsSilently(t *testing.T) {
	for _, args := range [][]string{{"--unknown"}, {"--version", "--config", "/tmp/value"}, {}} {
		var output bytes.Buffer
		if code := execute(context.Background(), args, &output); code != 2 {
			t.Fatalf("execute(%v) returned %d", args, code)
		}
		if output.Len() != 0 {
			t.Fatalf("execute(%v) exposed output %q", args, output.String())
		}
	}
}

func TestExecuteReportsConfigurationFailureWithClosedSchema(t *testing.T) {
	var output bytes.Buffer
	if code := execute(context.Background(), []string{"--config", "/definitely/missing"}, &output); code != 1 {
		t.Fatalf("execute returned %d", code)
	}
	value := output.String()
	if !strings.Contains(value, `"code":"agent_lifecycle"`) || strings.Contains(value, "/definitely/missing") {
		t.Fatalf("unexpected failure output %q", value)
	}
}
