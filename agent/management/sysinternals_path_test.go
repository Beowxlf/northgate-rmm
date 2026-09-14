package management

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSysinternalsPathContract(t *testing.T) {
	var cases struct{ Valid, Invalid []string }
	data, err := os.ReadFile("testdata/sysinternals-paths.json")
	if err != nil || json.Unmarshal(data, &cases) != nil {
		t.Fatal("Cannot read shared path contract")
	}
	cases.Invalid = append(cases.Invalid, `C:\`+strings.Repeat("x", 1025))
	for _, path := range cases.Valid {
		if err := validateWindowsTrustPath(path); err != nil {
			t.Errorf("valid path %q: %v", path, err)
		}
	}
	for _, path := range cases.Invalid {
		if validateWindowsTrustPath(path) == nil {
			t.Errorf("unsafe path accepted: %q", path)
		}
	}
}
