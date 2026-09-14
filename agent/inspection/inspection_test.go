package inspection

import (
	"context"
	"strings"
	"testing"
)

func TestUnsupportedCategoryCannotExecute(t *testing.T) {
	for _, v := range []string{"services; whoami", "../health", "", "shell"} {
		if _, err := Collect(context.Background(), v, "test"); err == nil {
			t.Fatal("accepted arbitrary category")
		}
	}
}
func TestAccountParserExcludesCredentialFields(t *testing.T) {
	rows := parseLinux("users", "alice:secret:1000:1000:Example:/home/alice:/bin/bash\n")
	if len(rows) != 1 || rows[0]["id"] != "alice" || len(rows[0]) != 5 {
		t.Fatal(rows)
	}
	for _, v := range rows[0] {
		if strings.Contains(v, "secret") {
			t.Fatal("credential field copied")
		}
	}
}
func TestNetworkIdentityIncludesPeer(t *testing.T) {
	rows := parseLinux("network", "tcp ESTAB 0 0 10.0.0.1:123 10.0.0.2:22\n")
	if len(rows) != 1 || rows[0]["remote"] != "10.0.0.2:22" {
		t.Fatal(rows)
	}
}
func TestOutputBoundIsEnforced(t *testing.T) {
	var b limitedBuffer
	n, err := b.Write([]byte(strings.Repeat("a", MaxBytes+100)))
	if err != nil || n != MaxBytes+100 || b.Len() != MaxBytes || !b.exceeded {
		t.Fatal("unbounded output")
	}
}
func TestSoftwareParserFiltersRemovedPackages(t *testing.T) {
	rows := parseLinux("software", "a\t1\tinstalled\nb\t2\tconfig-files\n")
	if len(rows) != 1 || rows[0]["id"] != "a" {
		t.Fatal(rows)
	}
}
