//go:build windows

package management

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func trustJob(inputs map[string]any) Job {
	return jobForTest("tool.run", map[string]any{"tool_id": "sysinternals", "profile": "trust", "inputs": inputs, "case_id": ""})
}

func TestSysinternalsRecipesHaveBoundedDefaults(t *testing.T) {
	c := configForTest(t)
	m := ToolManifest{ID: "sysinternals"}
	j := trustJob(map[string]any{})
	if err := validateToolJob(j, c); err != nil {
		t.Fatal(err)
	}
	args, err := toolArguments(j, c, m)
	root, _ := windows.GetSystemWindowsDirectory()
	expected := []string{"-accepteula", "-nobanner", "-r", "-c", "-h", "-e", filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)}
	if err != nil || !reflect.DeepEqual(args, expected) {
		t.Fatalf("incorrect default file recipe: %v %v", args, err)
	}
	j = jobForTest("tool.run", map[string]any{"tool_id": "sysinternals", "profile": "startup", "inputs": map[string]any{}, "case_id": ""})
	args, err = toolArguments(j, c, m)
	if err != nil || !reflect.DeepEqual(args, []string{"-accepteula", "-a", "l", "-c"}) {
		t.Fatalf("startup is not logon-only metadata: %v %v", args, err)
	}
	for _, profile := range []string{"startup", "trust"} {
		for _, inputs := range []map[string]any{{"flags": "-v"}, {"path": `C:\Ops\app.exe`, "flags": "-a *"}} {
			j := jobForTest("tool.run", map[string]any{"tool_id": "sysinternals", "profile": profile, "inputs": inputs, "case_id": ""})
			if validateToolJob(j, c) == nil {
				t.Fatal("arbitrary switches accepted")
			}
		}
	}
	j.Params["inputs"] = []byte(`{"path":"C:\\Ops\\app.exe"}`)
	if validateToolJob(j, c) == nil {
		t.Fatal("startup accepted a trust-only path")
	}
}

func TestSysinternalsTrustFileIsPinnedThroughExecution(t *testing.T) {
	c := configForTest(t)
	path := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(path, []byte("synthetic regular file"), 0600); err != nil {
		t.Fatal(err)
	}
	actual, closeFile, err := pinSysinternalsTrustFile(c, path)
	if err != nil || !strings.EqualFold(path, actual) {
		t.Fatalf("cannot pin regular file: %s %v", actual, err)
	}
	defer closeFile()
	if file, err := os.OpenFile(path, os.O_WRONLY, 0600); err == nil {
		file.Close()
		t.Fatal("pinned file can be changed")
	}
	if err := os.Rename(path, path+".replacement"); err == nil {
		t.Fatal("pinned file can be replaced")
	}
	if err := os.Rename(filepath.Dir(path), filepath.Dir(path)+"-moved"); err == nil {
		t.Fatal("pinned parent can be replaced")
	}
	closeFile()
	if file, err := os.OpenFile(path, os.O_WRONLY, 0600); err != nil {
		t.Fatal("file lock not released")
	} else {
		file.Close()
	}
}

func TestSysinternalsDefaultSystemExecutableCanBeReadWhilePinned(t *testing.T) {
	c := configForTest(t)
	path, err := sysinternalsDefaultTarget()
	if err != nil {
		t.Fatal(err)
	}
	actual, release, err := pinSysinternalsTrustFile(c, path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	f, err := os.Open(actual)
	if err != nil {
		t.Fatal("pin prevents a separate reader from inspecting the default executable", err)
	}
	defer f.Close()
	magic := make([]byte, 2)
	if _, err := f.Read(magic); err != nil || string(magic) != "MZ" {
		t.Fatal("default is not a readable Windows executable")
	}
}

func TestSysinternalsTrustRejectsPrivateShortPathAlias(t *testing.T) {
	c := configForTest(t)
	c.Root = filepath.Join(c.Root, "Long private worker directory")
	if err := os.Mkdir(c.Root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Root, "Long private identity filename.key")
	if err := os.WriteFile(path, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(path)
	buffer := make([]uint16, 32768)
	n, err := windows.GetShortPathName(name, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatal("Cannot query Windows short-path behavior", err)
	}
	short := windows.UTF16ToString(buffer[:n])
	if strings.EqualFold(short, path) {
		t.Skip("8.3 aliases are disabled on this test volume")
	}
	_, release, err := pinSysinternalsTrustFile(c, short)
	release()
	if err == nil {
		t.Fatal("short-path alias bypassed worker private-directory exclusion")
	}
}

func TestSysinternalsTrustRejectsDirectoryOversizeAndPrivateFiles(t *testing.T) {
	c := configForTest(t)
	root := t.TempDir()
	large := filepath.Join(root, "large.exe")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(64<<20 + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	state := filepath.Join(c.Root, "private.key")
	if err := os.WriteFile(state, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.IdentityFile, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, large, state, c.IdentityFile, strings.ToUpper(state), filepath.Join(root, "missing.exe")} {
		_, cleanup, err := pinSysinternalsTrustFile(c, path)
		cleanup()
		if err == nil {
			t.Fatalf("invalid target accepted: %q", path)
		}
	}
	j := trustJob(map[string]any{"path": root})
	args, err := toolArguments(j, c, ToolManifest{ID: "sysinternals"})
	if err != nil {
		t.Fatal(err)
	}
	result := runBudgetedTool(context.Background(), j, c, ToolManifest{ID: "sysinternals"}, args)
	if result.State != "failed" || !strings.Contains(result.Error, "regular file") {
		t.Fatalf("directory validation did not run before process launch: %+v", result)
	}
}

func TestSysinternalsTrustRejectsReparseParentsAndFiles(t *testing.T) {
	c := configForTest(t)
	root := t.TempDir()
	target := filepath.Join(root, "target.exe")
	if err := os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.exe")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("Windows symlink creation requires developer mode or privilege")
	}
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(root, parent); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(parent, "target.exe")} {
		_, cleanup, err := pinSysinternalsTrustFile(c, path)
		cleanup()
		if err == nil {
			t.Fatal("reparse target accepted")
		}
	}
}
