//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsStateRejectsBroadACL(t *testing.T) {
	directory := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setDACL := func(sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	private := "D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	setDACL(private)
	if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePlatformState(directory); err != nil {
		t.Fatalf("private state rejected: %v", err)
	}
	setDACL(private + "(A;OICI;FR;;;WD)")
	if validatePlatformState(directory) == nil {
		t.Fatal("world-readable state accepted")
	}
}
