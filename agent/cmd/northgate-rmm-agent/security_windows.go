//go:build windows

package main

import (
	"errors"
	"io/fs"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errPrivateState = errors.New("Windows state requires a private local directory without reparse points")

func validatePlatformState(path string) error {
	if !filepath.IsAbs(path) || len(filepath.VolumeName(path)) != 2 {
		return errPrivateState
	}
	count := 0
	return filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
		count++
		if err != nil || count > 10000 {
			return errPrivateState
		}
		return validateWindowsACL(name)
	})
}

func validatePrivateInput(name string, _ fs.FileInfo) error { return validateWindowsACL(name) }

func validateWindowsACL(name string) error {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return errPrivateState
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errPrivateState
	}
	security, err := windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return errPrivateState
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errPrivateState
	}
	allowed := func(sid *windows.SID) bool {
		value := sid.String()
		return value == tokenUser.User.Sid.String() || value == "S-1-5-18" || value == "S-1-5-32-544"
	}
	owner, _, err := security.Owner()
	if err != nil || owner == nil || !allowed(owner) {
		return errPrivateState
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errPrivateState
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil {
			return errPrivateState
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !allowed((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errPrivateState
		}
	}
	return nil
}
