//go:build windows

package platformfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrUnsafe = errors.New("Windows filesystem boundary is unsafe or unavailable")

func allowedSID(sid *windows.SID) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || sid == nil {
		return false
	}
	value := sid.String()
	return value == user.User.Sid.String() || value == "S-1-5-18" || value == "S-1-5-32-544"
}

func Validate(name string, private bool) error {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ErrUnsafe
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUnsafe
	}
	sd, err := windows.GetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return ErrUnsafe
	}
	owner, _, err := sd.Owner()
	if err != nil || (!allowedSID(owner) && (private || owner == nil || owner.String() != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")) {
		return ErrUnsafe
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrUnsafe
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil {
			return ErrUnsafe
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrUnsafe
		}
		if allowedSID((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			continue
		}
		// Inherit-only ACEs do not grant authority over this ancestor itself.
		if !private && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if private || uint32(ace.Mask)&(windows.WRITE_DAC|windows.WRITE_OWNER|windows.DELETE|0x0040|windows.GENERIC_ALL|windows.GENERIC_WRITE) != 0 {
			return ErrUnsafe
		}
	}
	if private && attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		handle, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return ErrUnsafe
		}
		defer windows.CloseHandle(handle)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &info) != nil || info.NumberOfLinks != 1 {
			return ErrUnsafe
		}
	}
	return nil
}

func Ancestors(name string) error {
	if !filepath.IsAbs(name) || len(filepath.VolumeName(name)) != 2 {
		return ErrUnsafe
	}
	for current := filepath.Clean(name); ; current = filepath.Dir(current) {
		if err := Validate(current, false); err != nil {
			return err
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

func Protect(name string) error {
	if Ancestors(filepath.Dir(name)) != nil {
		return ErrUnsafe
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ErrUnsafe
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return ErrUnsafe
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return ErrUnsafe
	}
	return windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func Sync(root *os.Root) error {
	// Request a write-capable directory handle. Unsupported filesystem flushes
	// are failures, never silently treated as durable commits.
	ptr, err := windows.UTF16PtrFromString(root.Name())
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.FlushFileBuffers(handle)
}

func ValidateTree(path string) error {
	if err := Ancestors(filepath.Dir(path)); err != nil {
		return err
	}
	count := 0
	return filepath.WalkDir(path, func(name string, _ fs.DirEntry, err error) error {
		count++
		if err != nil || count > 10000 {
			return ErrUnsafe
		}
		return Validate(name, true)
	})
}
