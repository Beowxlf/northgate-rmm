//go:build windows

package management

import (
	"context"
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

var credentialNetAPI = windows.NewLazySystemDLL("netapi32.dll")
var credentialGetUser = credentialNetAPI.NewProc("NetUserGetInfo")
var credentialSetUser = credentialNetAPI.NewProc("NetUserSetInfo")
var credentialGetServer = credentialNetAPI.NewProc("NetServerGetInfo")
var credentialFree = credentialNetAPI.NewProc("NetApiBufferFree")
var credentialLogon = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")

func credentialAccount(ctx context.Context, c Config) (*uint16, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !validCredentialAccount(c) {
		return nil, errors.New("unmanaged credential account")
	}
	var server uintptr
	r, _, _ := credentialGetServer.Call(0, 101, uintptr(unsafe.Pointer(&server)))
	if r != 0 {
		return nil, errors.New("local server identity unavailable")
	}
	defer credentialFree.Call(server)
	s := (*struct {
		Platform           uint32
		Name               *uint16
		Major, Minor, Type uint32
		Comment            *uint16
	})(unsafe.Pointer(server))
	if s.Type&(0x8|0x10) != 0 {
		return nil, errors.New("domain controllers are excluded")
	}
	name, _ := windows.UTF16PtrFromString(c.CredentialAccount.Username)
	var user uintptr
	r, _, _ = credentialGetUser.Call(0, uintptr(unsafe.Pointer(name)), 23, uintptr(unsafe.Pointer(&user)))
	if r != 0 {
		return nil, errors.New("local account unavailable")
	}
	defer credentialFree.Call(user)
	u := (*struct {
		Name, FullName, Comment *uint16
		Flags                   uint32
		SID                     *windows.SID
	})(unsafe.Pointer(user))
	if u.SID == nil || u.SID.String() != c.CredentialAccount.SID || !strings.EqualFold(windows.UTF16PtrToString(u.Name), c.CredentialAccount.Username) || u.Flags&0x200 == 0 || u.Flags&(0x2|0x10|0x800|0x1000|0x2000) != 0 {
		return nil, errors.New("managed account identity or status changed")
	}
	if err := credentialNotServiceAccount(ctx, c.CredentialAccount.Username); err != nil {
		return nil, err
	}
	return name, nil
}

func credentialNotServiceAccount(ctx context.Context, username string) error {
	host, err := os.Hostname()
	if err != nil {
		return errors.New("local computer name unavailable")
	}
	manager, err := mgr.Connect()
	if err != nil {
		return errors.New("service account inventory unavailable")
	}
	defer manager.Disconnect()
	names, err := manager.ListServices()
	if err != nil || len(names) > 4096 {
		return errors.New("service account inventory unavailable")
	}
	for _, name := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		serviceName, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return errors.New("invalid service inventory")
		}
		handle, err := windows.OpenService(manager.Handle, serviceName, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			return errors.New("service account inventory incomplete")
		}
		service := mgr.Service{Name: name, Handle: handle}
		config, err := service.Config()
		service.Close()
		if err != nil {
			return errors.New("service account inventory incomplete")
		}
		account := strings.ToLower(config.ServiceStartName)
		if account == strings.ToLower(username) || account == `.\`+strings.ToLower(username) || account == strings.ToLower(host+`\`+username) {
			return errors.New("service identities are excluded from interactive password rotation")
		}
	}
	return nil
}

func setCredentialPassword(ctx context.Context, c Config, password []byte) error {
	name, err := credentialAccount(ctx, c)
	if err != nil {
		return credentialUnchanged{err}
	}
	b, err := windows.UTF16FromString(string(password))
	if err != nil {
		return credentialUnchanged{err}
	}
	defer clear(b)
	info := struct{ Password *uint16 }{&b[0]}
	var parameter uint32
	if ctx.Err() != nil {
		return credentialUnchanged{ctx.Err()}
	}
	r, _, _ := credentialSetUser.Call(0, uintptr(unsafe.Pointer(name)), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	if r != 0 {
		return errors.New("local password change was not acknowledged")
	}
	return nil
}

func verifyCredentialPassword(ctx context.Context, c Config, password []byte) error {
	name, err := credentialAccount(ctx, c)
	if err != nil {
		return err
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	domain, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return err
	}
	b, err := windows.UTF16FromString(string(password))
	if err != nil {
		return errors.New("invalid credential")
	}
	defer clear(b)
	var token windows.Token
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// NETWORK performs real authentication; NEW_CREDENTIALS would not.
	r, _, _ := credentialLogon.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(&b[0])), 3, 0, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return errors.New("candidate local authentication failed")
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user.User.Sid.String() != c.CredentialAccount.SID {
		return errors.New("candidate identity verification failed")
	}
	return nil
}
