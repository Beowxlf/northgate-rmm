package management

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

// Deployment configuration, never an operator-selected account or SID.
type CredentialAccount struct {
	Username string `json:"username"`
	SID      string `json:"sid"`
}

// Used only for errors proven to precede the password-setting API.
type credentialUnchanged struct{ err error }

func (e credentialUnchanged) Error() string { return "credential was not changed" }

var managedSID = regexp.MustCompile(`^S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[1-9][0-9]{3,9}$`)

func validCredentialAccount(c Config) bool {
	return c.CredentialAccount != nil && c.CredentialAccount.Username == "rmmremote" && managedSID.MatchString(c.CredentialAccount.SID)
}

func credentialRecipient(c Config) (*ecdh.PrivateKey, error) {
	path := filepath.Join(c.Root, "credential-recipient.key")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		key, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e == nil {
			_, e = f.Write(key.Bytes())
			if e == nil {
				e = f.Sync()
			}
			closeErr := f.Close()
			if e != nil {
				return nil, e
			}
			if closeErr != nil {
				return nil, closeErr
			}
			return key, nil
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() != 32 {
		return nil, errors.New("credential recipient unavailable")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b)
}

func credentialRotationCapabilities(c Config) map[string]any {
	result := map[string]any{"available": false}
	if runtime.GOOS != "windows" || !validCredentialAccount(c) {
		return result
	}
	key, err := credentialRecipient(c)
	domain, hostErr := os.Hostname()
	if err != nil || hostErr != nil {
		return result
	}
	return map[string]any{"available": true, "username": c.CredentialAccount.Username, "account_sid": c.CredentialAccount.SID, "protocol": "rdp", "domain": domain, "recipient": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}
}

func validateCredentialJob(j Job, c Config) error {
	if runtime.GOOS != "windows" || !validCredentialAccount(c) || j.Endpoint != c.Endpoint || j.Identity != c.Identity ||
		!ID.MatchString(j.ID) || !ID.MatchString(text(j, "rotation_id")) || text(j, "username") != c.CredentialAccount.Username ||
		text(j, "account_sid") != c.CredentialAccount.SID || text(j, "protocol") != "rdp" ||
		(text(j, "phase") != "apply" && text(j, "phase") != "check") || integer(j, "expected_version") < 1 || integer(j, "expected_version") > 2147483647 {
		return errors.New("credential rotation is outside the configured account scope")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(text(j, "candidate"))
	if err != nil || len(b) < 60 || len(b) > 2048 {
		return errors.New("invalid encrypted credential")
	}
	return nil
}

func credentialAAD(j Job) []byte {
	return []byte(strings.Join([]string{"NorthGate-Credential-v1", j.Endpoint, j.Identity, j.ID, text(j, "rotation_id"), text(j, "phase"), text(j, "username"), text(j, "account_sid"), fmt.Sprint(integer(j, "expected_version"))}, "/"))
}

func decryptCredential(j Job, key *ecdh.PrivateKey) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(text(j, "candidate"))
	if err != nil || len(b) < 60 || len(b) > 2048 {
		return nil, errors.New("invalid credential envelope")
	}
	pub, err := ecdh.X25519().NewPublicKey(b[:32])
	if err != nil {
		return nil, err
	}
	shared, err := key.ECDH(pub)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("NorthGate-Credential-v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	password, err := gcm.Open(nil, b[32:44], b[44:], credentialAAD(j))
	if err != nil || len(password) < 16 || len(password) > 128 || !utf8.Valid(password) {
		return nil, errors.New("invalid encrypted credential")
	}
	for _, ch := range password {
		if ch < 33 || ch > 126 {
			clear(password)
			return nil, errors.New("invalid encrypted credential")
		}
	}
	return password, nil
}

// The journal precedes the OS change. A second apply never calls the setter,
// including after a process crash or a lost receipt. A check only authenticates.
func rotationJournal(ctx context.Context, j Job, c Config, password []byte, key *ecdh.PrivateKey, apply func() error, verify func() error) string {
	mac := hmac.New(sha256.New, key.Bytes())
	mac.Write([]byte(strings.Join([]string{j.Endpoint, j.Identity, text(j, "rotation_id"), text(j, "username"), text(j, "account_sid"), fmt.Sprint(integer(j, "expected_version"))}, "/")))
	mac.Write([]byte{0})
	mac.Write(password)
	binding := hex.EncodeToString(mac.Sum(nil))
	path := filepath.Join(c.Root, "credential-rotation-"+text(j, "rotation_id")+".json")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > 1024 {
			return "unknown"
		}
		b, e := os.ReadFile(path)
		var previous struct {
			Binding string `json:"binding"`
		}
		if e != nil || json.Unmarshal(b, &previous) != nil || !hmac.Equal([]byte(previous.Binding), []byte(binding)) {
			return "unknown"
		}
		if text(j, "phase") == "apply" {
			return "unknown"
		}
	} else if os.IsNotExist(err) && text(j, "phase") == "apply" {
		if ctx.Err() != nil {
			return "unknown"
		}
		if saveJSON(path, map[string]string{"binding": binding}) != nil {
			return "unknown"
		}
		if ctx.Err() != nil {
			return "unknown"
		}
		if err := apply(); err != nil {
			var unchanged credentialUnchanged
			if errors.As(err, &unchanged) {
				return "failed"
			}
			return "unknown"
		}
	} else {
		return "unknown"
	}
	if ctx.Err() != nil || verify() != nil || ctx.Err() != nil {
		return "unknown"
	}
	return "verified"
}

func executeCredentialRotation(ctx context.Context, j Job, c Config) Result {
	result := Result{State: "completed", Exit: 0, Identity: executionIdentity()}
	key, err := credentialRecipient(c)
	status := "unknown"
	if err == nil {
		password, e := decryptCredential(j, key)
		if e == nil {
			defer clear(password)
			status = rotationJournal(ctx, j, c, password, key,
				func() error { return setCredentialPassword(ctx, c, password) },
				func() error { return verifyCredentialPassword(ctx, c, password) })
		}
	}
	b, _ := json.Marshal(map[string]any{"rotation_id": text(j, "rotation_id"), "username": text(j, "username"), "account_sid": text(j, "account_sid"), "protocol": "rdp", "status": status, "local_authenticated": status == "verified"})
	result.Output = string(b)
	return result
}
