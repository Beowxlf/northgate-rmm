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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rotationTestJob(c Config) Job {
	j := jobForTest("credential.rotate", map[string]any{"rotation_id": "44444444-4444-4444-8444-444444444444", "phase": "apply", "username": "rmmremote", "account_sid": "S-1-5-21-1-2-3-1001", "protocol": "rdp", "expected_version": 1, "candidate": ""})
	j.Endpoint = c.Endpoint
	j.Identity = c.Identity
	return j
}

func TestCredentialJournalNeverReappliesAfterLostAcknowledgement(t *testing.T) {
	c := configForTest(t)
	j := rotationTestJob(c)
	key, e := credentialRecipient(c)
	if e != nil {
		t.Fatal(e)
	}
	password := []byte("SyntheticPassword-12345")
	sets, checks := 0, 0
	setter := func() error { sets++; return errors.New("simulated interruption after setter") }
	verifier := func() error { checks++; return nil }
	if s := rotationJournal(context.Background(), j, c, password, key, setter, verifier); s != "unknown" {
		t.Fatal(s)
	}
	if s := rotationJournal(context.Background(), j, c, password, key, setter, verifier); s != "unknown" {
		t.Fatal(s)
	}
	j.Params["phase"] = json.RawMessage(`"check"`)
	if s := rotationJournal(context.Background(), j, c, password, key, setter, verifier); s != "verified" {
		t.Fatal(s)
	}
	if sets != 1 || checks != 1 {
		t.Fatalf("sets=%d checks=%d", sets, checks)
	}
	if s := rotationJournal(context.Background(), j, c, []byte("DifferentPassword-12345"), key, setter, verifier); s != "unknown" {
		t.Fatal(s)
	}
	if sets != 1 || checks != 1 {
		t.Fatal("conflicting candidate reached OS API")
	}
	b, e := os.ReadFile(filepath.Join(c.Root, "credential-rotation-44444444-4444-4444-8444-444444444444.json"))
	if e != nil || strings.Contains(string(b), string(password)) {
		t.Fatal("journal must not retain candidate")
	}
}

func TestCredentialCancelledBeforeJournalDoesNotChangeAccount(t *testing.T) {
	c := configForTest(t)
	j := rotationTestJob(c)
	key, _ := credentialRecipient(c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	setter := func() error { t.Fatal("cancelled setter ran"); return nil }
	if s := rotationJournal(ctx, j, c, []byte("SyntheticPassword-12345"), key, setter, setter); s != "unknown" {
		t.Fatal(s)
	}
}

func TestCredentialPreChangeRejectionIsDefinitive(t *testing.T) {
	c := configForTest(t)
	j := rotationTestJob(c)
	key, _ := credentialRecipient(c)
	setter := func() error { return credentialUnchanged{errors.New("account has service dependency")} }
	verifier := func() error { t.Fatal("rejected account must not authenticate"); return nil }
	if status := rotationJournal(context.Background(), j, c, []byte("SyntheticPassword-12345"), key, setter, verifier); status != "failed" {
		t.Fatal(status)
	}
}

func TestCredentialEnvelopeBindsEnrollmentJobPhaseAndAccount(t *testing.T) {
	c := configForTest(t)
	j := rotationTestJob(c)
	key, _ := credentialRecipient(c)
	ephemeral, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := ephemeral.ECDH(key.PublicKey())
	mac := hmac.New(sha256.New, shared)
	mac.Write([]byte("NorthGate-Credential-v1"))
	block, _ := aes.NewCipher(mac.Sum(nil))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	password := []byte("SyntheticPassword-12345")
	b := append(ephemeral.PublicKey().Bytes(), nonce...)
	b = append(b, gcm.Seal(nil, nonce, password, credentialAAD(j))...)
	j.Params["candidate"], _ = json.Marshal(base64.StdEncoding.EncodeToString(b))
	plain, e := decryptCredential(j, key)
	if e != nil || string(plain) != string(password) {
		t.Fatal("valid candidate rejected")
	}
	j.Identity = "55555555-5555-4555-8555-555555555555"
	if _, e = decryptCredential(j, key); e == nil {
		t.Fatal("cross-enrollment candidate accepted")
	}
	j.Identity = c.Identity
	j.Params["phase"] = json.RawMessage(`"check"`)
	if _, e = decryptCredential(j, key); e == nil {
		t.Fatal("cross-phase candidate accepted")
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, e = decryptCredential(j, other); e == nil {
		t.Fatal("wrong worker decrypted candidate")
	}
}

func TestCredentialRecipientPersistsAndRejectsInvalidAccount(t *testing.T) {
	c := configForTest(t)
	key, e := credentialRecipient(c)
	if e != nil {
		t.Fatal(e)
	}
	again, e := credentialRecipient(c)
	if e != nil || string(key.Bytes()) != string(again.Bytes()) {
		t.Fatal("recipient changed")
	}
	for _, account := range []CredentialAccount{{"Administrator", "S-1-5-21-1-2-3-500"}, {"rmmremote", "S-1-5-21-1-2-3-0500"}, {"another", "S-1-5-21-1-2-3-1001"}} {
		c.CredentialAccount = &account
		if validCredentialAccount(c) {
			t.Fatal("unmanaged account accepted")
		}
	}
}

func TestCredentialEnvelopePythonInteroperability(t *testing.T) {
	// Fixed synthetic Python-produced wire vector; no workstation credentials.
	var vector struct {
		Key      string `json:"recipient_private_key"`
		Job      Job    `json:"job"`
		Expected string `json:"expected"`
	}
	b, err := os.ReadFile(filepath.Join("testdata", "credential-rotation-envelope.json"))
	if err != nil || json.Unmarshal(b, &vector) != nil {
		t.Fatal("invalid interoperability fixture")
	}
	raw, err := base64.StdEncoding.DecodeString(vector.Key)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	password, err := decryptCredential(vector.Job, key)
	if err != nil || string(password) != vector.Expected {
		t.Fatal("Python credential envelope was not decoded")
	}
}
