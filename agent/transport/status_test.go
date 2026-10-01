package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStatusRequiresFreshBoundSignedGoodAssertion(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{Raw: []byte("server leaf bytes")}
	digest := sha256.Sum256(certificate.Raw)
	now := time.Now().Unix()
	for _, test := range []struct {
		name, status, fingerprint string
		issued, expires           int64
		corrupt, wantError        bool
	}{
		{"good", "good", hex.EncodeToString(digest[:]), now - 1, now + 60, false, false},
		{"revoked", "revoked", hex.EncodeToString(digest[:]), now - 1, now + 60, false, true},
		{"expired", "good", hex.EncodeToString(digest[:]), now - 120, now - 1, false, true},
		{"future", "good", hex.EncodeToString(digest[:]), now + 60, now + 120, false, true},
		{"wrong leaf", "good", "wrong", now - 1, now + 60, false, true},
		{"bad signature", "good", hex.EncodeToString(digest[:]), now - 1, now + 60, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{"sha256": test.fingerprint, "status": test.status, "issued": test.issued, "expires": test.expires})
			signature := ed25519.Sign(key, payload)
			if test.corrupt {
				signature[0] ^= 1
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("credential reached status service")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"payload": payload, "signature": signature})
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			verify, err := StatusVerifier(server.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), roots)
			if err != nil {
				t.Fatal(err)
			}
			err = verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}})
			if (err != nil) != test.wantError {
				t.Fatalf("status acceptance mismatch: %v", err)
			}
		})
	}
}
