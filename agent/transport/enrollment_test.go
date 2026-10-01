package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentBindsReturnedCertificateAndRefusesRedirect(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "enrollment test"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	encoded, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
	const endpoint = "123e4567-e89b-42d3-a456-426614174000"
	for _, scenario := range []string{"success", "wrong-key", "wrong-target", "redirect", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/v1/enrollment" || r.Method != "POST" {
					t.Error("unexpected request")
				}
				if scenario == "redirect" {
					w.Header().Set("Location", "/elsewhere")
					w.WriteHeader(307)
					return
				}
				if scenario == "duplicate" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(201)
					_, _ = w.Write([]byte(`{"state":"issued","state":"issued"}`))
					return
				}
				var request struct {
					Grant string `json:"grant"`
					CSR   []byte `json:"csr"`
				}
				if json.NewDecoder(r.Body).Decode(&request) != nil || !grantPattern.MatchString(request.Grant) {
					t.Error("bad enrollment body")
					w.WriteHeader(400)
					return
				}
				csr, err := x509.ParseCertificateRequest(request.CSR)
				if err != nil || csr.CheckSignature() != nil {
					t.Error("bad CSR")
					w.WriteHeader(400)
					return
				}
				id := endpoint
				if scenario == "wrong-target" {
					id = testMessageID
				}
				uri, _ := url.Parse("urn:northgate-rmm:endpoint:" + id)
				leaf := &x509.Certificate{SerialNumber: big.NewInt(12), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
				publicKey := csr.PublicKey
				if scenario == "wrong-key" {
					publicKey = &key.PublicKey
				}
				cert, err := x509.CreateCertificate(rand.Reader, leaf, root, publicKey, key)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(map[string]any{"endpoint_id": endpoint, "identity_id": testMessageID, "state": "issued", "leaf_certificate": cert, "intermediate_certificates": [][]byte{}})
			}))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			server.StartTLS()
			defer server.Close()
			serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			material, err := Enroll(context.Background(), server.URL, "ngr1_"+strings.Repeat("a", 43), "", serverPEM, issuerPEM, 2*time.Second)
			if scenario == "success" {
				if err != nil || material.EndpointID != endpoint || len(material.PrivateKeyPEM) == 0 {
					t.Fatalf("enrollment failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe enrollment accepted")
			}
			if calls != 1 {
				t.Fatalf("expected single attempt, got %d", calls)
			}
		})
	}
}
