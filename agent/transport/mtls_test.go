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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testMessageID = "123e4567-e89b-42d3-a456-426614174001"

type testPKI struct {
	server tls.Certificate
	client tls.Certificate
	roots  *x509.CertPool
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "synthetic test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	issue := func(serial int64, usage x509.ExtKeyUsage, ip net.IP) tls.Certificate {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatalf("generate leaf key: %v", keyErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "synthetic leaf"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		if ip != nil {
			template.IPAddresses = []net.IP{ip}
		}
		leafDER, createErr := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if createErr != nil {
			t.Fatalf("create leaf: %v", createErr)
		}
		return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}
	}
	return testPKI{
		server: issue(2, x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1")),
		client: issue(3, x509.ExtKeyUsageClientAuth, nil),
		roots:  roots,
	}
}

func startMTLSServer(t *testing.T, pki testPKI, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.roots,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newTestSender(t *testing.T, server *httptest.Server, pki testPKI) *MTLSSender {
	t.Helper()
	sender, err := NewMTLSSender(
		server.URL,
		Credentials{Certificate: pki.client, ServerRoots: pki.roots},
		2*time.Second,
	)
	if err != nil {
		t.Fatalf("NewMTLSSender() error = %v", err)
	}
	return sender
}

func writeAck(t *testing.T, writer http.ResponseWriter, messageID string, accepted bool) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(acknowledgement{MessageID: messageID, Accepted: accepted}); err != nil {
		t.Fatalf("encode acknowledgement: %v", err)
	}
}

func TestMTLSSenderRequiresMutualTLSAndExactAcknowledgement(t *testing.T) {
	pki := newTestPKI(t)
	server := startMTLSServer(t, pki, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != messagePath {
			t.Errorf("unexpected request target: %s %s", request.Method, request.URL.Path)
		}
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
			t.Error("request did not include an authenticated client certificate")
		}
		if request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type: %q", request.Header.Get("Content-Type"))
		}
		writeAck(t, writer, testMessageID, true)
	}))

	sender := newTestSender(t, server, pki)
	transport, ok := sender.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableKeepAlives ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.TLSClientConfig.ClientSessionCache != nil {
		t.Fatalf("sender transport does not enforce the fail-closed connection policy: %#v", transport)
	}
	err := sender.Send(context.Background(), testMessageID, []byte(`{"type":"inventory"}`))
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestMTLSSenderRefusesRedirects(t *testing.T) {
	pki := newTestPKI(t)
	server := startMTLSServer(t, pki, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", "https://example.invalid/redirected")
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	err := newTestSender(t, server, pki).Send(context.Background(), testMessageID, []byte(`{}`))
	if err == nil || IsRetryable(err) {
		t.Fatalf("Send() redirect error = %v, want permanent refusal", err)
	}
}

func TestMTLSSenderRejectsInvalidAcknowledgements(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "wrong ID", body: `{"message_id":"123e4567-e89b-42d3-a456-426614174002","accepted":true}`},
		{name: "not accepted", body: `{"message_id":"123e4567-e89b-42d3-a456-426614174001","accepted":false}`},
		{name: "unknown field", body: `{"message_id":"123e4567-e89b-42d3-a456-426614174001","accepted":true,"extra":1}`},
		{name: "duplicate field", body: `{"message_id":"123e4567-e89b-42d3-a456-426614174001","accepted":true,"accepted":true}`},
		{name: "trailing value", body: `{"message_id":"123e4567-e89b-42d3-a456-426614174001","accepted":true} {}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			server := startMTLSServer(t, pki, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(test.body))
			}))
			err := newTestSender(t, server, pki).Send(context.Background(), testMessageID, []byte(`{}`))
			if err == nil || IsRetryable(err) {
				t.Fatalf("Send() error = %v, want permanent acknowledgement failure", err)
			}
		})
	}
}

func TestMTLSSenderBoundsResponseAndClassifiesStatus(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		retryable bool
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, retryable: true},
		{name: "server failure", status: http.StatusServiceUnavailable, retryable: true},
		{name: "authorization failure", status: http.StatusForbidden, retryable: false},
		{name: "oversized acknowledgement", status: http.StatusOK, body: string(make([]byte, MaxResponseBytes+1)), retryable: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pki := newTestPKI(t)
			server := startMTLSServer(t, pki, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			err := newTestSender(t, server, pki).Send(context.Background(), testMessageID, []byte(`{}`))
			if err == nil || IsRetryable(err) != test.retryable {
				t.Fatalf("Send() error = %v, retryable = %t", err, IsRetryable(err))
			}
		})
	}
}

func TestMTLSSenderRejectsTLS12AndUntrustedServer(t *testing.T) {
	pki := newTestPKI(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeAck(t, writer, testMessageID, true)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.roots,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	if err := newTestSender(t, server, pki).Send(context.Background(), testMessageID, []byte(`{}`)); err == nil || IsRetryable(err) {
		t.Fatalf("Send() TLS 1.2 error = %v, want permanent protocol failure", err)
	}

	trustedServer := startMTLSServer(t, pki, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeAck(t, writer, testMessageID, true)
	}))
	otherPKI := newTestPKI(t)
	sender, err := NewMTLSSender(
		trustedServer.URL,
		Credentials{Certificate: pki.client, ServerRoots: otherPKI.roots},
		2*time.Second,
	)
	if err != nil {
		t.Fatalf("NewMTLSSender() error = %v", err)
	}
	err = sender.Send(context.Background(), testMessageID, []byte(`{}`))
	if err == nil || IsRetryable(err) {
		t.Fatalf("Send() error = %v, want permanent trust failure", err)
	}
}

func TestMTLSSenderTreatsConnectionFailureAsTransient(t *testing.T) {
	pki := newTestPKI(t)
	sender, err := NewMTLSSender(
		"https://127.0.0.1:1",
		Credentials{Certificate: pki.client, ServerRoots: pki.roots},
		time.Second,
	)
	if err != nil {
		t.Fatalf("NewMTLSSender() error = %v", err)
	}
	err = sender.Send(context.Background(), testMessageID, []byte(`{}`))
	if err == nil || !IsRetryable(err) {
		t.Fatalf("Send() connection error = %v, want transient failure", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("Send() leaked the private origin in its error: %v", err)
	}
}

func TestNewMTLSSenderRejectsIncompleteInputs(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		name        string
		origin      string
		credentials Credentials
		timeout     time.Duration
	}{
		{name: "HTTP", origin: "http://127.0.0.1", credentials: Credentials{Certificate: pki.client, ServerRoots: pki.roots}, timeout: time.Second},
		{name: "path", origin: "https://127.0.0.1/not-origin", credentials: Credentials{Certificate: pki.client, ServerRoots: pki.roots}, timeout: time.Second},
		{name: "legacy numeric host", origin: "https://0177.0.0.1", credentials: Credentials{Certificate: pki.client, ServerRoots: pki.roots}, timeout: time.Second},
		{name: "out of range port", origin: "https://127.0.0.1:65536", credentials: Credentials{Certificate: pki.client, ServerRoots: pki.roots}, timeout: time.Second},
		{name: "Unicode host", origin: "https://example\u200d.test", credentials: Credentials{Certificate: pki.client, ServerRoots: pki.roots}, timeout: time.Second},
		{name: "missing roots", origin: "https://127.0.0.1", credentials: Credentials{Certificate: pki.client}, timeout: time.Second},
		{name: "missing certificate", origin: "https://127.0.0.1", credentials: Credentials{ServerRoots: pki.roots}, timeout: time.Second},
		{name: "zero timeout", origin: "https://127.0.0.1", credentials: Credentials{Certificate: pki.client, ServerRoots: pki.roots}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewMTLSSender(test.origin, test.credentials, test.timeout); err == nil {
				t.Fatal("NewMTLSSender() accepted incomplete input")
			}
		})
	}
}

func TestMTLSSenderRejectsInvalidMessageBounds(t *testing.T) {
	sender := &MTLSSender{client: &http.Client{}}
	if err := sender.Send(context.Background(), "not-a-uuid", []byte(`{}`)); err == nil {
		t.Fatal("Send() accepted invalid message ID")
	}
	if err := sender.Send(context.Background(), testMessageID, make([]byte, MaxRequestBytes+1)); err == nil {
		t.Fatal("Send() accepted oversized payload")
	}
}
