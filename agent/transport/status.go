package transport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

// StatusVerifier verifies short-lived assertions using a separately pinned key.
// It never sends an endpoint credential to the status origin.
func StatusVerifier(origin string, publicPEM []byte, roots *x509.CertPool) (func(tls.ConnectionState) error, error) {
	parsed, err := validateOrigin(origin)
	if err != nil || roots == nil {
		return nil, errInvalidTrust
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errInvalidTrust
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := public.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errInvalidTrust
	}
	return func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errInvalidTrust
		}
		fingerprint := sha256.Sum256(state.PeerCertificates[0].Raw)
		address := *parsed
		address.Path = "/" + hex.EncodeToString(fingerprint[:]) + ".json"
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 4096, TLSHandshakeTimeout: 3 * time.Second}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
		response, err := client.Get(address.String())
		if err != nil {
			return errInvalidTrust
		}
		defer response.Body.Close()
		if response.StatusCode != 200 || response.Header.Get("Content-Encoding") != "" {
			return errInvalidTrust
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		if err != nil || len(raw) > 4096 || strictjson.Validate(raw) != nil {
			return errInvalidTrust
		}
		var envelope struct {
			Payload   []byte `json:"payload"`
			Signature []byte `json:"signature"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&envelope) != nil || !ed25519.Verify(key, envelope.Payload, envelope.Signature) || strictjson.Validate(envelope.Payload) != nil {
			return errInvalidTrust
		}
		var assertion struct {
			SHA256  string `json:"sha256"`
			Status  string `json:"status"`
			Issued  int64  `json:"issued"`
			Expires int64  `json:"expires"`
		}
		decoder = json.NewDecoder(bytes.NewReader(envelope.Payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&assertion) != nil {
			return errInvalidTrust
		}
		now := time.Now().Unix()
		if assertion.SHA256 != hex.EncodeToString(fingerprint[:]) || assertion.Status != "good" || assertion.Issued > now || assertion.Expires <= now || assertion.Expires-assertion.Issued > 120 || assertion.Expires <= assertion.Issued {
			return errors.New("server certificate status unavailable")
		}
		return nil
	}, nil
}
