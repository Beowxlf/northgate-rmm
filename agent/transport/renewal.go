package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/identity"
	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

type ManagedSender struct {
	VerifyServer                  func(tls.ConnectionState) error
	Origin, Directory, EndpointID string
	Timeout                       time.Duration
}

func (sender ManagedSender) Send(ctx context.Context, messageID string, payload []byte) error {
	current, err := identity.Load(sender.Directory, time.Now())
	if err != nil || current.EndpointID != sender.EndpointID {
		return &DeliveryError{Code: "identity_unavailable"}
	}
	if time.Until(current.Certificate.Leaf.NotAfter) <= 6*time.Hour {
		chain, renewalErr := renew(ctx, sender.Origin, current, sender.Timeout, sender.VerifyServer)
		if renewalErr == nil {
			if err := identity.ReplaceCertificate(sender.Directory, chain, time.Now()); err != nil {
				return &DeliveryError{Code: "identity_write_uncertain"}
			}
			current, err = identity.Load(sender.Directory, time.Now())
			if err != nil {
				return &DeliveryError{Code: "identity_unavailable"}
			}
		}
	}
	client, err := NewMTLSSender(sender.Origin, Credentials{Certificate: current.Certificate, ServerRoots: current.ServerRoots, VerifyServer: sender.VerifyServer}, sender.Timeout)
	if err != nil {
		return err
	}
	return client.Send(ctx, messageID, payload)
}

func renew(ctx context.Context, origin string, current identity.Loaded, timeout time.Duration, verify func(tls.ConnectionState) error) ([]byte, error) {
	parsed, err := validateOrigin(origin)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, current.Certificate.PrivateKey)
	if err != nil {
		return nil, ErrEnrollment
	}
	digest := sha256.Sum256(current.Certificate.Certificate[0])
	digest[6] = digest[6]&15 | 0x50
	digest[8] = digest[8]&63 | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
	body, err := json.Marshal(map[string]any{"request_id": id, "csr": csr})
	if err != nil {
		return nil, err
	}
	parsed.Path = "/v1/agent/renew"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Close = true
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, VerifyConnection: verify, RootCAs: current.ServerRoots, Certificates: []tls.Certificate{current.Certificate}}, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 8192, TLSHandshakeTimeout: timeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrEnrollment }}
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrEnrollment
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return nil, ErrEnrollment
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 || strictjson.Validate(raw) != nil {
		return nil, ErrEnrollment
	}
	var result struct {
		EndpointID    string   `json:"endpoint_id"`
		IdentityID    string   `json:"identity_id"`
		State         string   `json:"state"`
		Leaf          []byte   `json:"leaf_certificate"`
		Intermediates [][]byte `json:"intermediate_certificates"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.EndpointID != current.EndpointID || !uuidPattern.MatchString(result.IdentityID) || result.State != "issued" || len(result.Leaf) > 16384 || len(result.Intermediates) > 4 {
		return nil, ErrEnrollment
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.Leaf})
	for _, cert := range result.Intermediates {
		if len(cert) > 16384 {
			return nil, ErrEnrollment
		}
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})...)
	}
	return chain, nil
}
