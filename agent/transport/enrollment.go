package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/identity"
	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

var ErrEnrollment = errors.New("enrollment failed; reconcile grant and identity before retrying")
var grantPattern = regexp.MustCompile(`^ngr1_[A-Za-z0-9_-]{43}$`)

// Enroll performs one attempt using an endpoint-generated key. It never retries
// a consumed grant, follows redirects, uses ambient proxies, or logs secrets.
// Both trust bundles and the expected endpoint must come from the operator.
// The caller installs the returned material through identity.Install.
func Enroll(ctx context.Context, origin, token, endpointID string, serverRootsPEM, issuerRootsPEM []byte, timeout time.Duration, verifiers ...func(tls.ConnectionState) error) (identity.Material, error) {
	parsed, err := validateOrigin(origin)
	if err != nil || !grantPattern.MatchString(token) || (endpointID != "" && !uuidPattern.MatchString(endpointID)) || timeout < time.Second || timeout > time.Minute {
		return identity.Material{}, ErrEnrollment
	}
	if len(serverRootsPEM) == 0 || len(serverRootsPEM) > 65536 || len(issuerRootsPEM) == 0 || len(issuerRootsPEM) > 65536 {
		return identity.Material{}, ErrEnrollment
	}
	serverRoots, issuerRoots := x509.NewCertPool(), x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(serverRootsPEM) || !issuerRoots.AppendCertsFromPEM(issuerRootsPEM) {
		return identity.Material{}, ErrEnrollment
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return identity.Material{}, ErrEnrollment
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return identity.Material{}, ErrEnrollment
	}
	body, err := json.Marshal(struct {
		Token string `json:"grant"`
		CSR   []byte `json:"csr"`
	}{token, csr})
	if err != nil {
		return identity.Material{}, ErrEnrollment
	}
	parsed.Path = "/v1/enrollment"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return identity.Material{}, ErrEnrollment
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Close = true
	var verify func(tls.ConnectionState) error
	if len(verifiers) > 1 {
		return identity.Material{}, ErrEnrollment
	}
	if len(verifiers) == 1 {
		verify = verifiers[0]
	}
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: serverRoots, VerifyConnection: verify},
		DisableCompression: true, DisableKeepAlives: true,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		MaxResponseHeaderBytes: 8192,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrEnrollment },
	}
	response, err := client.Do(request)
	if err != nil {
		return identity.Material{}, ErrEnrollment
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" {
		return identity.Material{}, ErrEnrollment
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 131073))
	if err != nil || len(raw) > 131072 || strictjson.Validate(raw) != nil {
		return identity.Material{}, ErrEnrollment
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
	if decoder.Decode(&result) != nil || !uuidPattern.MatchString(result.EndpointID) || (endpointID != "" && result.EndpointID != endpointID) || !uuidPattern.MatchString(result.IdentityID) || result.State != "issued" || len(result.Intermediates) > 4 || len(result.Leaf) > 16384 {
		return identity.Material{}, ErrEnrollment
	}
	endpointID = result.EndpointID
	leaf, err := x509.ParseCertificate(result.Leaf)
	if err != nil {
		return identity.Material{}, ErrEnrollment
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range result.Intermediates {
		if len(encoded) > 16384 {
			return identity.Material{}, ErrEnrollment
		}
		cert, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return identity.Material{}, ErrEnrollment
		}
		intermediates.AddCert(cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: issuerRoots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 || len(chains[0]) > 8 {
		return identity.Material{}, ErrEnrollment
	}
	var chainPEM []byte
	for _, certificate := range chains[0] {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour {
		return identity.Material{}, ErrEnrollment
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) || len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:northgate-rmm:endpoint:"+endpointID || leaf.IsCA || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return identity.Material{}, ErrEnrollment
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return identity.Material{}, ErrEnrollment
	}
	return identity.Material{EndpointID: endpointID, ClientCertificatePEM: chainPEM, PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), ServerRootsPEM: append([]byte(nil), serverRootsPEM...)}, nil
}
