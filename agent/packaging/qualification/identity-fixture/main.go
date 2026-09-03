// Command identity-fixture creates one synthetic, short-lived endpoint
// identity for the isolated G2A systemd qualification environment. It is not
// an enrollment implementation and must never be shipped in an agent package.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/identity"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(64)
	}
	if err := createFixture(os.Args[1], os.Args[2], time.Now().UTC()); err != nil {
		os.Exit(1)
	}
}

func createFixture(directory, endpointID string, now time.Time) error {
	if directory == "" || endpointID == "" || now.IsZero() {
		return errors.New("fixture inputs are required")
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NorthGate G2A synthetic root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		return err
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	identityURI, err := url.Parse("urn:northgate-rmm:endpoint:" + endpointID)
	if err != nil {
		return err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "NorthGate G2A synthetic endpoint"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identityURI},
	}
	clientDER, err := x509.CreateCertificate(
		rand.Reader, clientTemplate, rootTemplate, clientPublic, rootPrivate,
	)
	if err != nil {
		return err
	}
	clientPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		rootPEM...,
	)
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return identity.Install(directory, identity.Material{
		EndpointID:           endpointID,
		ClientCertificatePEM: clientPEM,
		PrivateKeyPEM:        privatePEM,
		ServerRootsPEM:       rootPEM,
	}, now)
}
