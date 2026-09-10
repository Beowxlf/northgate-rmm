package identity

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// ReplaceCertificate preserves the enrolled key and server roots. Renewal may
// extend certificate lifetime but cannot change endpoint or either trust root.
func ReplaceCertificate(directory string, certificatePEM []byte, now time.Time) error {
	previous, err := Load(directory, now)
	if err != nil {
		return err
	}
	root, parent, err := openStore(directory, false)
	if err != nil {
		return err
	}
	defer root.Close()
	defer parent.Close()
	file, err := root.Open(bundleName)
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, MaxBundleBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) > MaxBundleBytes {
		return ErrCorrupt
	}
	bundle, err := decodeBundle(raw)
	if err != nil {
		return ErrCorrupt
	}
	material := Material{EndpointID: bundle.EndpointID, ClientCertificatePEM: certificatePEM, PrivateKeyPEM: []byte(bundle.PrivateKeyPEM), ServerRootsPEM: []byte(bundle.ServerRootsPEM)}
	updated, _, err := validateMaterial(material, now)
	if err != nil || updated.Leaf == nil || previous.Certificate.Leaf == nil || !updated.Leaf.NotAfter.After(previous.Certificate.Leaf.NotAfter) {
		return ErrCorrupt
	}
	oldRoot, err := x509.ParseCertificate(previous.Certificate.Certificate[len(previous.Certificate.Certificate)-1])
	if err != nil {
		return ErrCorrupt
	}
	roots := x509.NewCertPool()
	roots.AddCert(oldRoot)
	intermediates := x509.NewCertPool()
	for _, encoded := range updated.Certificate[1:] {
		cert, err := x509.ParseCertificate(encoded)
		if err != nil {
			return ErrCorrupt
		}
		intermediates.AddCert(cert)
	}
	if _, err := updated.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ErrCorrupt
	}
	bundle.ClientCertificatePEM = string(certificatePEM)
	encoded, err := json.Marshal(bundle)
	if err != nil || len(encoded) > MaxBundleBytes {
		return ErrCorrupt
	}
	staged, err := root.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if count, err := staged.Write(encoded); err != nil || count != len(encoded) {
		staged.Close()
		return errors.New("identity renewal write uncertain")
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporaryName, bundleName); err != nil {
		return err
	}
	if err := directorySync(root); err != nil {
		return &InstallUncertainError{Cause: err}
	}
	return nil
}
