package identity

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

// RecoverRenewal discards only an unpublished temporary file while retaining a
// valid installed identity. The caller must hold the agent sequence lock and
// stop the service. Missing/expired installed identities require revocation and
// fresh enrollment, never automatic replacement of authority.
func RecoverRenewal(directory string, now time.Time) error {
	root, parent, err := openStore(directory, false)
	if err != nil {
		return err
	}
	defer root.Close()
	defer parent.Close()
	entries, err := readEntries(root)
	if err != nil || len(entries) != 2 {
		return ErrCorrupt
	}
	for _, entry := range entries {
		if entry.Name() != bundleName && entry.Name() != temporaryName {
			return ErrCorrupt
		}
		info, err := root.Lstat(entry.Name())
		if err != nil || !info.Mode().IsRegular() || !privateFile(info, filepath.Join(directory, entry.Name())) || info.Size() > MaxBundleBytes {
			return ErrCorrupt
		}
	}
	file, err := root.Open(bundleName)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxBundleBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) > MaxBundleBytes {
		return ErrCorrupt
	}
	bundle, err := decodeBundle(raw)
	if err != nil {
		return ErrCorrupt
	}
	_, _, err = validateMaterial(Material{EndpointID: bundle.EndpointID, ClientCertificatePEM: []byte(bundle.ClientCertificatePEM), PrivateKeyPEM: []byte(bundle.PrivateKeyPEM), ServerRootsPEM: []byte(bundle.ServerRootsPEM)}, now)
	if err != nil {
		return ErrCorrupt
	}
	if err := root.Remove(temporaryName); err != nil && !os.IsNotExist(err) {
		return err
	}
	return directorySync(root)
}
