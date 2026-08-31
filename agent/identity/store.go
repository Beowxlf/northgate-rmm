// Package identity persists one already-enrolled endpoint identity in a
// create-once, permission-restricted bundle. It contains no enrollment grant,
// network client, rotation, or revocation-status implementation.
package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

const (
	SchemaVersion             = 1
	bundleName                = "identity.json"
	temporaryName             = "identity.tmp"
	MaxBundleBytes            = 128 * 1024
	maxClientCertificateBytes = 32 * 1024
	maxPrivateKeyBytes        = 16 * 1024
	maxServerRootsBytes       = 64 * 1024
	maxCertificateCount       = 8
)

var (
	ErrExists     = errors.New("endpoint identity already exists")
	ErrCorrupt    = errors.New("endpoint identity store is corrupt")
	directorySync = syncDirectory
	uuidPattern   = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
)

// InstallUncertainError means cleanup could not prove whether identity material
// survived a failed publication. Callers must inspect or quarantine the store;
// they must not repeat enrollment or install another identity automatically.
type InstallUncertainError struct {
	Cause error
}

func (err *InstallUncertainError) Error() string {
	return "endpoint identity install outcome is uncertain"
}

func (err *InstallUncertainError) Unwrap() error { return err.Cause }

// Material is the bounded output of a separately qualified enrollment flow.
// PrivateKeyPEM must contain the endpoint-generated key and is never returned
// from a file-oriented API after parsing.
type Material struct {
	EndpointID           string
	ClientCertificatePEM []byte
	PrivateKeyPEM        []byte
	ServerRootsPEM       []byte
}

// Loaded contains only parsed in-memory identity material suitable for the
// outbound mTLS sender.
type Loaded struct {
	EndpointID  string
	Certificate tls.Certificate
	ServerRoots *x509.CertPool
}

type wireBundle struct {
	SchemaVersion        int    `json:"schema_version"`
	EndpointID           string `json:"endpoint_id"`
	ClientCertificatePEM string `json:"client_certificate_pem"`
	PrivateKeyPEM        string `json:"private_key_pem"`
	ServerRootsPEM       string `json:"server_roots_pem"`
}

// Install validates and durably publishes one identity bundle without
// replacing an existing or partially installed identity.
func Install(directory string, material Material, now time.Time) (returnErr error) {
	if _, _, err := validateMaterial(material, now); err != nil {
		return err
	}
	raw, err := json.Marshal(wireBundle{
		SchemaVersion:        SchemaVersion,
		EndpointID:           material.EndpointID,
		ClientCertificatePEM: string(material.ClientCertificatePEM),
		PrivateKeyPEM:        string(material.PrivateKeyPEM),
		ServerRootsPEM:       string(material.ServerRootsPEM),
	})
	if err != nil || len(raw) > MaxBundleBytes {
		return errors.New("endpoint identity bundle exceeds the supported size")
	}

	root, parent, err := openStore(directory, true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer parent.Close()

	entries, err := readEntries(root)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		if len(entries) == 1 && entries[0].Name() == bundleName {
			if _, loadErr := Load(directory, now); loadErr == nil {
				return ErrExists
			}
		}
		return ErrCorrupt
	}

	file, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("create endpoint identity staging file: %w", err)
	}
	removeTemporary := true
	defer func() {
		if !removeTemporary {
			return
		}
		cleanupErr := root.Remove(temporaryName)
		if errors.Is(cleanupErr, fs.ErrNotExist) {
			cleanupErr = nil
		}
		if cleanupErr == nil {
			cleanupErr = directorySync(root)
		}
		if cleanupErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("clean endpoint identity staging file: %w", cleanupErr))
		}
	}()
	if written, err := file.Write(raw); err != nil || written != len(raw) {
		_ = file.Close()
		if err == nil {
			err = io.ErrShortWrite
		}
		return fmt.Errorf("write endpoint identity staging file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync endpoint identity staging file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("protect endpoint identity staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close endpoint identity staging file: %w", err)
	}
	if err := root.Link(temporaryName, bundleName); err != nil {
		if _, statErr := root.Stat(bundleName); statErr == nil {
			return ErrExists
		}
		return fmt.Errorf("publish endpoint identity bundle: %w", err)
	}
	if err := root.Remove(temporaryName); err != nil {
		removeTemporary = false
		return rollbackPublished(root, parent, true, fmt.Errorf("remove endpoint identity staging file: %w", err))
	}
	removeTemporary = false
	if err := directorySync(root); err != nil {
		return rollbackPublished(root, parent, false, fmt.Errorf("sync endpoint identity directory: %w", err))
	}
	if err := directorySync(parent); err != nil {
		return rollbackPublished(root, parent, false, fmt.Errorf("sync endpoint identity parent directory: %w", err))
	}
	return nil
}

// Load reads and validates one complete identity bundle. Unknown files,
// permissive Linux modes, malformed credentials, and expired certificates fail
// closed before any material is returned.
func Load(directory string, now time.Time) (Loaded, error) {
	root, parent, err := openStore(directory, false)
	if err != nil {
		return Loaded{}, err
	}
	defer root.Close()
	defer parent.Close()

	entries, err := readEntries(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != bundleName {
		return Loaded{}, ErrCorrupt
	}
	info, err := root.Lstat(bundleName)
	if err != nil || !info.Mode().IsRegular() || !privateFile(info) || info.Size() < 1 || info.Size() > MaxBundleBytes {
		return Loaded{}, ErrCorrupt
	}
	file, err := root.Open(bundleName)
	if err != nil {
		return Loaded{}, fmt.Errorf("open endpoint identity bundle: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return Loaded{}, ErrCorrupt
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxBundleBytes+1))
	if err != nil {
		return Loaded{}, fmt.Errorf("read endpoint identity bundle: %w", err)
	}
	if len(raw) > MaxBundleBytes {
		return Loaded{}, ErrCorrupt
	}
	bundle, err := decodeBundle(raw)
	if err != nil {
		return Loaded{}, ErrCorrupt
	}
	material := Material{
		EndpointID:           bundle.EndpointID,
		ClientCertificatePEM: []byte(bundle.ClientCertificatePEM),
		PrivateKeyPEM:        []byte(bundle.PrivateKeyPEM),
		ServerRootsPEM:       []byte(bundle.ServerRootsPEM),
	}
	certificate, roots, err := validateMaterial(material, now)
	if err != nil {
		return Loaded{}, ErrCorrupt
	}
	return Loaded{EndpointID: material.EndpointID, Certificate: certificate, ServerRoots: roots}, nil
}

func openStore(directory string, create bool) (*os.Root, *os.Root, error) {
	clean := filepath.Clean(directory)
	volumeRoot := filepath.Clean(filepath.VolumeName(clean) + string(os.PathSeparator))
	if directory == "" || !filepath.IsAbs(directory) || clean != directory || clean == volumeRoot {
		return nil, nil, errors.New("endpoint identity directory must be a non-root absolute clean path")
	}
	parentPath := filepath.Dir(directory)
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("endpoint identity parent must be an existing real directory")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open endpoint identity parent: %w", err)
	}
	openedParentInfo, err := parent.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParentInfo) {
		parent.Close()
		return nil, nil, errors.New("endpoint identity parent changed while opening")
	}

	base := filepath.Base(directory)
	info, err := parent.Lstat(base)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := parent.Mkdir(base, 0o700); err != nil {
			parent.Close()
			return nil, nil, fmt.Errorf("create endpoint identity directory: %w", err)
		}
		if err := directorySync(parent); err != nil {
			parent.Close()
			return nil, nil, fmt.Errorf("sync endpoint identity parent: %w", err)
		}
		info, err = parent.Lstat(base)
	} else if err != nil {
		parent.Close()
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, ErrCorrupt
		}
		return nil, nil, fmt.Errorf("inspect endpoint identity directory: %w", err)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		parent.Close()
		return nil, nil, errors.New("endpoint identity path must be a real directory")
	}
	root, err := parent.OpenRoot(base)
	if err != nil {
		parent.Close()
		return nil, nil, fmt.Errorf("open endpoint identity directory: %w", err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(info, openedInfo) {
		root.Close()
		parent.Close()
		return nil, nil, errors.New("endpoint identity directory changed while opening")
	}
	if create {
		if err := root.Chmod(".", 0o700); err != nil {
			root.Close()
			parent.Close()
			return nil, nil, fmt.Errorf("protect endpoint identity directory: %w", err)
		}
		openedInfo, err = root.Stat(".")
	}
	if err != nil || !privateDirectory(openedInfo) {
		root.Close()
		parent.Close()
		return nil, nil, errors.New("endpoint identity directory permissions are not private")
	}
	return root, parent, nil
}

func readEntries(root *os.Root) ([]fs.DirEntry, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("list endpoint identity directory: %w", err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("list endpoint identity directory: %w", err)
	}
	if len(entries) > 1 {
		return nil, ErrCorrupt
	}
	return entries, nil
}

func rollbackPublished(root, parent *os.Root, removeTemporary bool, cause error) error {
	removeErr := root.Remove(bundleName)
	if errors.Is(removeErr, fs.ErrNotExist) {
		removeErr = nil
	}
	var removeTemporaryErr error
	if removeTemporary {
		removeTemporaryErr = root.Remove(temporaryName)
		if errors.Is(removeTemporaryErr, fs.ErrNotExist) {
			removeTemporaryErr = nil
		}
	}
	rootSyncErr := directorySync(root)
	parentSyncErr := directorySync(parent)
	if removeErr == nil && removeTemporaryErr == nil && rootSyncErr == nil && parentSyncErr == nil {
		return cause
	}
	return &InstallUncertainError{Cause: errors.Join(cause, removeErr, removeTemporaryErr, rootSyncErr, parentSyncErr)}
}

func decodeBundle(raw []byte) (wireBundle, error) {
	if err := strictjson.Validate(raw); err != nil {
		return wireBundle{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle wireBundle
	if err := decoder.Decode(&bundle); err != nil {
		return wireBundle{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return wireBundle{}, errors.New("endpoint identity bundle contains trailing data")
	}
	if bundle.SchemaVersion != SchemaVersion {
		return wireBundle{}, errors.New("unsupported endpoint identity schema")
	}
	return bundle, nil
}

func validateMaterial(material Material, now time.Time) (tls.Certificate, *x509.CertPool, error) {
	if !uuidPattern.MatchString(material.EndpointID) {
		return tls.Certificate{}, nil, errors.New("endpoint identity has an invalid endpoint ID")
	}
	if now.IsZero() {
		return tls.Certificate{}, nil, errors.New("endpoint identity validation time is required")
	}
	if len(material.ClientCertificatePEM) == 0 || len(material.ClientCertificatePEM) > maxClientCertificateBytes ||
		len(material.PrivateKeyPEM) == 0 || len(material.PrivateKeyPEM) > maxPrivateKeyBytes ||
		len(material.ServerRootsPEM) == 0 || len(material.ServerRootsPEM) > maxServerRootsBytes {
		return tls.Certificate{}, nil, errors.New("endpoint identity material is outside size limits")
	}
	clientCertificates, err := parseCertificates(material.ClientCertificatePEM, maxCertificateCount)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("endpoint client certificate PEM is invalid")
	}
	if err := validatePrivateKeyPEM(material.PrivateKeyPEM); err != nil {
		return tls.Certificate{}, nil, errors.New("endpoint private key PEM is invalid")
	}
	certificate, err := tls.X509KeyPair(material.ClientCertificatePEM, material.PrivateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New("endpoint certificate and private key do not form a valid pair")
	}
	if !supportedPrivateKey(certificate.PrivateKey) {
		return tls.Certificate{}, nil, errors.New("endpoint private key algorithm or strength is unsupported")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		!allowsClientAuthentication(leaf) || !matchesEndpointID(leaf, material.EndpointID) {
		return tls.Certificate{}, nil, errors.New("endpoint client certificate is invalid or not currently usable")
	}
	for index := 1; index < len(clientCertificates); index++ {
		issuer := clientCertificates[index]
		if !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) ||
			clientCertificates[index-1].CheckSignatureFrom(issuer) != nil {
			return tls.Certificate{}, nil, errors.New("endpoint client certificate chain is invalid")
		}
	}
	certificate.Leaf = leaf

	rootCertificates, err := parseCertificates(material.ServerRootsPEM, maxCertificateCount)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("server trust roots PEM is invalid")
	}
	roots := x509.NewCertPool()
	for _, root := range rootCertificates {
		if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
			return tls.Certificate{}, nil, errors.New("server trust root is not a certificate authority")
		}
		roots.AddCert(root)
	}
	return certificate, roots, nil
}

func validatePrivateKeyPEM(raw []byte) error {
	block, rest := pem.Decode(raw)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("private key must contain exactly one unadorned PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return nil
	default:
		return errors.New("unsupported private key PEM type")
	}
}

func parseCertificates(raw []byte, maxBlocks int) ([]*x509.Certificate, error) {
	rest := raw
	certificates := make([]*x509.Certificate, 0, maxBlocks)
	for len(bytes.TrimSpace(rest)) != 0 {
		if len(certificates) >= maxBlocks {
			return nil, errors.New("too many certificate PEM blocks")
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(remaining) >= len(rest) {
			return nil, errors.New("invalid certificate PEM block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		rest = remaining
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate PEM is empty")
	}
	return certificates, nil
}

func allowsClientAuthentication(certificate *x509.Certificate) bool {
	if len(certificate.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func matchesEndpointID(certificate *x509.Certificate, endpointID string) bool {
	return len(certificate.URIs) == 1 &&
		certificate.URIs[0].String() == "urn:northgate-rmm:endpoint:"+endpointID
}

func supportedPrivateKey(privateKey any) bool {
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		return len(key) == ed25519.PrivateKeySize
	case *ecdsa.PrivateKey:
		return key.Curve == elliptic.P256() || key.Curve == elliptic.P384()
	case *rsa.PrivateKey:
		return key.N != nil && key.N.BitLen() >= 2048
	default:
		return false
	}
}
