package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testEndpointID = "123e4567-e89b-42d3-a456-426614174000"

func TestInstallAndLoadIdentity(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	material := syntheticMaterial(t, now)
	parent := t.TempDir()
	directory := filepath.Join(parent, "identity")

	if err := Install(directory, material, now); err != nil {
		t.Fatalf("install identity: %v", err)
	}
	loaded, err := Load(directory, now)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if loaded.EndpointID != testEndpointID {
		t.Fatalf("unexpected endpoint ID: %q", loaded.EndpointID)
	}
	if loaded.Certificate.Leaf == nil || loaded.Certificate.Leaf.Subject.CommonName != "synthetic-endpoint" {
		t.Fatal("client certificate leaf was not parsed")
	}
	if loaded.Certificate.PrivateKey == nil || len(loaded.Certificate.Certificate) != 2 {
		t.Fatal("client certificate chain or private key missing")
	}
	expectedRoots := x509.NewCertPool()
	rootBlock, _ := pem.Decode(material.ServerRootsPEM)
	rootCertificate, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	expectedRoots.AddCert(rootCertificate)
	if loaded.ServerRoots == nil || !loaded.ServerRoots.Equal(expectedRoots) {
		t.Fatal("explicit server trust root missing")
	}
	if err := Install(directory, syntheticMaterial(t, now), now); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate install error = %v, want ErrExists", err)
	}
	reloaded, err := Load(directory, now)
	if err != nil || reloaded.EndpointID != testEndpointID {
		t.Fatalf("identity changed after duplicate install: %v", err)
	}

	if runtime.GOOS != "windows" {
		directoryInfo, err := os.Stat(directory)
		if err != nil || directoryInfo.Mode().Perm() != 0o700 {
			t.Fatalf("identity directory mode = %v, err = %v", directoryInfo.Mode().Perm(), err)
		}
		fileInfo, err := os.Stat(filepath.Join(directory, bundleName))
		if err != nil || fileInfo.Mode().Perm() != 0o600 {
			t.Fatalf("identity file mode = %v, err = %v", fileInfo.Mode().Perm(), err)
		}
	}
}

func TestInstallRejectsInvalidMaterial(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	valid := syntheticMaterial(t, now)
	other := syntheticMaterial(t, now)
	tests := []struct {
		name   string
		mutate func(*Material)
	}{
		{"invalid endpoint ID", func(item *Material) { item.EndpointID = "host-name" }},
		{"empty certificate", func(item *Material) { item.ClientCertificatePEM = nil }},
		{"mismatched key", func(item *Material) { item.PrivateKeyPEM = other.PrivateKeyPEM }},
		{"certificate garbage", func(item *Material) {
			item.ClientCertificatePEM = append(item.ClientCertificatePEM, []byte("garbage")...)
		}},
		{"key garbage", func(item *Material) { item.PrivateKeyPEM = append(item.PrivateKeyPEM, []byte("garbage")...) }},
		{"key headers", func(item *Material) {
			block, _ := pem.Decode(item.PrivateKeyPEM)
			block.Headers = map[string]string{"Comment": "not allowed"}
			item.PrivateKeyPEM = pem.EncodeToMemory(block)
		}},
		{"unsupported key block", func(item *Material) {
			block, _ := pem.Decode(item.PrivateKeyPEM)
			block.Type = "OPENSSH PRIVATE KEY"
			item.PrivateKeyPEM = pem.EncodeToMemory(block)
		}},
		{"root garbage", func(item *Material) { item.ServerRootsPEM = append(item.ServerRootsPEM, []byte("garbage")...) }},
		{"too many roots", func(item *Material) {
			item.ServerRootsPEM = bytesRepeat(item.ServerRootsPEM, maxCertificateCount+1)
		}},
		{"oversized roots", func(item *Material) { item.ServerRootsPEM = make([]byte, maxServerRootsBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material := cloneMaterial(valid)
			test.mutate(&material)
			directory := filepath.Join(t.TempDir(), "identity")
			if err := Install(directory, material, now); err == nil {
				t.Fatal("invalid material was accepted")
			}
			if _, err := os.Stat(filepath.Join(directory, bundleName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid material created a bundle: %v", err)
			}
		})
	}
	if err := Install(filepath.Join(t.TempDir(), "identity"), valid, time.Time{}); err == nil {
		t.Fatal("zero validation time was accepted")
	}
}

func TestInstallRejectsUnusableCertificates(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		clientUsage []x509.ExtKeyUsage
		clientCA    bool
		rootCA      bool
		notBefore   time.Time
		notAfter    time.Time
	}{
		{"expired", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, true, now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"not yet valid", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, true, now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"server only", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, true, now.Add(-time.Hour), now.Add(time.Hour)},
		{"client is CA", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true, true, now.Add(-time.Hour), now.Add(time.Hour)},
		{"root is not CA", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, false, now.Add(-time.Hour), now.Add(time.Hour)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material := customMaterial(t, test.notBefore, test.notAfter, test.clientUsage, test.clientCA, test.rootCA)
			if err := Install(filepath.Join(t.TempDir(), "identity"), material, now); err == nil {
				t.Fatal("unusable certificate material was accepted")
			}
		})
	}
}

func TestInstallRejectsEndpointBindingAndChainMismatch(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	mismatchedBinding := customMaterialWithBinding(
		t,
		now.Add(-time.Hour),
		now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		false,
		true,
		"123e4567-e89b-42d3-a456-426614174001",
	)
	if err := Install(filepath.Join(t.TempDir(), "identity"), mismatchedBinding, now); err == nil {
		t.Fatal("mismatched endpoint certificate URI was accepted")
	}

	material := syntheticMaterial(t, now)
	other := syntheticMaterial(t, now)
	leaf, _ := pem.Decode(material.ClientCertificatePEM)
	_, otherIssuerPEM := pem.Decode(other.ClientCertificatePEM)
	otherIssuer, _ := pem.Decode(otherIssuerPEM)
	material.ClientCertificatePEM = append(
		pem.EncodeToMemory(leaf),
		pem.EncodeToMemory(otherIssuer)...,
	)
	if err := Install(filepath.Join(t.TempDir(), "identity"), material, now); err == nil {
		t.Fatal("mismatched client certificate chain was accepted")
	}
}

func TestInstallRejectsIncompatibleExtendedKeyUsage(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	unknownUsage := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1}}
	unknownClient := customMaterialWithUsages(
		t,
		now.Add(-time.Hour),
		now.Add(time.Hour),
		[]x509.ExtKeyUsage(nil),
		unknownUsage,
		nil,
		false,
		true,
		testEndpointID,
		nil,
		nil,
		nil,
	)
	if err := Install(filepath.Join(t.TempDir(), "identity"), unknownClient, now); err == nil {
		t.Fatal("unknown-only client EKU was accepted")
	}

	clientOnlyRoot := customMaterialWithUsages(
		t,
		now.Add(-time.Hour),
		now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil,
		nil,
		false,
		true,
		testEndpointID,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil,
		nil,
	)
	if err := Install(filepath.Join(t.TempDir(), "identity"), clientOnlyRoot, now); err == nil {
		t.Fatal("server root restricted to client authentication was accepted")
	}
}

func TestInstallRejectsRestrictedIssuerAndUnhandledCriticalRoot(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	restrictedIssuer := customMaterialWithUsages(
		t,
		now.Add(-time.Hour),
		now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		false,
		true,
		testEndpointID,
		nil,
		nil,
		nil,
	)
	if err := Install(filepath.Join(t.TempDir(), "identity"), restrictedIssuer, now); err == nil {
		t.Fatal("client issuer restricted to server authentication was accepted")
	}

	criticalExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2},
		Critical: true,
		Value:    []byte{5, 0},
	}
	criticalRoot := customMaterialWithUsages(
		t,
		now.Add(-time.Hour),
		now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil,
		nil,
		false,
		true,
		testEndpointID,
		nil,
		nil,
		[]pkix.Extension{criticalExtension},
	)
	if err := Install(filepath.Join(t.TempDir(), "identity"), criticalRoot, now); err == nil {
		t.Fatal("server root with an unhandled critical extension was accepted")
	}
}

func TestLoadFailsClosedOnStoreTampering(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"unknown file", func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing bundle", func(t *testing.T, directory string) {
			if err := os.Remove(filepath.Join(directory, bundleName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated JSON", func(t *testing.T, directory string) {
			writeBundle(t, directory, []byte(`{"schema_version":1`))
		}},
		{"invalid UTF-8", func(t *testing.T, directory string) {
			writeBundle(t, directory, []byte{'{', '"', 0xff, '"', ':', '1', '}'})
		}},
		{"unsupported schema", func(t *testing.T, directory string) {
			raw := readBundle(t, directory)
			raw = []byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":2`, 1))
			writeBundle(t, directory, raw)
		}},
		{"trailing value", func(t *testing.T, directory string) {
			raw := append(readBundle(t, directory), []byte(` true`)...)
			writeBundle(t, directory, raw)
		}},
		{"unknown field", func(t *testing.T, directory string) {
			raw := readBundle(t, directory)
			raw = append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
			writeBundle(t, directory, raw)
		}},
		{"duplicate field", func(t *testing.T, directory string) {
			raw := readBundle(t, directory)
			raw = append([]byte(`{"schema_version":1,`), raw[1:]...)
			writeBundle(t, directory, raw)
		}},
		{"invalid endpoint", func(t *testing.T, directory string) {
			raw := readBundle(t, directory)
			raw = []byte(strings.Replace(string(raw), testEndpointID, "not-an-endpoint", 1))
			writeBundle(t, directory, raw)
		}},
		{"staging file", func(t *testing.T, directory string) {
			if err := os.Rename(filepath.Join(directory, bundleName), filepath.Join(directory, temporaryName)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "identity")
			if err := Install(directory, syntheticMaterial(t, now), now); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, directory)
			if _, err := Load(directory, now); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("load error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestInstallFailsClosedOnNonemptyOrInvalidPaths(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	material := syntheticMaterial(t, now)

	parent := t.TempDir()
	directory := filepath.Join(parent, "identity")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Install(directory, material, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("nonempty install error = %v, want ErrCorrupt", err)
	}
	malformedDirectory := filepath.Join(parent, "malformed")
	if err := os.Mkdir(malformedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(malformedDirectory, bundleName), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Install(malformedDirectory, material, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("malformed existing store error = %v, want ErrCorrupt", err)
	}

	missingParent := filepath.Join(parent, "missing", "identity")
	if err := Install(missingParent, material, now); err == nil {
		t.Fatal("missing parent was accepted")
	}
	filePath := filepath.Join(parent, "file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Install(filePath, material, now); err == nil {
		t.Fatal("regular-file identity path was accepted")
	}
	if err := Install(string(os.PathSeparator), material, now); err == nil {
		t.Fatal("filesystem root was accepted")
	}
}

func TestInstallRollsBackDirectorySyncFailure(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	material := syntheticMaterial(t, now)
	parent := t.TempDir()
	directory := filepath.Join(parent, "identity")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	originalSync := directorySync
	t.Cleanup(func() { directorySync = originalSync })
	calls := 0
	injected := errors.New("injected sync failure")
	directorySync = func(root *os.Root) error {
		calls++
		if calls == 1 {
			return injected
		}
		return originalSync(root)
	}
	err := Install(directory, material, now)
	if !errors.Is(err, injected) {
		t.Fatalf("install error = %v, want injected failure", err)
	}
	var uncertain *InstallUncertainError
	if errors.As(err, &uncertain) {
		t.Fatalf("clean rollback was reported uncertain: %v", err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("rollback left files: entries=%v err=%v", entries, readErr)
	}
}

func TestInstallReportsUncertainRollbackDurability(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	material := syntheticMaterial(t, now)
	parent := t.TempDir()
	directory := filepath.Join(parent, "identity")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	originalSync := directorySync
	t.Cleanup(func() { directorySync = originalSync })
	injected := errors.New("injected persistent sync failure")
	directorySync = func(*os.Root) error { return injected }
	err := Install(directory, material, now)
	var uncertain *InstallUncertainError
	if !errors.As(err, &uncertain) || !errors.Is(err, injected) {
		t.Fatalf("install error = %v, want typed uncertainty with cause", err)
	}
	if got := uncertain.Error(); got != "endpoint identity install outcome is uncertain" {
		t.Fatalf("uncertain error leaked detail: %q", got)
	}
}

func TestLoadFailsClosedOnPathAndPermissionProblems(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	if _, err := Load("relative", now); err == nil {
		t.Fatal("relative path was accepted")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing"), now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing store error = %v, want ErrCorrupt", err)
	}

	parent := t.TempDir()
	realDirectory := filepath.Join(parent, "real")
	if err := Install(realDirectory, syntheticMaterial(t, now), now); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(parent, "link")
	if err := os.Symlink(realDirectory, symlink); err == nil {
		if _, err := Load(symlink, now); err == nil {
			t.Fatal("symlinked identity directory was accepted")
		}
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(realDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(realDirectory, now); err == nil {
			t.Fatal("permissive identity directory was accepted")
		}
		if err := os.Chmod(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(realDirectory, bundleName), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(realDirectory, now); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("permissive file error = %v, want ErrCorrupt", err)
		}
	}
}

func TestLoadRejectsCertificateAfterExpiry(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	directory := filepath.Join(t.TempDir(), "identity")
	if err := Install(directory, syntheticMaterial(t, now), now); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(directory, now.Add(25*time.Hour)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expired load error = %v, want ErrCorrupt", err)
	}
}

func syntheticMaterial(t *testing.T, now time.Time) Material {
	t.Helper()
	return customMaterial(
		t,
		now.Add(-time.Hour),
		now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		false,
		true,
	)
}

func customMaterial(
	t *testing.T,
	notBefore time.Time,
	notAfter time.Time,
	clientUsage []x509.ExtKeyUsage,
	clientCA bool,
	rootCA bool,
) Material {
	return customMaterialWithBinding(t, notBefore, notAfter, clientUsage, clientCA, rootCA, testEndpointID)
}

func customMaterialWithBinding(
	t *testing.T,
	notBefore time.Time,
	notAfter time.Time,
	clientUsage []x509.ExtKeyUsage,
	clientCA bool,
	rootCA bool,
	binding string,
) Material {
	return customMaterialWithUsages(
		t,
		notBefore,
		notAfter,
		clientUsage,
		nil,
		nil,
		clientCA,
		rootCA,
		binding,
		nil,
		nil,
		nil,
	)
}

func customMaterialWithUsages(
	t *testing.T,
	notBefore time.Time,
	notAfter time.Time,
	clientUsage []x509.ExtKeyUsage,
	clientUnknownUsage []asn1.ObjectIdentifier,
	clientIssuerUsage []x509.ExtKeyUsage,
	clientCA bool,
	rootCA bool,
	binding string,
	rootUsage []x509.ExtKeyUsage,
	rootUnknownUsage []asn1.ObjectIdentifier,
	rootExtraExtensions []pkix.Extension,
) Material {
	t.Helper()
	clientCAPublic, clientCAPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCATemplate := certificateTemplate("synthetic-client-ca", notBefore.Add(-time.Hour), notAfter.Add(time.Hour), true)
	clientCATemplate.ExtKeyUsage = clientIssuerUsage
	clientCADER := createCertificate(t, clientCATemplate, clientCATemplate, clientCAPublic, clientCAPrivate)

	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := certificateTemplate("synthetic-endpoint", notBefore, notAfter, clientCA)
	clientTemplate.ExtKeyUsage = clientUsage
	clientTemplate.UnknownExtKeyUsage = clientUnknownUsage
	endpointURI, err := url.Parse("urn:northgate-rmm:endpoint:" + binding)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate.URIs = []*url.URL{endpointURI}
	clientDER := createCertificate(t, clientTemplate, clientCATemplate, clientPublic, clientCAPrivate)
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}

	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := certificateTemplate("synthetic-server-root", notBefore.Add(-time.Hour), notAfter.Add(time.Hour), rootCA)
	rootTemplate.ExtKeyUsage = rootUsage
	rootTemplate.UnknownExtKeyUsage = rootUnknownUsage
	rootTemplate.ExtraExtensions = rootExtraExtensions
	rootDER := createCertificate(t, rootTemplate, rootTemplate, rootPublic, rootPrivate)

	return Material{
		EndpointID: testEndpointID,
		ClientCertificatePEM: append(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCADER})...,
		),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}),
		ServerRootsPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
	}
}

func certificateTemplate(commonName string, notBefore, notAfter time.Time, isCA bool) *x509.Certificate {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	return template
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, public, signer any) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func cloneMaterial(material Material) Material {
	return Material{
		EndpointID:           material.EndpointID,
		ClientCertificatePEM: append([]byte(nil), material.ClientCertificatePEM...),
		PrivateKeyPEM:        append([]byte(nil), material.PrivateKeyPEM...),
		ServerRootsPEM:       append([]byte(nil), material.ServerRootsPEM...),
	}
}

func bytesRepeat(raw []byte, count int) []byte {
	result := make([]byte, 0, len(raw)*count)
	for index := 0; index < count; index++ {
		result = append(result, raw...)
	}
	return result
}

func readBundle(t *testing.T, directory string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, bundleName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeBundle(t *testing.T, directory string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, bundleName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWireBundleDoesNotAccidentallyExposeJSONObjects(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	material := syntheticMaterial(t, now)
	directory := filepath.Join(t.TempDir(), "identity")
	if err := Install(directory, material, now); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(readBundle(t, directory), &document); err != nil {
		t.Fatal(err)
	}
	if len(document) != 5 {
		t.Fatalf("wire field count = %d, want 5", len(document))
	}
	for _, field := range []string{"client_certificate_pem", "private_key_pem", "server_roots_pem"} {
		if _, ok := document[field].(string); !ok {
			t.Fatalf("%s is not an opaque string", field)
		}
	}
}
