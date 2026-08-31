package identity

import (
	"encoding/json"
	"testing"
)

func FuzzDecodeBundle(f *testing.F) {
	seed, err := json.Marshal(wireBundle{
		SchemaVersion:        SchemaVersion,
		EndpointID:           testEndpointID,
		ClientCertificatePEM: "synthetic-certificate",
		PrivateKeyPEM:        "synthetic-private-key",
		ServerRootsPEM:       "synthetic-root",
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxBundleBytes+1 {
			t.Skip()
		}
		_, _ = decodeBundle(raw)
	})
}
