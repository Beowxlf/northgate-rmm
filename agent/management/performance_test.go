package management

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func performanceServer(t testing.TB) (Config, *atomic.Int64, *atomic.Bool) {
	t.Helper()
	var connections atomic.Int64
	var revoked atomic.Bool
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() {
			w.WriteHeader(http.StatusForbidden)
		}
		_, _ = w.Write([]byte("{}"))
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	cert := s.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	c := Config{Endpoint: "11111111-1111-4111-8111-111111111111", Server: s.URL, ServerIP: "127.0.0.1", IdentityFile: filepath.Join(root, "identity.json"), Roots: filepath.Join(root, "roots.pem")}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	material, _ := json.Marshal(map[string]string{"endpoint_id": c.Endpoint, "client_certificate_pem": string(certificate), "private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))})
	if err = os.WriteFile(c.IdentityFile, material, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.Roots, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	return c, &connections, &revoked
}

func requestPerformance(t testing.TB, client *http.Client, url string) int {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func TestPollConnectionReuseRotationAndRevocation(t *testing.T) {
	c, connections, revoked := performanceServer(t)
	var cache pollClient
	defer cache.close()
	for range 10 {
		client, err := cache.get(c)
		if err != nil {
			t.Fatal(err)
		}
		if requestPerformance(t, client, c.Server) != 200 {
			t.Fatal("request failed")
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("idle polls opened %d connections", connections.Load())
	}
	revoked.Store(true)
	current, err := cache.get(c)
	if err != nil {
		t.Fatal(err)
	}
	if requestPerformance(t, current, c.Server) != 403 {
		t.Fatal("reuse bypassed application revocation")
	}
	revoked.Store(false)
	roots, _ := os.ReadFile(c.Roots)
	if err = os.WriteFile(c.Roots, append(roots, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	rotated, err := cache.get(c)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == current {
		t.Fatal("trust change retained old connection")
	}
	requestPerformance(t, rotated, c.Server)
	if connections.Load() != 2 {
		t.Fatal("trust change did not establish new TLS")
	}
	cache.validity.mu.Lock()
	cache.validity.before = time.Now().Add(-time.Second)
	cache.validity.mu.Unlock()
	refreshed, err := cache.get(c)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed == rotated {
		t.Fatal("expired peer chain retained")
	}
	if err = os.WriteFile(c.IdentityFile, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = cache.get(c); err == nil || cache.client != nil {
		t.Fatal("bad credential update retained old identity")
	}
}

func TestVersionCacheDetectsChangesAndRetriesFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	var cache versionCache
	calls := 0
	probe := func(string) string { calls++; return "1.0.0" }
	for range 10 {
		if cache.get(path, probe) != "1.0.0" {
			t.Fatal("missing version")
		}
	}
	if calls != 1 {
		t.Fatal("unchanged binary repeatedly spawned")
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	cache.get(path, probe)
	if calls != 2 {
		t.Fatal("changed binary remained cached")
	}
	entry := cache.entries[path]
	entry.checked = time.Now().Add(-time.Minute)
	cache.entries[path] = entry
	cache.get(path, probe)
	if calls != 3 {
		t.Fatal("old result remained cached")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if cache.get(path, probe) != "" {
		t.Fatal("removed component remained installed")
	}
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		cache.get(path, func(string) string { calls++; return "" })
	}
	if calls != 5 {
		t.Fatal("failed version lookup did not retry")
	}
}

func BenchmarkManagementPollHTTPS(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		name := "fresh"
		if reuse {
			name = "reused"
		}
		b.Run(name, func(b *testing.B) {
			c, connections, _ := performanceServer(b)
			var cache pollClient
			defer cache.close()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var current *http.Client
				var err error
				if reuse {
					current, err = cache.get(c)
				} else {
					current, err = client(c)
				}
				if err != nil {
					b.Fatal(err)
				}
				requestPerformance(b, current, c.Server)
				if !reuse {
					current.CloseIdleConnections()
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(connections.Load())/float64(b.N), "connections/op")
		})
	}
}
