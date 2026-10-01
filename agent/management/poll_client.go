package management

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"
)

// pollClient is used only by the serial poll loop. Protected credential files
// are still read each poll: replacement, removal or corruption must immediately
// retire the old connection, including when the replacement cannot be parsed.
type pollClient struct {
	client          *http.Client
	config          Config
	identity, roots [32]byte
	created         time.Time
	validity        *certificateWindow
}

type certificateWindow struct {
	mu            sync.Mutex
	after, before time.Time
}

func (v *certificateWindow) include(certificates []*x509.Certificate) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, cert := range certificates {
		if cert.NotBefore.After(v.after) {
			v.after = cert.NotBefore
		}
		if v.before.IsZero() || cert.NotAfter.Before(v.before) {
			v.before = cert.NotAfter
		}
	}
}

func (v *certificateWindow) valid(now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return !now.Before(v.after) && (v.before.IsZero() || now.Before(v.before))
}

func (p *pollClient) close() {
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
	p.client = nil
}

func (p *pollClient) get(c Config) (*http.Client, error) {
	identity, err := readBounded(c.IdentityFile, 128*1024)
	if err != nil {
		p.close()
		return nil, err
	}
	roots, err := readBounded(c.Roots, 65536)
	if err != nil {
		p.close()
		return nil, err
	}
	iHash, rHash, now := sha256.Sum256(identity), sha256.Sum256(roots), time.Now()
	if p.client != nil && p.config == c && p.identity == iHash && p.roots == rHash && now.Sub(p.created) < 5*time.Minute && p.validity.valid(now) {
		return p.client, nil
	}
	p.close()
	client, err := clientWithMaterial(c, identity, roots)
	if err != nil {
		return nil, err
	}
	window := &certificateWindow{}
	transport := client.Transport.(*http.Transport)
	for _, cert := range transport.TLSClientConfig.Certificates {
		for _, der := range cert.Certificate {
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				client.CloseIdleConnections()
				return nil, err
			}
			window.include([]*x509.Certificate{parsed})
		}
	}
	if !window.valid(now) {
		client.CloseIdleConnections()
		return nil, errors.New("client certificate outside validity period")
	}
	// Normal TLS verification runs first. Also retain chain validity boundaries
	// so a persistent connection cannot silently outlive a certificate.
	transport.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
		for _, chain := range state.VerifiedChains {
			window.include(chain)
		}
		return nil
	}
	p.client, p.config, p.identity, p.roots, p.created, p.validity = client, c, iHash, rHash, now, window
	return client, nil
}
