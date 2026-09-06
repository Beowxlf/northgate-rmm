// Package management implements the explicitly privileged, signed-job worker.
package management

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var Version = "1.1.0-lab.2"

const MaxResult = 32 * 1024 * 1024
const MaxFile = 16 * 1024 * 1024
const MaxOutput = 512 * 1024

var ID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type Config struct {
	Endpoint     string `json:"endpoint_id"`
	Identity     string `json:"identity_id"`
	Signing      string `json:"signing_key"`
	Escrow       string `json:"escrow_key"`
	UpdateKey    string `json:"update_key"`
	UpdateSigner string `json:"update_signer"`
	Server       string `json:"server_url"`
	ServerIP     string `json:"server_ip"`
	Roots        string `json:"server_roots"`
	IdentityFile string `json:"identity_file"`
	Root         string `json:"state_directory"`
}
type Job struct {
	ID       string                     `json:"id"`
	Endpoint string                     `json:"endpoint"`
	Identity string                     `json:"identity"`
	Subject  string                     `json:"subject"`
	Session  string                     `json:"session"`
	Action   string                     `json:"action"`
	Expires  float64                    `json:"expires"`
	Exercise string                     `json:"exercise"`
	Params   map[string]json.RawMessage `json:"params"`
}
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Frame struct {
	Job      string `json:"job"`
	Sequence int    `json:"sequence"`
	Data     string `json:"data"`
}
type Input struct {
	Sequence int `json:"sequence"`
	Value    struct {
		Data    string `json:"data"`
		Columns int    `json:"columns"`
		Rows    int    `json:"rows"`
	} `json:"value"`
}
type Control struct {
	Job    string  `json:"job"`
	Cancel bool    `json:"cancel"`
	Lease  float64 `json:"lease"`
	Input  []Input `json:"input"`
}
type Response struct {
	Schema   int                 `json:"schema"`
	Endpoint string              `json:"endpoint"`
	Identity string              `json:"identity"`
	Nonce    string              `json:"nonce"`
	Expires  int64               `json:"expires"`
	Job      *Job                `json:"job"`
	Controls []Control           `json:"controls"`
	Acks     []string            `json:"acks"`
	FrameAck [][]json.RawMessage `json:"frame_ack"`
}
type Receipt struct {
	Job    string            `json:"job"`
	Sealed map[string]string `json:"sealed"`
}
type Result struct {
	State     string `json:"state"`
	Exit      int    `json:"exit_code"`
	Output    string `json:"output"`
	Identity  string `json:"execution_identity"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
}

func readBounded(path string, limit int64) ([]byte, error) {
	root, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer root.Close()
	info, e := root.Lstat(filepath.Base(path))
	if e != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid protected input")
	}
	f, e := root.Open(filepath.Base(path))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > int(limit) {
		return nil, errors.New("input too large")
	}
	return b, e
}
func loadConfig(path string) (Config, error) {
	var c Config
	b, e := readBounded(path, 16384)
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	u, e := url.Parse(c.Server)
	ip := net.ParseIP(c.ServerIP)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || ip == nil || !ip.IsPrivate() || ip.To4() == nil || !ID.MatchString(c.Endpoint) || !ID.MatchString(c.Identity) {
		return c, errors.New("invalid management configuration")
	}
	for _, k := range []string{c.Signing, c.Escrow, c.UpdateKey} {
		b, e := base64.StdEncoding.DecodeString(k)
		if e != nil || len(b) != 32 {
			return c, errors.New("invalid pinned key")
		}
	}
	for _, p := range []string{c.Root, c.IdentityFile, c.Roots} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("absolute protected paths required")
		}
	}
	return c, nil
}
func client(c Config) (*http.Client, error) {
	b, e := readBounded(c.IdentityFile, 128*1024)
	if e != nil {
		return nil, e
	}
	var material struct {
		Endpoint    string `json:"endpoint_id"`
		Certificate string `json:"client_certificate_pem"`
		Key         string `json:"private_key_pem"`
	}
	if e = json.Unmarshal(b, &material); e != nil || material.Endpoint != c.Endpoint {
		return nil, errors.New("enrollment mismatch")
	}
	cert, e := tls.X509KeyPair([]byte(material.Certificate), []byte(material.Key))
	if e != nil {
		return nil, e
	}
	roots, e := readBounded(c.Roots, 65536)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(roots) {
		return nil, errors.New("invalid server roots")
	}
	u, _ := url.Parse(c.Server)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: u.Hostname()}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxConnsPerHost: 2}
	dial := &net.Dialer{Timeout: 5 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(u.Hostname(), port) {
			return nil, errors.New("unexpected destination")
		}
		return dial.DialContext(ctx, network, net.JoinHostPort(c.ServerIP, port))
	}
	return &http.Client{Transport: transport, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}, nil
}
func verify(c Config, env Envelope, nonce string) (Response, error) {
	var response Response
	payload, e := base64.StdEncoding.DecodeString(env.Payload)
	if e != nil || len(payload) > MaxResult {
		return response, errors.New("invalid response")
	}
	sig, e := base64.StdEncoding.DecodeString(env.Signature)
	key, _ := base64.StdEncoding.DecodeString(c.Signing)
	if e != nil || !ed25519.Verify(key, append([]byte("NorthGate-Management-v1\x00"), payload...), sig) {
		return response, errors.New("invalid management signature")
	}
	if e = json.Unmarshal(payload, &response); e != nil {
		return response, e
	}
	now := time.Now().Unix()
	if response.Schema != 1 || response.Endpoint != c.Endpoint || response.Identity != c.Identity || response.Nonce != nonce || response.Expires < now || response.Expires > now+40 {
		return response, errors.New("expired or mismatched response")
	}
	if j := response.Job; j != nil {
		if !ID.MatchString(j.ID) || j.Endpoint != c.Endpoint || j.Identity != c.Identity || j.Subject == "" || j.Session == "" || j.Expires < float64(now) || j.Expires > float64(now+901) {
			return response, errors.New("invalid job binding")
		}
	}
	return response, nil
}
func encryptResult(c Config, job string, result Result) (Receipt, error) {
	receipt := Receipt{Job: job}
	pub, e := base64.StdEncoding.DecodeString(c.Escrow)
	if e != nil {
		return receipt, e
	}
	peer, e := ecdh.X25519().NewPublicKey(pub)
	if e != nil {
		return receipt, e
	}
	ephemeral, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return receipt, e
	}
	shared, e := ephemeral.ECDH(peer)
	if e != nil {
		return receipt, e
	}
	h := hmac.New(sha256.New, shared)
	h.Write([]byte("NorthGate-Receipt-v1"))
	block, e := aes.NewCipher(h.Sum(nil))
	if e != nil {
		return receipt, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return receipt, e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return receipt, e
	}
	raw, e := json.Marshal(result)
	if e != nil || len(raw) > MaxResult-1024 {
		return receipt, errors.New("receipt too large")
	}
	receipt.Sealed = map[string]string{"ephemeral": base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()), "nonce": base64.StdEncoding.EncodeToString(nonce), "body": base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, raw, []byte(job)))}
	return receipt, nil
}
