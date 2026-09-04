package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

const (
	messagePath       = "/v1/agent/messages"
	MaxResponseBytes  = 4 * 1024
	MaxRequestBytes   = 65_536
	minRequestTimeout = time.Second
	maxRequestTimeout = time.Minute
)

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	errRedirect     = errors.New("redirect refused")
	errInvalidTrust = errors.New("TLS trust validation failed")
)

// Credentials holds an already-enrolled endpoint certificate and its explicit
// server trust roots. Loading and protecting these values belongs to the
// separately qualified identity store; the sender accepts no key file paths.
type Credentials struct {
	Certificate tls.Certificate
	ServerRoots *x509.CertPool
}

// DeliveryError exposes a bounded diagnostic code and retry decision without
// including a URL, certificate, response body, or endpoint-controlled data.
type DeliveryError struct {
	Code      string
	Retryable bool
	Status    int
	cause     error
}

func (err *DeliveryError) Error() string {
	if err.Status != 0 {
		return fmt.Sprintf("agent delivery failed (%s, status %d)", err.Code, err.Status)
	}
	return fmt.Sprintf("agent delivery failed (%s)", err.Code)
}

func (err *DeliveryError) Unwrap() error { return err.cause }

// IsRetryable reports only the sender's explicit retry classification.
func IsRetryable(err error) bool {
	var deliveryError *DeliveryError
	return errors.As(err, &deliveryError) && deliveryError.Retryable
}

// MTLSSender sends one bounded message over a new TLS 1.3 connection. Connection
// reuse, redirects, environment proxies, compression, and TLS resumption are
// disabled so every attempt revalidates the exact server and client identities.
type MTLSSender struct {
	endpoint string
	client   *http.Client
}

type handshakeError struct{ cause error }

func (err *handshakeError) Error() string { return "TLS handshake failed" }
func (err *handshakeError) Unwrap() error { return err.cause }

// NewMTLSSender constructs a post-enrollment sender. The origin must be an HTTPS
// authority with no userinfo, query, fragment, or application path.
func NewMTLSSender(origin string, credentials Credentials, timeout time.Duration) (*MTLSSender, error) {
	parsed, err := validateOrigin(origin)
	if err != nil {
		return nil, err
	}
	if timeout < minRequestTimeout || timeout > maxRequestTimeout {
		return nil, errors.New("request timeout is outside the supported range")
	}
	if credentials.ServerRoots == nil {
		return nil, errors.New("explicit server trust roots are required")
	}
	if len(credentials.Certificate.Certificate) == 0 || credentials.Certificate.PrivateKey == nil {
		return nil, errors.New("endpoint certificate and private key are required")
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         parsed.Hostname(),
		RootCAs:            credentials.ServerRoots.Clone(),
		Certificates:       []tls.Certificate{credentials.Certificate},
		ClientSessionCache: nil,
	}
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        tlsConfig,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: MaxResponseBytes,
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		connection := tls.Client(raw, tlsConfig.Clone())
		if err := connection.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, &handshakeError{cause: err}
		}
		return connection, nil
	}
	parsed.Path = messagePath
	return &MTLSSender{
		endpoint: parsed.String(),
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errRedirect
			},
		},
	}, nil
}

func validateOrigin(origin string) (*url.URL, error) {
	if origin == "" || strings.ContainsAny(origin, "%#") {
		return nil, errors.New("control-plane origin is invalid")
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errors.New("control-plane origin must be absolute HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || strings.HasSuffix(parsed.Host, ":") {
		return nil, errors.New("control-plane origin contains unsupported components")
	}
	if !validAuthorityHostname(parsed.Hostname()) {
		return nil, errors.New("control-plane origin contains an invalid hostname")
	}
	if port := parsed.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, errors.New("control-plane origin contains an invalid port")
		}
	}
	return parsed, nil
}

func validAuthorityHostname(hostname string) bool {
	if net.ParseIP(hostname) != nil {
		return true
	}
	if len(hostname) == 0 || len(hostname) > 253 || strings.HasSuffix(hostname, ".") ||
		looksLikeLegacyIPv4(hostname) {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func looksLikeLegacyIPv4(hostname string) bool {
	for _, component := range strings.Split(hostname, ".") {
		if component == "" {
			return false
		}
		candidate := component
		base := byte(10)
		if len(candidate) > 2 && candidate[0] == '0' && (candidate[1] == 'x' || candidate[1] == 'X') {
			candidate = candidate[2:]
			base = 16
		}
		if candidate == "" {
			return false
		}
		for index := 0; index < len(candidate); index++ {
			character := candidate[index]
			decimal := character >= '0' && character <= '9'
			hexLetter := base == 16 && ((character >= 'a' && character <= 'f') ||
				(character >= 'A' && character <= 'F'))
			if !decimal && !hexLetter {
				return false
			}
		}
	}
	return true
}

type acknowledgement struct {
	MessageID string `json:"message_id"`
	Accepted  *bool  `json:"accepted"`
}

// Send transmits one message and succeeds only after an exact, bounded
// acknowledgement for the same message ID. A caller may remove the spool item
// only after this method returns nil.
func (sender *MTLSSender) Send(ctx context.Context, messageID string, payload []byte) error {
	if sender == nil || sender.client == nil {
		return &DeliveryError{Code: "sender_unavailable"}
	}
	if !uuidPattern.MatchString(messageID) {
		return &DeliveryError{Code: "invalid_message_id"}
	}
	if len(payload) == 0 || len(payload) > MaxRequestBytes {
		return &DeliveryError{Code: "invalid_payload_size"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sender.endpoint, bytes.NewReader(payload))
	if err != nil {
		return &DeliveryError{Code: "request_build_failed"}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Close = true

	response, err := sender.client.Do(request)
	if err != nil {
		return classifyNetworkError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &DeliveryError{
			Code:      "http_status",
			Retryable: retryableStatus(response.StatusCode),
			Status:    response.StatusCode,
		}
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	charset, hasCharset := parameters["charset"]
	if err != nil || mediaType != "application/json" || len(parameters) > 1 ||
		(hasCharset && !strings.EqualFold(charset, "utf-8")) {
		return &DeliveryError{Code: "invalid_response_type"}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		if callerErr := ctx.Err(); callerErr != nil {
			return &DeliveryError{Code: "request_stopped", cause: callerErr}
		}
		return &DeliveryError{Code: "response_read_failed", Retryable: true}
	}
	if len(raw) == 0 || len(raw) > MaxResponseBytes {
		return &DeliveryError{Code: "invalid_response_size"}
	}
	if err := strictjson.Validate(raw); err != nil {
		return &DeliveryError{Code: "invalid_acknowledgement"}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var ack acknowledgement
	if err := decoder.Decode(&ack); err != nil {
		return &DeliveryError{Code: "invalid_acknowledgement"}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return &DeliveryError{Code: "invalid_acknowledgement"}
	}
	if ack.MessageID != messageID {
		return &DeliveryError{Code: "acknowledgement_mismatch"}
	}
	if ack.Accepted == nil {
		return &DeliveryError{Code: "invalid_acknowledgement"}
	}
	if !*ack.Accepted {
		return &DeliveryError{Code: "acknowledgement_rejected"}
	}
	return nil
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func classifyNetworkError(ctx context.Context, err error) error {
	if callerErr := ctx.Err(); callerErr != nil {
		return &DeliveryError{Code: "request_stopped", cause: callerErr}
	}
	if errors.Is(err, errRedirect) {
		return &DeliveryError{Code: "request_stopped", cause: errRedirect}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &DeliveryError{Code: "request_timeout", Retryable: true}
	}
	var certificateError *tls.CertificateVerificationError
	var failedHandshake *handshakeError
	var alertError tls.AlertError
	var recordHeaderError tls.RecordHeaderError
	var hostnameError x509.HostnameError
	var authorityError x509.UnknownAuthorityError
	var rootsError x509.SystemRootsError
	if errors.As(err, &failedHandshake) && transientHandshakeError(failedHandshake.cause) {
		return &DeliveryError{Code: "network_failed", Retryable: true}
	}
	if errors.As(err, &failedHandshake) || errors.As(err, &certificateError) || errors.As(err, &alertError) ||
		errors.As(err, &recordHeaderError) || errors.As(err, &hostnameError) ||
		errors.As(err, &authorityError) || errors.As(err, &rootsError) {
		return &DeliveryError{Code: "tls_trust_failed", cause: errInvalidTrust}
	}
	return &DeliveryError{Code: "network_failed", Retryable: true}
}

func transientHandshakeError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var systemCallError *os.SyscallError
	var errorNumber syscall.Errno
	if errors.As(err, &systemCallError) || errors.As(err, &errorNumber) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
