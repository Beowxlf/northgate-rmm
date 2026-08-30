// Package protocol defines the language-neutral Phase 1-compatible inventory
// envelope emitted by the Phase 2 agent core.
package protocol

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	Version                  = 1
	InventorySchema          = 1
	MaxSequence        int64 = (1 << 63) - 1
	MaxMessageTTL            = 5 * time.Minute
	MaxFields                = 128
	MaxFieldKeyBytes         = 64
	MaxFieldValueBytes       = 512
	MaxEncodedMessage        = 65_536
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Envelope struct {
	MessageID       string    `json:"message_id"`
	EndpointID      string    `json:"endpoint_id"`
	BootID          string    `json:"boot_id"`
	Sequence        int64     `json:"sequence"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	CorrelationID   string    `json:"correlation_id"`
	ProtocolVersion int       `json:"protocol_version"`
}

type InventoryPayload struct {
	Platform          string            `json:"platform"`
	Architecture      string            `json:"architecture"`
	Fields            map[string]string `json:"fields"`
	CollectorComplete bool              `json:"collector_complete"`
	SchemaVersion     int               `json:"schema_version"`
}

type InventoryMessage struct {
	Type     string           `json:"type"`
	Envelope Envelope         `json:"envelope"`
	Payload  InventoryPayload `json:"payload"`
}

// EncodeInventory validates and encodes exactly the schema accepted by the
// Phase 1 control-plane codec.
func EncodeInventory(envelope Envelope, payload InventoryPayload) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	message := InventoryMessage{Type: "inventory", Envelope: envelope, Payload: payload}
	raw, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxEncodedMessage {
		return nil, errors.New("encoded inventory exceeds message size limit")
	}
	return raw, nil
}

func validateEnvelope(envelope Envelope) error {
	if !uuidPattern.MatchString(envelope.MessageID) ||
		!uuidPattern.MatchString(envelope.EndpointID) ||
		!uuidPattern.MatchString(envelope.BootID) ||
		!uuidPattern.MatchString(envelope.CorrelationID) {
		return errors.New("envelope identifiers must be canonical lowercase UUIDs")
	}
	if envelope.ProtocolVersion != Version {
		return errors.New("unsupported protocol version")
	}
	if envelope.Sequence < 1 || envelope.Sequence > MaxSequence {
		return errors.New("sequence is outside the supported range")
	}
	if envelope.CreatedAt.IsZero() || envelope.ExpiresAt.IsZero() {
		return errors.New("message timestamps are required")
	}
	_, createdOffset := envelope.CreatedAt.Zone()
	_, expiresOffset := envelope.ExpiresAt.Zone()
	if createdOffset != 0 || expiresOffset != 0 {
		return errors.New("message timestamps must use UTC")
	}
	ttl := envelope.ExpiresAt.Sub(envelope.CreatedAt)
	if ttl <= 0 || ttl > MaxMessageTTL {
		return errors.New("message lifetime is invalid")
	}
	return nil
}

func validatePayload(payload InventoryPayload) error {
	if payload.Platform != "linux" {
		return errors.New("inventory platform is unsupported")
	}
	if payload.Architecture == "" || len(payload.Architecture) > 32 {
		return errors.New("inventory architecture is invalid")
	}
	if payload.SchemaVersion != InventorySchema {
		return errors.New("unsupported inventory schema version")
	}
	if len(payload.Fields) > MaxFields {
		return errors.New("too many inventory fields")
	}
	for key, value := range payload.Fields {
		if key == "" || len(key) > MaxFieldKeyBytes || len(value) > MaxFieldValueBytes ||
			!utf8.ValidString(key) || !utf8.ValidString(value) {
			return errors.New("inventory field is empty or too long")
		}
	}
	return nil
}
