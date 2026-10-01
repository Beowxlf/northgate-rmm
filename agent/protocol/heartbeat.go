package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
	"io"
	"unicode/utf8"
)

type HeartbeatPayload struct {
	AgentVersion string   `json:"agent_version"`
	Capabilities []string `json:"capabilities"`
}
type HeartbeatMessage struct {
	Type     string           `json:"type"`
	Envelope Envelope         `json:"envelope"`
	Payload  HeartbeatPayload `json:"payload"`
}

func validateHeartbeat(p HeartbeatPayload) error {
	if !utf8.ValidString(p.AgentVersion) || len(p.AgentVersion) == 0 || len(p.AgentVersion) > 64 || len(p.Capabilities) > 32 || p.Capabilities == nil {
		return errors.New("invalid heartbeat payload")
	}
	for _, c := range p.Capabilities {
		if !utf8.ValidString(c) || len(c) == 0 || len(c) > 64 {
			return errors.New("invalid heartbeat capability")
		}
	}
	return nil
}
func EncodeHeartbeat(e Envelope, p HeartbeatPayload) ([]byte, error) {
	if err := validateEnvelope(e); err != nil {
		return nil, err
	}
	if err := validateHeartbeat(p); err != nil {
		return nil, err
	}
	return json.Marshal(HeartbeatMessage{Type: "heartbeat", Envelope: e, Payload: p})
}
func DecodeHeartbeat(raw []byte) (HeartbeatMessage, error) {
	var m HeartbeatMessage
	if len(raw) == 0 || len(raw) > MaxEncodedMessage || strictjson.Validate(raw) != nil {
		return m, errors.New("invalid heartbeat JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	var tail any
	if d.Decode(&tail) != io.EOF || m.Type != "heartbeat" {
		return m, errors.New("invalid heartbeat message")
	}
	if err := validateEnvelope(m.Envelope); err != nil {
		return m, err
	}
	return m, validateHeartbeat(m.Payload)
}

// DecodeMessage validates the complete message before exposing its envelope.
func DecodeMessage(raw []byte) (InventoryMessage, error) {
	var kind struct {
		Type string `json:"type"`
	}
	if len(raw) > MaxEncodedMessage || json.Unmarshal(raw, &kind) != nil {
		return InventoryMessage{}, errors.New("invalid message")
	}
	if kind.Type == "heartbeat" {
		m, err := DecodeHeartbeat(raw)
		return InventoryMessage{Type: m.Type, Envelope: m.Envelope}, err
	}
	return DecodeInventory(raw)
}
