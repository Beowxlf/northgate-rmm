package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestHeartbeatRoundTripAndStrictEnvelope(t *testing.T) {
	e := Envelope{MessageID: "123e4567-e89b-42d3-a456-426614174001", EndpointID: "123e4567-e89b-42d3-a456-426614174002", BootID: "123e4567-e89b-42d3-a456-426614174003", CorrelationID: "123e4567-e89b-42d3-a456-426614174004", Sequence: 1, ProtocolVersion: Version, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	raw, err := EncodeHeartbeat(e, HeartbeatPayload{AgentVersion: "1.0.0", Capabilities: []string{"inventory"}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeMessage(raw)
	if err != nil || m.Type != "heartbeat" || m.Envelope.Sequence != 1 {
		t.Fatalf("decode: %#v %v", m, err)
	}
	for _, bad := range [][]byte{append(raw, []byte("{}")...), bytes.Replace(raw, []byte(`"capabilities":["inventory"]`), []byte(`"capabilities":null`), 1), bytes.Replace(raw, []byte(`"agent_version":"1.0.0"`), []byte(`"agent_version":"1.0.0","extra":true`), 1)} {
		if _, err := DecodeMessage(bad); err == nil {
			t.Fatal("accepted malformed heartbeat")
		}
	}
}
