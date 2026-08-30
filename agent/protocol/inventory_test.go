package protocol

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func validEnvelope() Envelope {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	return Envelope{
		MessageID:       "123e4567-e89b-42d3-a456-426614174000",
		EndpointID:      "123e4567-e89b-42d3-a456-426614174001",
		BootID:          "123e4567-e89b-42d3-a456-426614174002",
		Sequence:        1,
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Minute),
		CorrelationID:   "123e4567-e89b-42d3-a456-426614174003",
		ProtocolVersion: Version,
	}
}

func validPayload() InventoryPayload {
	return InventoryPayload{
		Platform:          "linux",
		Architecture:      "amd64",
		Fields:            map[string]string{"os.id": "debian"},
		CollectorComplete: true,
		SchemaVersion:     InventorySchema,
	}
}

func TestEncodeInventoryMatchesPhaseOneShape(t *testing.T) {
	raw, err := EncodeInventory(validEnvelope(), validPayload())
	if err != nil {
		t.Fatalf("EncodeInventory() error = %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if root["type"] != "inventory" || len(root) != 3 {
		t.Fatalf("unexpected message shape: %s", raw)
	}
}

func TestEncodeInventoryMatchesSharedContractFixture(t *testing.T) {
	raw, err := EncodeInventory(validEnvelope(), validPayload())
	if err != nil {
		t.Fatalf("EncodeInventory() error = %v", err)
	}
	fixture, err := os.ReadFile("../../tests/fixtures/agent_inventory_v1.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(raw, bytes.TrimSpace(fixture)) {
		t.Fatalf("encoded inventory does not match shared fixture\ngot:  %s\nwant: %s", raw, fixture)
	}
}

func FuzzEncodeInventoryFields(f *testing.F) {
	f.Add("os.id", "debian")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, key, value string) {
		payload := validPayload()
		payload.Fields = map[string]string{key: value}
		_, _ = EncodeInventory(validEnvelope(), payload)
	})
}

func TestEncodeInventoryRejectsInvalidEnvelopeAndPayload(t *testing.T) {
	t.Run("bad id", func(t *testing.T) {
		envelope := validEnvelope()
		envelope.EndpointID = "host-1"
		if _, err := EncodeInventory(envelope, validPayload()); err == nil {
			t.Fatal("EncodeInventory() accepted invalid endpoint ID")
		}
	})
	t.Run("long ttl", func(t *testing.T) {
		envelope := validEnvelope()
		envelope.ExpiresAt = envelope.CreatedAt.Add(MaxMessageTTL + time.Second)
		if _, err := EncodeInventory(envelope, validPayload()); err == nil {
			t.Fatal("EncodeInventory() accepted long TTL")
		}
	})
	t.Run("non UTC", func(t *testing.T) {
		envelope := validEnvelope()
		offset := time.FixedZone("test", 3600)
		envelope.CreatedAt = envelope.CreatedAt.In(offset)
		envelope.ExpiresAt = envelope.ExpiresAt.In(offset)
		if _, err := EncodeInventory(envelope, validPayload()); err == nil {
			t.Fatal("EncodeInventory() accepted non-UTC timestamps")
		}
	})
	t.Run("long field", func(t *testing.T) {
		payload := validPayload()
		payload.Fields["value"] = strings.Repeat("x", MaxFieldValueBytes+1)
		if _, err := EncodeInventory(validEnvelope(), payload); err == nil {
			t.Fatal("EncodeInventory() accepted oversized field")
		}
	})
}
