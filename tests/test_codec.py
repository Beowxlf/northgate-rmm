import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from northgate_rmm.codec import MAX_ENCODED_MESSAGE_BYTES, decode_message
from northgate_rmm.domain import HeartbeatMessage, InventoryMessage, Platform
from northgate_rmm.errors import ValidationError

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def message_document(message_type: str = "heartbeat") -> dict[str, object]:
    endpoint_id = uuid4()
    envelope: dict[str, object] = {
        "message_id": str(uuid4()),
        "endpoint_id": str(endpoint_id),
        "boot_id": str(uuid4()),
        "sequence": 1,
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(seconds=30)).isoformat(),
        "correlation_id": str(uuid4()),
        "protocol_version": 1,
    }
    if message_type == "heartbeat":
        payload: dict[str, object] = {
            "agent_version": "0.1.0-sim",
            "capabilities": ["inventory.v1"],
        }
    else:
        payload = {
            "platform": "linux",
            "architecture": "x86_64",
            "fields": {"kernel": "synthetic"},
            "collector_complete": True,
            "schema_version": 1,
        }
    return {"type": message_type, "envelope": envelope, "payload": payload}


def encoded(document: dict[str, object]) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode()


def test_decodes_exact_heartbeat_and_inventory_schemas() -> None:
    heartbeat = decode_message(encoded(message_document()))
    inventory = decode_message(encoded(message_document("inventory")))

    assert isinstance(heartbeat, HeartbeatMessage)
    assert heartbeat.payload.capabilities == ("inventory.v1",)
    assert isinstance(inventory, InventoryMessage)
    assert inventory.payload.platform is Platform.LINUX
    assert inventory.payload.fields == (("kernel", "synthetic"),)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff",
        b'{"type":',
        b"[]",
        b'{"type":"heartbeat","type":"inventory","envelope":{},"payload":{}}',
        b'{"type":"unknown","envelope":{},"payload":{}}',
    ],
)
def test_malformed_or_ambiguous_json_fails_closed(raw: bytes) -> None:
    with pytest.raises(ValidationError):
        decode_message(raw)


def test_encoded_size_limit_is_checked_before_json_parsing() -> None:
    raw = b"{" + (b" " * MAX_ENCODED_MESSAGE_BYTES) + b"}"
    with pytest.raises(ValidationError, match="size limit"):
        decode_message(raw)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("unknown_root", "fields do not match"),
        ("missing_envelope_field", "fields do not match"),
        ("boolean_sequence", "must be an integer"),
        ("unsupported_platform", "platform is unsupported"),
        ("too_many_capabilities", "too many capabilities"),
        ("oversized_inventory_value", "inventory field"),
    ],
)
def test_schema_and_domain_bounds_fail_closed(mutation: str, message: str) -> None:
    document = message_document(
        "inventory"
        if "inventory" in mutation or mutation == "unsupported_platform"
        else "heartbeat"
    )
    envelope = document["envelope"]
    payload = document["payload"]
    assert isinstance(envelope, dict)
    assert isinstance(payload, dict)

    if mutation == "unknown_root":
        document["extra"] = "denied"
    elif mutation == "missing_envelope_field":
        del envelope["boot_id"]
    elif mutation == "boolean_sequence":
        envelope["sequence"] = True
    elif mutation == "unsupported_platform":
        payload["platform"] = "bsd"
    elif mutation == "too_many_capabilities":
        payload["capabilities"] = [f"capability-{index}" for index in range(33)]
    elif mutation == "oversized_inventory_value":
        payload["fields"] = {"field": "x" * 513}
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValidationError, match=message):
        decode_message(encoded(deepcopy(document)))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("message_id", "not-a-uuid", "must be a UUID"),
        ("created_at", "not-a-time", "ISO 8601"),
        ("protocol_version", 2, "unsupported protocol"),
    ],
)
def test_envelope_scalar_failures_are_domain_errors(
    field: str,
    value: object,
    message: str,
) -> None:
    document = message_document()
    envelope = document["envelope"]
    assert isinstance(envelope, dict)
    envelope[field] = value

    with pytest.raises(ValidationError, match=message):
        decode_message(encoded(document))


def test_payload_must_be_an_object() -> None:
    document = message_document()
    document["payload"] = []
    with pytest.raises(ValidationError, match="payload must be an object"):
        decode_message(encoded(document))
