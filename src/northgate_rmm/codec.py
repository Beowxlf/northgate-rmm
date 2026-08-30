"""Strict, size-bounded JSON decoder for synthetic Phase 1 messages."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from northgate_rmm.domain import (
    HeartbeatMessage,
    HeartbeatPayload,
    InventoryMessage,
    InventoryPayload,
    MessageEnvelope,
    Platform,
)
from northgate_rmm.errors import ValidationError

MAX_ENCODED_MESSAGE_BYTES = 65_536


def decode_message(raw: bytes) -> HeartbeatMessage | InventoryMessage:
    """Decode an exact-schema message without accepting ambiguous JSON."""

    if not raw:
        raise ValidationError("message body is empty")
    if len(raw) > MAX_ENCODED_MESSAGE_BYTES:
        raise ValidationError("message body exceeds the encoded size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValidationError("message body is not valid bounded JSON") from exc

    root = _object(value, "message")
    _exact_keys(root, {"type", "envelope", "payload"}, "message")
    message_type = _string(root["type"], "type")
    envelope = _decode_envelope(_object(root["envelope"], "envelope"))
    payload = _object(root["payload"], "payload")
    if message_type == "heartbeat":
        _exact_keys(payload, {"agent_version", "capabilities"}, "heartbeat payload")
        capabilities_value = payload["capabilities"]
        if not isinstance(capabilities_value, list):
            raise ValidationError("capabilities must be an array")
        capabilities = tuple(_string(item, "capability") for item in capabilities_value)
        return HeartbeatMessage(
            envelope=envelope,
            payload=HeartbeatPayload(
                agent_version=_string(payload["agent_version"], "agent_version"),
                capabilities=capabilities,
            ),
        )
    if message_type == "inventory":
        _exact_keys(
            payload,
            {
                "platform",
                "architecture",
                "fields",
                "collector_complete",
                "schema_version",
            },
            "inventory payload",
        )
        fields_object = _object(payload["fields"], "fields")
        fields = tuple(
            sorted(
                (
                    _string(key, "inventory key"),
                    _string(item, "inventory value"),
                )
                for key, item in fields_object.items()
            )
        )
        collector_complete = payload["collector_complete"]
        if type(collector_complete) is not bool:
            raise ValidationError("collector_complete must be a boolean")
        return InventoryMessage(
            envelope=envelope,
            payload=InventoryPayload(
                platform=_platform(payload["platform"]),
                architecture=_string(payload["architecture"], "architecture"),
                fields=fields,
                collector_complete=collector_complete,
                schema_version=_integer(payload["schema_version"], "schema_version"),
            ),
        )
    raise ValidationError("unsupported message type")


def _decode_envelope(value: dict[str, Any]) -> MessageEnvelope:
    _exact_keys(
        value,
        {
            "message_id",
            "endpoint_id",
            "boot_id",
            "sequence",
            "created_at",
            "expires_at",
            "correlation_id",
            "protocol_version",
        },
        "envelope",
    )
    return MessageEnvelope(
        message_id=_uuid(value["message_id"], "message_id"),
        endpoint_id=_uuid(value["endpoint_id"], "endpoint_id"),
        boot_id=_uuid(value["boot_id"], "boot_id"),
        sequence=_integer(value["sequence"], "sequence"),
        created_at=_timestamp(value["created_at"], "created_at"),
        expires_at=_timestamp(value["expires_at"], "expires_at"),
        correlation_id=_uuid(value["correlation_id"], "correlation_id"),
        protocol_version=_integer(value["protocol_version"], "protocol_version"),
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{field_name} must be an object")
    return cast(dict[str, Any], value)


def _exact_keys(value: dict[str, Any], expected: set[str], field_name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ValidationError(
            f"{field_name} fields do not match schema; "
            f"missing={missing}, unknown={unknown}"
        )


def _string(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string")
    return value


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise ValidationError(f"{field_name} must be an integer")
    return value


def _uuid(value: object, field_name: str) -> UUID:
    try:
        return UUID(_string(value, field_name))
    except ValueError as exc:
        raise ValidationError(f"{field_name} must be a UUID") from exc


def _timestamp(value: object, field_name: str) -> datetime:
    raw = _string(value, field_name)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field_name} must be an ISO 8601 timestamp") from exc
    return parsed


def _platform(value: object) -> Platform:
    try:
        return Platform(_string(value, "platform"))
    except ValueError as exc:
        raise ValidationError("platform is unsupported") from exc
