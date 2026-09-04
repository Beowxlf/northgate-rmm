"""Typed domain values for the local RMM protocol simulator."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from northgate_rmm.errors import ValidationError

PROTOCOL_VERSION = 1
MAX_MESSAGE_TTL = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_ENROLLMENT_GRANT_TTL = timedelta(minutes=15)
MAX_SEQUENCE = (2**63) - 1
MAX_DISPLAY_NAME_LENGTH = 128
MAX_AGENT_VERSION_LENGTH = 64
MAX_CAPABILITIES = 32
MAX_INVENTORY_FIELDS = 128
MAX_INVENTORY_KEY_LENGTH = 64
MAX_INVENTORY_VALUE_LENGTH = 512


def require_aware(value: datetime, field_name: str) -> None:
    """Reject naive timestamps so state derivation is deterministic."""

    try:
        offset = value.utcoffset()
    except (AttributeError, OverflowError, TypeError, ValueError) as error:
        raise ValidationError(f"{field_name} must include a valid timezone") from error
    if value.tzinfo is None or offset is None:
        raise ValidationError(f"{field_name} must include a timezone")


def canonical_digest(payload: dict[str, Any]) -> str:
    """Return a stable digest for bounded, JSON-compatible message data."""

    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class Platform(StrEnum):
    """Platforms represented by synthetic inventory only."""

    LINUX = "linux"
    WINDOWS = "windows"


class EndpointLifecycle(StrEnum):
    """Identity lifecycle, kept separate from communication freshness."""

    PENDING = "pending"
    ISSUED = "issued"
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class EndpointHealth(StrEnum):
    """Communication health derived only from trusted receipt time."""

    ONLINE = "online"
    STALE = "stale"
    OFFLINE = "offline"


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    """Boundaries for deterministic online, stale, and offline status."""

    online_for: timedelta = timedelta(seconds=90)
    stale_for: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        if self.online_for <= timedelta(0):
            raise ValidationError("online_for must be positive")
        if self.stale_for <= self.online_for:
            raise ValidationError("stale_for must exceed online_for")


@dataclass(frozen=True, slots=True)
class EndpointIdentity:
    """Synthetic public identity bound to exactly one endpoint."""

    identity_id: UUID
    endpoint_id: UUID
    public_key_fingerprint: str
    created_at: datetime
    status: EndpointLifecycle = EndpointLifecycle.ACTIVE
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    def __post_init__(self) -> None:
        require_aware(self.created_at, "created_at")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.public_key_fingerprint) is None:
            raise ValidationError("fingerprint must be a lowercase SHA-256 value")
        if self.status is EndpointLifecycle.REVOKED:
            if self.revoked_at is None or not self.revocation_reason:
                raise ValidationError("revoked identity requires time and reason")
        elif self.revoked_at is not None or self.revocation_reason is not None:
            raise ValidationError("only a revoked identity may have revocation facts")
        if self.revoked_at is not None:
            require_aware(self.revoked_at, "revoked_at")
            if self.revoked_at < self.created_at:
                raise ValidationError("revocation cannot predate identity creation")

    @property
    def lifecycle(self) -> EndpointLifecycle:
        return self.status


@dataclass(frozen=True, slots=True)
class EnrollmentGrant:
    """Short-lived, single-use authorization to create one Linux identity."""

    grant_id: UUID
    token_sha256: str
    display_name: str
    platform: Platform
    architecture: str
    created_at: datetime
    expires_at: datetime
    created_by: str
    consumed_at: datetime | None = None
    consumed_identity_id: UUID | None = None

    def __post_init__(self) -> None:
        require_aware(self.created_at, "created_at")
        require_aware(self.expires_at, "expires_at")
        if re.fullmatch(r"[0-9a-f]{64}", self.token_sha256) is None:
            raise ValidationError("token_sha256 must be a lowercase SHA-256 value")
        if not self.display_name or len(self.display_name) > MAX_DISPLAY_NAME_LENGTH:
            raise ValidationError("display_name is empty or too long")
        if self.platform is not Platform.LINUX:
            raise ValidationError("v1 enrollment grants support Linux only")
        if self.architecture != "amd64":
            raise ValidationError("v1 enrollment grants support amd64 only")
        if not self.created_by or len(self.created_by) > 256:
            raise ValidationError("created_by is empty or too long")
        created_utc = self.created_at.astimezone(UTC)
        expires_utc = self.expires_at.astimezone(UTC)
        lifetime = expires_utc - created_utc
        if lifetime <= timedelta(0) or lifetime > MAX_ENROLLMENT_GRANT_TTL:
            raise ValidationError("enrollment grant lifetime is invalid")
        if (self.consumed_at is None) != (self.consumed_identity_id is None):
            raise ValidationError("enrollment grant consumption state is incomplete")
        if self.consumed_at is not None:
            require_aware(self.consumed_at, "consumed_at")
            consumed_utc = self.consumed_at.astimezone(UTC)
            if not created_utc <= consumed_utc < expires_utc:
                raise ValidationError("enrollment grant consumption time is invalid")


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Synthetic endpoint record; display attributes are not identity."""

    endpoint_id: UUID
    display_name: str
    platform: Platform
    architecture: str
    identity_id: UUID
    enrolled_at: datetime
    last_receipt_at: datetime | None = None
    last_heartbeat_at: datetime | None = None

    def __post_init__(self) -> None:
        require_aware(self.enrolled_at, "enrolled_at")
        if not self.display_name or len(self.display_name) > MAX_DISPLAY_NAME_LENGTH:
            raise ValidationError("display_name is empty or too long")
        if not self.architecture or len(self.architecture) > 32:
            raise ValidationError("architecture is empty or too long")
        if self.last_receipt_at is not None:
            require_aware(self.last_receipt_at, "last_receipt_at")
        if self.last_heartbeat_at is not None:
            require_aware(self.last_heartbeat_at, "last_heartbeat_at")


@dataclass(frozen=True, slots=True)
class MessageEnvelope:
    """Versioned envelope shared by synthetic endpoint messages."""

    message_id: UUID
    endpoint_id: UUID
    boot_id: UUID
    sequence: int
    created_at: datetime
    expires_at: datetime
    correlation_id: UUID
    protocol_version: int = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        require_aware(self.created_at, "created_at")
        require_aware(self.expires_at, "expires_at")
        if self.protocol_version != PROTOCOL_VERSION:
            raise ValidationError("unsupported protocol version")
        if not 1 <= self.sequence <= MAX_SEQUENCE:
            raise ValidationError("sequence is outside the supported range")
        ttl = self.expires_at - self.created_at
        if ttl <= timedelta(0) or ttl > MAX_MESSAGE_TTL:
            raise ValidationError("message lifetime is invalid")


@dataclass(frozen=True, slots=True)
class HeartbeatPayload:
    """Minimal liveness and capability payload."""

    agent_version: str
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.agent_version or len(self.agent_version) > MAX_AGENT_VERSION_LENGTH:
            raise ValidationError("agent_version is empty or too long")
        if len(self.capabilities) > MAX_CAPABILITIES:
            raise ValidationError("too many capabilities")
        if any(not item or len(item) > 64 for item in self.capabilities):
            raise ValidationError("capability is empty or too long")

    def digest(self) -> str:
        return canonical_digest(
            {
                "agent_version": self.agent_version,
                "capabilities": list(self.capabilities),
            }
        )


@dataclass(frozen=True, slots=True)
class InventoryPayload:
    """Versioned synthetic inventory with explicit partial-completion state."""

    platform: Platform
    architecture: str
    fields: tuple[tuple[str, str], ...] = ()
    collector_complete: bool = True
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValidationError("unsupported inventory schema version")
        if not self.architecture or len(self.architecture) > 32:
            raise ValidationError("architecture is empty or too long")
        if len(self.fields) > MAX_INVENTORY_FIELDS:
            raise ValidationError("too many inventory fields")
        if len({key for key, _value in self.fields}) != len(self.fields):
            raise ValidationError("inventory field names must be unique")
        if any(
            not key
            or len(key) > MAX_INVENTORY_KEY_LENGTH
            or len(value) > MAX_INVENTORY_VALUE_LENGTH
            for key, value in self.fields
        ):
            raise ValidationError("inventory field is empty or too long")

    def digest(self) -> str:
        return canonical_digest(
            {
                "architecture": self.architecture,
                "collector_complete": self.collector_complete,
                "fields": dict(self.fields),
                "platform": self.platform.value,
                "schema_version": self.schema_version,
            }
        )


@dataclass(frozen=True, slots=True)
class HeartbeatMessage:
    envelope: MessageEnvelope
    payload: HeartbeatPayload


@dataclass(frozen=True, slots=True)
class InventoryMessage:
    envelope: MessageEnvelope
    payload: InventoryPayload


@dataclass(frozen=True, slots=True)
class Observation:
    """Append-only accepted message fact."""

    observation_id: UUID
    endpoint_id: UUID
    message_id: UUID
    observation_type: str
    schema_version: int
    source_time: datetime
    received_at: datetime
    boot_id: UUID
    sequence: int
    payload_digest: str
    encoded_message_digest: str | None = None

    def __post_init__(self) -> None:
        require_aware(self.source_time, "source_time")
        require_aware(self.received_at, "received_at")
        if re.fullmatch(r"[0-9a-f]{64}", self.payload_digest) is None:
            raise ValidationError("payload_digest must be a lowercase SHA-256 value")
        if (
            self.encoded_message_digest is not None
            and re.fullmatch(r"[0-9a-f]{64}", self.encoded_message_digest) is None
        ):
            raise ValidationError(
                "encoded_message_digest must be a lowercase SHA-256 value"
            )


@dataclass(frozen=True, slots=True)
class EndpointStatus:
    endpoint_id: UUID
    lifecycle: EndpointLifecycle
    health: EndpointHealth
    last_heartbeat_at: datetime | None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Append-only security and state-transition evidence."""

    event_id: UUID
    server_time: datetime
    actor_type: str
    actor_id: str
    subject: str
    action: str
    decision: str
    reason: str
    correlation_id: UUID
    metadata: tuple[tuple[str, str], ...] = ()
