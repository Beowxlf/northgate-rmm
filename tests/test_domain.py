from datetime import UTC, datetime, timedelta
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest

from northgate_rmm.domain import (
    Endpoint,
    EndpointIdentity,
    EnrollmentGrant,
    FreshnessPolicy,
    HeartbeatPayload,
    InventoryPayload,
    MessageEnvelope,
    Observation,
    Platform,
    canonical_digest,
)
from northgate_rmm.errors import ValidationError

NOW = datetime(2026, 8, 29, 16, 0, tzinfo=UTC)


def test_canonical_digest_is_order_independent() -> None:
    assert canonical_digest({"b": 2, "a": 1}) == canonical_digest({"a": 1, "b": 2})


@pytest.mark.parametrize(
    ("online", "stale", "message"),
    [
        (timedelta(0), timedelta(seconds=1), "online_for"),
        (timedelta(seconds=2), timedelta(seconds=1), "stale_for"),
    ],
)
def test_freshness_policy_rejects_invalid_boundaries(
    online: timedelta,
    stale: timedelta,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        FreshnessPolicy(online_for=online, stale_for=stale)


def test_message_envelope_validates_protocol_sequence_and_ttl() -> None:
    def envelope(
        *,
        protocol_version: int = 1,
        sequence: int = 1,
        created_at: datetime = NOW,
        expires_at: datetime = NOW + timedelta(seconds=30),
    ) -> MessageEnvelope:
        return MessageEnvelope(
            message_id=uuid4(),
            endpoint_id=uuid4(),
            boot_id=uuid4(),
            sequence=sequence,
            created_at=created_at,
            expires_at=expires_at,
            correlation_id=uuid4(),
            protocol_version=protocol_version,
        )

    envelope()
    with pytest.raises(ValidationError, match="protocol"):
        envelope(protocol_version=2)
    with pytest.raises(ValidationError, match="sequence"):
        envelope(sequence=0)
    with pytest.raises(ValidationError, match="sequence"):
        envelope(sequence=2**63)
    with pytest.raises(ValidationError, match="lifetime"):
        envelope(expires_at=NOW)
    with pytest.raises(ValidationError, match="lifetime"):
        envelope(expires_at=NOW + timedelta(minutes=6))
    with pytest.raises(ValidationError, match="timezone"):
        envelope(created_at=NOW.replace(tzinfo=None))


def test_endpoint_and_identity_validate_bounded_fields() -> None:
    endpoint_id = uuid4()
    identity_id = uuid4()
    with pytest.raises(ValidationError, match="fingerprint"):
        EndpointIdentity(
            identity_id=identity_id,
            endpoint_id=endpoint_id,
            public_key_fingerprint="not-a-fingerprint",
            created_at=NOW,
        )
    with pytest.raises(ValidationError, match="reason"):
        EndpointIdentity(
            identity_id=identity_id,
            endpoint_id=endpoint_id,
            public_key_fingerprint="sha256:" + "a" * 64,
            created_at=NOW,
            revoked_at=NOW,
        )
    with pytest.raises(ValidationError, match="predate"):
        EndpointIdentity(
            identity_id=identity_id,
            endpoint_id=endpoint_id,
            public_key_fingerprint="sha256:" + "a" * 64,
            created_at=NOW,
            revoked_at=NOW - timedelta(seconds=1),
            revocation_reason="invalid chronology",
        )
    with pytest.raises(ValidationError, match="display_name"):
        Endpoint(
            endpoint_id=endpoint_id,
            display_name="",
            platform=Platform.LINUX,
            architecture="x86_64",
            identity_id=identity_id,
            enrolled_at=NOW,
        )
    with pytest.raises(ValidationError, match="architecture"):
        Endpoint(
            endpoint_id=endpoint_id,
            display_name="sim",
            platform=Platform.LINUX,
            architecture="",
            identity_id=identity_id,
            enrolled_at=NOW,
        )


def test_enrollment_grant_enforces_v1_scope_lifetime_and_consumption() -> None:
    grant_id = uuid4()
    identity_id = uuid4()

    def grant(**changes: object) -> EnrollmentGrant:
        values = {
            "grant_id": grant_id,
            "token_sha256": "a" * 64,
            "display_name": "debian-canary-01",
            "platform": Platform.LINUX,
            "architecture": "amd64",
            "created_at": NOW,
            "expires_at": NOW + timedelta(minutes=15),
            "created_by": "release-operator",
        }
        values.update(changes)
        return EnrollmentGrant(**values)  # type: ignore[arg-type]

    assert grant().consumed_at is None
    consumed = grant(
        consumed_at=NOW + timedelta(minutes=1),
        consumed_identity_id=identity_id,
    )
    assert consumed.consumed_identity_id == identity_id
    with pytest.raises(ValidationError, match="token_sha256"):
        grant(token_sha256="not-a-digest")  # noqa: S106 -- non-secret invalid input
    with pytest.raises(ValidationError, match="Linux"):
        grant(platform=Platform.WINDOWS)
    with pytest.raises(ValidationError, match="amd64"):
        grant(architecture="arm64")
    with pytest.raises(ValidationError, match="lifetime"):
        grant(expires_at=NOW + timedelta(minutes=16))
    with pytest.raises(ValidationError, match="incomplete"):
        grant(consumed_at=NOW + timedelta(minutes=1))
    with pytest.raises(ValidationError, match="consumption time"):
        grant(consumed_at=NOW + timedelta(minutes=15), consumed_identity_id=identity_id)

    fall_back = datetime(
        2026,
        11,
        1,
        1,
        55,
        tzinfo=ZoneInfo("America/New_York"),
        fold=0,
    )
    with pytest.raises(ValidationError, match="lifetime"):
        grant(created_at=fall_back, expires_at=fall_back + timedelta(minutes=15))


def test_payloads_enforce_bounds_and_stable_digests() -> None:
    heartbeat = HeartbeatPayload(
        agent_version="0.1.0-sim",
        capabilities=("inventory.v1",),
    )
    assert len(heartbeat.digest()) == 64
    with pytest.raises(ValidationError, match="agent_version"):
        HeartbeatPayload(agent_version="")
    with pytest.raises(ValidationError, match="capabilities"):
        HeartbeatPayload(agent_version="v", capabilities=tuple("x" for _ in range(33)))
    with pytest.raises(ValidationError, match="capability"):
        HeartbeatPayload(agent_version="v", capabilities=("",))

    inventory = InventoryPayload(
        platform=Platform.WINDOWS,
        architecture="amd64",
        fields=(("os", "synthetic-windows"),),
    )
    assert len(inventory.digest()) == 64
    with pytest.raises(ValidationError, match="schema"):
        InventoryPayload(
            platform=Platform.LINUX,
            architecture="x86_64",
            schema_version=2,
        )
    with pytest.raises(ValidationError, match="inventory field"):
        InventoryPayload(
            platform=Platform.LINUX,
            architecture="x86_64",
            fields=(("", "value"),),
        )
    with pytest.raises(ValidationError, match="unique"):
        InventoryPayload(
            platform=Platform.LINUX,
            architecture="x86_64",
            fields=(("os", "first"), ("os", "second")),
        )


def test_observation_rejects_invalid_digests() -> None:
    values: dict[str, object] = {
        "observation_id": uuid4(),
        "endpoint_id": uuid4(),
        "message_id": uuid4(),
        "observation_type": "inventory",
        "schema_version": 1,
        "source_time": NOW,
        "received_at": NOW,
        "boot_id": uuid4(),
        "sequence": 1,
        "payload_digest": "a" * 64,
    }
    with pytest.raises(ValidationError, match="payload_digest"):
        Observation(**(values | {"payload_digest": "invalid"}))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="encoded_message_digest"):
        Observation(
            **values,  # type: ignore[arg-type]
            encoded_message_digest="invalid",
        )


def test_duplicate_fingerprint_and_revocation_reason_bounds() -> None:
    from northgate_rmm.control_plane import ControlPlane

    plane = ControlPlane()
    fingerprint = "sha256:" + "a" * 64
    plane.enroll_synthetic_endpoint(
        display_name="one",
        platform=Platform.LINUX,
        architecture="x86_64",
        public_key_fingerprint=fingerprint,
        now=NOW,
    )
    with pytest.raises(ValidationError, match="already enrolled"):
        plane.enroll_synthetic_endpoint(
            display_name="two",
            platform=Platform.LINUX,
            architecture="x86_64",
            public_key_fingerprint=fingerprint,
            now=NOW,
        )
    identity_id = plane.list_endpoints()[0].identity_id
    with pytest.raises(ValidationError, match="reason"):
        plane.revoke_identity(
            identity_id,
            reason="",
            actor_id="admin",
            now=NOW,
        )
