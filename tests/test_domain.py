from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from northgate_rmm.domain import (
    Endpoint,
    EndpointIdentity,
    FreshnessPolicy,
    HeartbeatPayload,
    InventoryPayload,
    MessageEnvelope,
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
