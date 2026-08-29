from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from northgate_rmm.control_plane import ControlPlane
from northgate_rmm.domain import (
    EndpointHealth,
    EndpointLifecycle,
    FreshnessPolicy,
    Platform,
)
from northgate_rmm.errors import (
    AuthorizationError,
    NotFoundError,
    ReplayError,
    ValidationError,
)
from northgate_rmm.simulator import SyntheticAgent

NOW = datetime(2026, 8, 29, 16, 0, tzinfo=UTC)


def enrolled_linux() -> tuple[ControlPlane, SyntheticAgent]:
    plane = ControlPlane()
    agent = SyntheticAgent.enroll(
        plane,
        display_name="linux-sim-01",
        platform=Platform.LINUX,
        architecture="x86_64",
        now=NOW,
    )
    return plane, agent


@pytest.mark.parametrize(
    ("platform", "architecture"),
    [(Platform.LINUX, "x86_64"), (Platform.WINDOWS, "amd64")],
)
def test_windows_and_linux_fixtures_follow_the_same_contract(
    platform: Platform,
    architecture: str,
) -> None:
    plane = ControlPlane()
    agent = SyntheticAgent.enroll(
        plane,
        display_name=f"{platform.value}-sim",
        platform=platform,
        architecture=architecture,
        now=NOW,
    )
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=agent.heartbeat(now=NOW),
        received_at=NOW + timedelta(seconds=1),
    )
    assert (
        plane.endpoint_status(agent.endpoint_id, now=NOW).health
        is EndpointHealth.ONLINE
    )


def test_heartbeat_drives_online_stale_and_offline_status() -> None:
    plane, agent = enrolled_linux()
    initial = plane.endpoint_status(agent.endpoint_id, now=NOW)
    assert initial.health is EndpointHealth.OFFLINE
    assert initial.lifecycle is EndpointLifecycle.ACTIVE

    message = agent.heartbeat(now=NOW)
    observation = plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=message,
        received_at=NOW + timedelta(seconds=1),
    )

    policy = FreshnessPolicy(
        online_for=timedelta(seconds=90),
        stale_for=timedelta(minutes=5),
    )
    assert observation.endpoint_id == agent.endpoint_id
    assert (
        plane.endpoint_status(
            agent.endpoint_id,
            now=NOW + timedelta(seconds=91),
            policy=policy,
        ).health
        is EndpointHealth.ONLINE
    )
    assert (
        plane.endpoint_status(
            agent.endpoint_id,
            now=NOW + timedelta(minutes=2),
            policy=policy,
        ).health
        is EndpointHealth.STALE
    )
    assert (
        plane.endpoint_status(
            agent.endpoint_id,
            now=NOW + timedelta(minutes=6),
            policy=policy,
        ).health
        is EndpointHealth.OFFLINE
    )


def test_inventory_is_independent_from_heartbeat_freshness() -> None:
    plane, agent = enrolled_linux()
    message = agent.inventory(
        now=NOW,
        fields={"kernel": "synthetic", "package_count": "42"},
        collector_complete=False,
    )
    observation = plane.ingest_inventory(
        authenticated_identity_id=agent.identity_id,
        message=message,
        received_at=NOW + timedelta(seconds=1),
    )

    endpoint = plane.get_endpoint(agent.endpoint_id)
    assert observation.observation_type == "inventory"
    assert endpoint.last_receipt_at == NOW + timedelta(seconds=1)
    assert endpoint.last_heartbeat_at is None
    assert (
        plane.endpoint_status(agent.endpoint_id, now=NOW).health
        is EndpointHealth.OFFLINE
    )


def test_transport_identity_controls_endpoint_binding() -> None:
    plane, agent = enrolled_linux()
    other = SyntheticAgent.enroll(
        plane,
        display_name="windows-sim-01",
        platform=Platform.WINDOWS,
        architecture="amd64",
        now=NOW,
    )
    original = agent.heartbeat(now=NOW)
    forged = replace(
        original,
        envelope=replace(original.envelope, endpoint_id=other.endpoint_id),
    )

    with pytest.raises(AuthorizationError, match="transport identity"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=forged,
            received_at=NOW + timedelta(seconds=1),
        )
    assert plane.audit_events[-1].decision == "rejected"


def test_unknown_and_revoked_identities_fail_closed() -> None:
    plane, agent = enrolled_linux()
    unknown_message = agent.heartbeat(now=NOW)
    with pytest.raises(AuthorizationError, match="unknown"):
        plane.ingest_heartbeat(
            authenticated_identity_id=uuid4(),
            message=unknown_message,
            received_at=NOW + timedelta(seconds=1),
        )

    revoked = plane.revoke_identity(
        agent.identity_id,
        reason="synthetic compromise exercise",
        actor_id="security-admin",
        now=NOW + timedelta(seconds=2),
    )
    assert revoked.lifecycle is EndpointLifecycle.REVOKED
    duplicate = plane.revoke_identity(
        agent.identity_id,
        reason="second request",
        actor_id="security-admin",
        now=NOW + timedelta(seconds=3),
    )
    assert duplicate == revoked
    assert plane.audit_events[-1].decision == "no_change"

    with pytest.raises(AuthorizationError, match="revoked"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=agent.heartbeat(now=NOW + timedelta(seconds=4)),
            received_at=NOW + timedelta(seconds=5),
        )
    status = plane.endpoint_status(agent.endpoint_id, now=NOW + timedelta(seconds=5))
    assert status.lifecycle is EndpointLifecycle.REVOKED


def test_message_id_and_sequence_replays_are_rejected() -> None:
    plane, agent = enrolled_linux()
    accepted = agent.heartbeat(now=NOW)
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=accepted,
        received_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(ReplayError, match="message ID"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=accepted,
            received_at=NOW + timedelta(seconds=2),
        )

    fresh = agent.heartbeat(now=NOW + timedelta(seconds=3))
    out_of_order = replace(
        fresh,
        envelope=replace(fresh.envelope, sequence=1),
    )
    with pytest.raises(ReplayError, match="sequence"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=out_of_order,
            received_at=NOW + timedelta(seconds=4),
        )

    agent.restart()
    after_restart = agent.heartbeat(now=NOW + timedelta(seconds=5))
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=after_restart,
        received_at=NOW + timedelta(seconds=6),
    )


def test_expired_message_and_inventory_mismatch_are_rejected() -> None:
    plane, agent = enrolled_linux()
    expired = agent.heartbeat(now=NOW, ttl=timedelta(seconds=1))
    with pytest.raises(ValidationError, match="expired"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=expired,
            received_at=NOW + timedelta(seconds=1),
        )

    inventory = agent.inventory(now=NOW, fields={"os": "synthetic"})
    mismatched = replace(
        inventory,
        payload=replace(inventory.payload, architecture="arm64"),
    )
    with pytest.raises(ValidationError, match="inventory binding"):
        plane.ingest_inventory(
            authenticated_identity_id=agent.identity_id,
            message=mismatched,
            received_at=NOW + timedelta(seconds=1),
        )


def test_observation_and_audit_views_are_immutable_snapshots() -> None:
    plane, agent = enrolled_linux()
    message = agent.heartbeat(now=NOW)
    observation = plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=message,
        received_at=NOW + timedelta(seconds=1),
    )
    observations = plane.observations
    audit_events = plane.audit_events

    assert isinstance(observations, tuple)
    assert isinstance(audit_events, tuple)
    assert observations[-1] == observation
    with pytest.raises(FrozenInstanceError):
        observation.sequence = 99  # type: ignore[misc]


def test_list_endpoints_and_missing_records() -> None:
    plane, agent = enrolled_linux()
    assert plane.list_endpoints()[0].endpoint_id == agent.endpoint_id
    with pytest.raises(NotFoundError, match="endpoint does not exist"):
        plane.get_endpoint(uuid4())
    with pytest.raises(NotFoundError, match="identity does not exist"):
        plane.get_identity(uuid4())
