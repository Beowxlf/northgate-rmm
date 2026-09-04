from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4
from zoneinfo import ZoneInfo

import psycopg
import pytest
from psycopg import sql

from northgate_rmm.agent_api import (
    AgentMessageApplication,
    AgentMessageRequest,
    VerifiedClientCertificate,
)
from northgate_rmm.domain import (
    EndpointHealth,
    EndpointLifecycle,
    Observation,
    Platform,
)
from northgate_rmm.errors import (
    AuthorizationError,
    NotFoundError,
    ReplayError,
    ValidationError,
)
from northgate_rmm.persistence import PostgresControlPlane, apply_migrations
from northgate_rmm.simulator import SyntheticAgent

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
DATABASE_URL = os.environ.get("DATABASE_URL")

pytestmark = [
    pytest.mark.postgresql,
    pytest.mark.skipif(DATABASE_URL is None, reason="DATABASE_URL is not configured"),
]


@pytest.fixture(scope="session")
def postgres_dsn() -> str:
    assert DATABASE_URL is not None
    apply_migrations(DATABASE_URL)
    return DATABASE_URL


@pytest.fixture(autouse=True)
def clean_database(postgres_dsn: str) -> None:
    with psycopg.connect(postgres_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            TRUNCATE audit_events, observations, message_sequences, enrollment_grants,
                     endpoint_identities, endpoints
            RESTART IDENTITY CASCADE
            """
        )


def enrolled_plane(postgres_dsn: str) -> tuple[PostgresControlPlane, SyntheticAgent]:
    plane = PostgresControlPlane(postgres_dsn)
    agent = SyntheticAgent.enroll(
        plane,
        display_name="linux-db-sim-01",
        platform=Platform.LINUX,
        architecture="x86_64",
        now=NOW,
    )
    return plane, agent


def test_runtime_connections_enforce_database_deadlines(postgres_dsn: str) -> None:
    plane = PostgresControlPlane(postgres_dsn, operation_timeout_seconds=1.25)
    with plane._connect() as connection, connection.cursor() as cursor:
        cursor.execute("SHOW statement_timeout")
        statement_timeout = cursor.fetchone()
        assert statement_timeout is not None
        assert statement_timeout["statement_timeout"] == "1250ms"
        cursor.execute("SHOW lock_timeout")
        lock_timeout = cursor.fetchone()
        assert lock_timeout is not None
        assert lock_timeout["lock_timeout"] == "1250ms"

    with pytest.raises(ValidationError, match="operation timeout"):
        PostgresControlPlane(postgres_dsn, operation_timeout_seconds=0.5)


def test_restart_preserves_endpoint_observation_and_audit(postgres_dsn: str) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    message = agent.heartbeat(now=NOW)
    observation = plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=message,
        received_at=NOW + timedelta(seconds=1),
    )

    restarted = PostgresControlPlane(postgres_dsn)

    assert restarted.get_endpoint(
        agent.endpoint_id
    ).last_heartbeat_at == NOW + timedelta(seconds=1)
    assert restarted.observations == (observation,)
    assert [event.action for event in restarted.audit_events] == [
        "endpoint.enroll",
        "heartbeat.ingest",
    ]


def test_inventory_status_and_missing_records(postgres_dsn: str) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    inventory = agent.inventory(
        now=NOW,
        fields={"kernel": "synthetic", "package_count": "42"},
        collector_complete=False,
    )
    observation = plane.ingest_inventory(
        authenticated_identity_id=agent.identity_id,
        message=inventory,
        received_at=NOW + timedelta(seconds=1),
    )

    assert observation.observation_type == "inventory"
    assert plane.get_endpoint(agent.endpoint_id).last_heartbeat_at is None
    assert (
        plane.endpoint_status(agent.endpoint_id, now=NOW).health
        is EndpointHealth.OFFLINE
    )
    assert plane.list_endpoints()[0].endpoint_id == agent.endpoint_id
    with pytest.raises(NotFoundError, match="endpoint"):
        plane.get_endpoint(uuid4())
    with pytest.raises(NotFoundError, match="identity"):
        plane.get_identity(uuid4())


def test_migrations_are_idempotent_and_checksum_protected(
    postgres_dsn: str,
    tmp_path: Path,
) -> None:
    assert apply_migrations(postgres_dsn) == ()
    migration_source = (
        Path(__file__).parents[1] / "src" / "northgate_rmm" / "migrations"
    )
    changed_directory = tmp_path / "migrations"
    changed_directory.mkdir()
    for source in migration_source.glob("[0-9][0-9][0-9][0-9]_*.sql"):
        contents = source.read_text(encoding="utf-8")
        if source.name == "0001_phase1.sql":
            contents += "\n-- changed after application\n"
        (changed_directory / source.name).write_text(contents, encoding="utf-8")
    with pytest.raises(ValidationError, match="checksum changed"):
        apply_migrations(postgres_dsn, changed_directory)

    missing_directory = tmp_path / "missing-migration"
    missing_directory.mkdir()
    (missing_directory / "0002_placeholder.sql").write_text(
        "SELECT 1;\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="missing from source"):
        apply_migrations(postgres_dsn, missing_directory)


def test_migrations_reject_late_files_before_applied_head(
    postgres_dsn: str,
    tmp_path: Path,
) -> None:
    migration_source = (
        Path(__file__).parents[1] / "src" / "northgate_rmm" / "migrations"
    )
    migration_directory = tmp_path / "out-of-order-migrations"
    migration_directory.mkdir()
    for source in migration_source.glob("[0-9][0-9][0-9][0-9]_*.sql"):
        (migration_directory / source.name).write_text(
            source.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    late_name = "9002_late.sql"
    head_name = "9003_applied_head.sql"
    late_script = "SELECT 1;\n"
    head_script = "SELECT 2;\n"
    (migration_directory / late_name).write_text(late_script, encoding="utf-8")
    (migration_directory / head_name).write_text(head_script, encoding="utf-8")

    with psycopg.connect(postgres_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO schema_migrations (version, sha256) VALUES (%s, %s)",
            (head_name, hashlib.sha256(head_script.encode()).hexdigest()),
        )

    try:
        with pytest.raises(ValidationError, match="precede the applied migration head"):
            apply_migrations(postgres_dsn, migration_directory)
    finally:
        with psycopg.connect(postgres_dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM schema_migrations WHERE version = %s",
                (head_name,),
            )


def test_message_authorization_and_time_failures_are_audited(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    other = SyntheticAgent.enroll(
        plane,
        display_name="windows-db-sim-01",
        platform=Platform.WINDOWS,
        architecture="amd64",
        now=NOW,
    )

    unknown = agent.heartbeat(now=NOW)
    with pytest.raises(AuthorizationError, match="unknown"):
        plane.ingest_heartbeat(
            authenticated_identity_id=uuid4(),
            message=unknown,
            received_at=NOW + timedelta(seconds=1),
        )

    wrong_endpoint = agent.heartbeat(now=NOW)
    wrong_endpoint = replace(
        wrong_endpoint,
        envelope=replace(wrong_endpoint.envelope, endpoint_id=other.endpoint_id),
    )
    with pytest.raises(AuthorizationError, match="transport identity"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=wrong_endpoint,
            received_at=NOW + timedelta(seconds=1),
        )

    expired = agent.heartbeat(now=NOW, ttl=timedelta(seconds=1))
    with pytest.raises(ValidationError, match="expired"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=expired,
            received_at=NOW + timedelta(seconds=1),
        )

    future = agent.heartbeat(now=NOW + timedelta(minutes=6))
    with pytest.raises(ValidationError, match="clock skew"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=future,
            received_at=NOW,
        )
    assert [event.decision for event in plane.audit_events].count("rejected") == 4


def test_enrollment_grant_secret_is_one_time_and_digest_only(
    postgres_dsn: str,
) -> None:
    plane = PostgresControlPlane(postgres_dsn)
    grant, token = plane.create_enrollment_grant(
        display_name="debian-canary-01",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
        actor_id="release-operator",
    )

    assert re.fullmatch(r"ngr1_[A-Za-z0-9_-]{43}", token)
    assert grant.token_sha256 == hashlib.sha256(token.encode("ascii")).hexdigest()
    assert plane.get_enrollment_grant(grant.grant_id) == grant
    with psycopg.connect(postgres_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT row_to_json(g)::text
            FROM enrollment_grants AS g
            WHERE grant_id = %s
            """,
            (grant.grant_id,),
        )
        stored = cursor.fetchone()
    assert stored is not None
    assert token not in stored[0]
    audit_json = json.dumps(
        [
            {
                "reason": event.reason,
                "metadata": dict(event.metadata),
            }
            for event in plane.audit_events
        ]
    )
    assert token not in audit_json
    assert grant.token_sha256 not in audit_json

    endpoint, identity = plane.consume_enrollment_grant(
        token=token,
        public_key_fingerprint="sha256:" + "b" * 64,
        now=NOW + timedelta(seconds=1),
    )
    consumed = plane.get_enrollment_grant(grant.grant_id)
    assert endpoint.display_name == "debian-canary-01"
    assert endpoint.platform is Platform.LINUX
    assert endpoint.architecture == "amd64"
    assert consumed.consumed_at == NOW + timedelta(seconds=1)
    assert consumed.consumed_identity_id == identity.identity_id
    correlated = [
        event
        for event in plane.audit_events
        if event.action in {"enrollment_grant.consume", "endpoint.enroll"}
    ]
    assert [event.decision for event in correlated] == ["accepted", "accepted"]
    assert len({event.correlation_id for event in correlated}) == 1


def test_enrollment_grant_expiry_uses_absolute_utc_time(postgres_dsn: str) -> None:
    plane = PostgresControlPlane(postgres_dsn)
    fall_back = datetime(
        2026,
        11,
        1,
        1,
        55,
        tzinfo=ZoneInfo("America/New_York"),
        fold=0,
    )

    grant, _token = plane.create_enrollment_grant(
        display_name="dst-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=fall_back,
        actor_id="release-operator",
    )

    assert grant.created_at.tzinfo is UTC
    assert grant.expires_at - grant.created_at == timedelta(minutes=15)
    assert plane.get_enrollment_grant(grant.grant_id) == grant


def test_pending_enrollment_requires_issuance_and_first_heartbeat_activation(
    postgres_dsn: str,
) -> None:
    plane = PostgresControlPlane(postgres_dsn)
    _grant, token = plane.create_enrollment_grant(
        display_name="pending-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
        actor_id="release-operator",
    )
    endpoint, identity = plane.begin_endpoint_enrollment(
        token=token,
        public_key_fingerprint="sha256:" + "8" * 64,
        now=NOW + timedelta(seconds=1),
    )
    with pytest.raises(AuthorizationError, match="unauthorized"):
        plane.authenticate_endpoint_certificate(
            endpoint_id=endpoint.endpoint_id,
            public_key_fingerprint=identity.public_key_fingerprint,
            authenticated_at=NOW + timedelta(seconds=2),
            correlation_id=uuid4(),
        )

    not_before = NOW - timedelta(minutes=1)
    not_after = NOW + timedelta(hours=23)
    issued = plane.record_issued_endpoint_identity(
        identity.identity_id,
        certificate_serial="abc123",
        certificate_issuer="CN=NorthGate Endpoint Issuer",
        certificate_not_before=not_before,
        certificate_not_after=not_after,
        now=NOW + timedelta(seconds=3),
    )
    assert issued == identity
    authenticated = plane.authenticate_endpoint_certificate(
        endpoint_id=endpoint.endpoint_id,
        public_key_fingerprint=identity.public_key_fingerprint,
        authenticated_at=NOW + timedelta(seconds=4),
        correlation_id=uuid4(),
    )
    assert authenticated == identity
    with psycopg.connect(postgres_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT identity_status, activated_at FROM endpoint_identities "
            "WHERE identity_id = %s",
            (identity.identity_id,),
        )
        assert cursor.fetchone() == ("issued", None)
    retry = plane.record_issued_endpoint_identity(
        identity.identity_id,
        certificate_serial="abc123",
        certificate_issuer="CN=NorthGate Endpoint Issuer",
        certificate_not_before=not_before,
        certificate_not_after=not_after,
        now=NOW + timedelta(seconds=5),
    )
    assert retry == identity
    pending_agent = SyntheticAgent(
        endpoint_id=endpoint.endpoint_id,
        identity_id=identity.identity_id,
        platform=Platform.LINUX,
        architecture="amd64",
    )
    with pytest.raises(AuthorizationError, match="activation heartbeat"):
        plane.ingest_inventory(
            authenticated_identity_id=identity.identity_id,
            message=pending_agent.inventory(
                now=NOW + timedelta(seconds=6),
                fields={"os.id": "debian"},
            ),
            received_at=NOW + timedelta(seconds=7),
        )
    plane.ingest_heartbeat(
        authenticated_identity_id=identity.identity_id,
        message=pending_agent.heartbeat(now=NOW + timedelta(seconds=8)),
        received_at=NOW + timedelta(seconds=9),
    )
    with psycopg.connect(postgres_dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT identity_status, certificate_serial, certificate_issuer,
                   certificate_not_before, certificate_not_after, activated_at
            FROM endpoint_identities
            WHERE identity_id = %s
            """,
            (identity.identity_id,),
        )
        row = cursor.fetchone()
    assert row == (
        "active",
        "abc123",
        "CN=NorthGate Endpoint Issuer",
        not_before,
        not_after,
        NOW + timedelta(seconds=9),
    )
    activation_decisions = [
        event.decision
        for event in plane.audit_events
        if event.action == "identity.issue"
    ]
    assert activation_decisions == ["accepted", "no_change"]
    endpoint_activations = [
        event
        for event in plane.audit_events
        if event.action == "identity.activate" and event.decision == "accepted"
    ]
    assert len(endpoint_activations) == 1
    assert endpoint_activations[0].reason == "first authenticated heartbeat accepted"


def test_enrollment_grant_rejections_are_generic_and_audited(
    postgres_dsn: str,
) -> None:
    plane = PostgresControlPlane(postgres_dsn)
    expired, expired_token = plane.create_enrollment_grant(
        display_name="expired-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
        actor_id="release-operator",
        ttl=timedelta(seconds=1),
    )
    used, used_token = plane.create_enrollment_grant(
        display_name="used-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
        actor_id="release-operator",
    )
    invalid_key, invalid_key_token = plane.create_enrollment_grant(
        display_name="invalid-key-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
        actor_id="release-operator",
    )
    future, future_token = plane.create_enrollment_grant(
        display_name="future-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW + timedelta(minutes=1),
        actor_id="release-operator",
    )
    plane.consume_enrollment_grant(
        token=used_token,
        public_key_fingerprint="sha256:" + "c" * 64,
        now=NOW + timedelta(seconds=1),
    )

    attempts = (
        (expired_token, "sha256:" + "d" * 64),
        (used_token, "sha256:" + "d" * 64),
        ("ngr1_" + "x" * 43, "sha256:" + "d" * 64),
        ("malformed", "sha256:" + "d" * 64),
        (invalid_key_token, "malformed-fingerprint"),
        (future_token, "sha256:" + "d" * 64),
    )
    for token, fingerprint in attempts:
        with pytest.raises(
            AuthorizationError,
            match="enrollment grant is invalid or unavailable",
        ):
            plane.consume_enrollment_grant(
                token=token,
                public_key_fingerprint=fingerprint,
                now=NOW + timedelta(seconds=2),
            )

    assert plane.get_enrollment_grant(expired.grant_id).consumed_at is None
    assert plane.get_enrollment_grant(used.grant_id).consumed_at is not None
    assert plane.get_enrollment_grant(invalid_key.grant_id).consumed_at is None
    assert plane.get_enrollment_grant(future.grant_id).consumed_at is None
    rejected = [
        event
        for event in plane.audit_events
        if event.action == "enrollment_grant.consume" and event.decision == "rejected"
    ]
    assert {event.reason for event in rejected} == {
        "grant is expired",
        "grant is already consumed",
        "token digest is unknown",
        "token format is invalid",
        "public key fingerprint format is invalid",
        "server time predates grant creation",
    }
    invalid_key_event = next(
        event
        for event in rejected
        if event.reason == "public key fingerprint format is invalid"
    )
    assert invalid_key_event.subject == f"enrollment_grant:{invalid_key.grant_id}"

    with pytest.raises(AuthorizationError, match="invalid or unavailable"):
        plane.consume_enrollment_grant(
            token=used_token,
            public_key_fingerprint="sha256:" + "d" * 64,
            now=NOW + timedelta(minutes=20),
        )
    assert plane.audit_events[-1].reason == "grant is already consumed"


def test_concurrent_enrollment_grant_consumption_has_one_winner(
    postgres_dsn: str,
) -> None:
    plane = PostgresControlPlane(postgres_dsn)
    grant, token = plane.create_enrollment_grant(
        display_name="concurrent-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
        actor_id="release-operator",
    )

    def consume(_index: int) -> bool:
        worker = PostgresControlPlane(postgres_dsn)
        try:
            worker.consume_enrollment_grant(
                token=token,
                public_key_fingerprint="sha256:" + "e" * 64,
                now=NOW + timedelta(seconds=1),
            )
        except AuthorizationError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(consume, range(2)))

    assert sorted(results) == [False, True]
    assert len(plane.list_endpoints()) == 1
    assert plane.get_enrollment_grant(grant.grant_id).consumed_at is not None
    outcomes = [
        event.decision
        for event in plane.audit_events
        if event.action == "enrollment_grant.consume"
    ]
    assert outcomes.count("accepted") == 1
    assert outcomes.count("rejected") == 1


def test_fingerprint_collision_does_not_consume_enrollment_grant(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    grant, token = plane.create_enrollment_grant(
        display_name="duplicate-key-canary",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
        actor_id="release-operator",
    )
    fingerprint = plane.get_identity(agent.identity_id).public_key_fingerprint

    with pytest.raises(AuthorizationError, match="invalid or unavailable"):
        plane.consume_enrollment_grant(
            token=token,
            public_key_fingerprint=fingerprint,
            now=NOW + timedelta(seconds=1),
        )

    assert plane.get_enrollment_grant(grant.grant_id).consumed_at is None
    assert len(plane.list_endpoints()) == 1
    assert plane.audit_events[-1].reason == "public key fingerprint is already enrolled"


def test_agent_message_api_authenticates_and_acknowledges_exact_retries(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    message = agent.inventory(
        now=NOW,
        fields={"os.id": "debian", "os.version_id": "12"},
    )
    body = json.dumps(
        {
            "type": "inventory",
            "envelope": {
                "message_id": str(message.envelope.message_id),
                "endpoint_id": str(message.envelope.endpoint_id),
                "boot_id": str(message.envelope.boot_id),
                "sequence": message.envelope.sequence,
                "created_at": message.envelope.created_at.isoformat(),
                "expires_at": message.envelope.expires_at.isoformat(),
                "correlation_id": str(message.envelope.correlation_id),
                "protocol_version": message.envelope.protocol_version,
            },
            "payload": {
                "platform": message.payload.platform.value,
                "architecture": message.payload.architecture,
                "fields": dict(message.payload.fields),
                "collector_complete": message.payload.collector_complete,
                "schema_version": message.payload.schema_version,
            },
        },
        separators=(",", ":"),
    ).encode()
    request = AgentMessageRequest(
        method="POST",
        path="/v1/agent/messages",
        content_type="application/json",
        content_encoding=None,
        body=body,
    )
    identity = plane.get_identity(agent.identity_id)
    peer = VerifiedClientCertificate(
        endpoint_id=agent.endpoint_id,
        public_key_fingerprint=identity.public_key_fingerprint,
    )
    app = AgentMessageApplication(plane)

    first = app.handle(request, peer=peer, received_at=NOW + timedelta(seconds=1))
    retry = app.handle(request, peer=peer, received_at=NOW + timedelta(seconds=2))
    conflict = app.handle(
        replace(request, body=body + b" "),
        peer=peer,
        received_at=NOW + timedelta(seconds=3),
    )

    assert first.status == retry.status == 200
    assert first.body == retry.body
    assert json.loads(first.body) == {
        "message_id": str(message.envelope.message_id),
        "accepted": True,
    }
    assert (conflict.status, conflict.body) == (
        409,
        b'{"error":"message_conflict"}',
    )
    assert len(plane.observations) == 1
    assert (
        plane.observations[0].encoded_message_digest == hashlib.sha256(body).hexdigest()
    )
    inventory_outcomes = [
        event.decision
        for event in plane.audit_events
        if event.action == "inventory.ingest"
    ]
    assert inventory_outcomes == ["accepted", "no_change", "rejected"]
    accepted_flow = [
        event
        for event in plane.audit_events
        if event.decision == "accepted"
        and event.action in {"certificate.authenticate", "inventory.ingest"}
    ]
    assert len(accepted_flow) >= 2
    assert accepted_flow[0].correlation_id == message.envelope.correlation_id
    assert accepted_flow[1].correlation_id == message.envelope.correlation_id


def test_agent_message_api_rejects_unknown_and_revoked_certificates(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    body = json.dumps(
        {
            "type": "heartbeat",
            "envelope": {
                "message_id": str(uuid4()),
                "endpoint_id": str(agent.endpoint_id),
                "boot_id": str(uuid4()),
                "sequence": 1,
                "created_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
                "correlation_id": str(uuid4()),
                "protocol_version": 1,
            },
            "payload": {
                "agent_version": "0.2.0",
                "capabilities": ["inventory.v1"],
            },
        },
        separators=(",", ":"),
    ).encode()
    request = AgentMessageRequest(
        method="POST",
        path="/v1/agent/messages",
        content_type="application/json",
        content_encoding=None,
        body=body,
    )
    app = AgentMessageApplication(plane)
    unknown = VerifiedClientCertificate(agent.endpoint_id, "sha256:" + "f" * 64)
    unknown_response = app.handle(request, peer=unknown, received_at=NOW)

    identity = plane.get_identity(agent.identity_id)
    plane.revoke_identity(
        identity.identity_id,
        reason="certificate compromise drill",
        actor_id="security-admin",
        now=NOW + timedelta(seconds=1),
    )
    revoked = VerifiedClientCertificate(
        agent.endpoint_id,
        identity.public_key_fingerprint,
    )
    revoked_response = app.handle(
        request,
        peer=revoked,
        received_at=NOW + timedelta(seconds=2),
    )

    assert (unknown_response.status, unknown_response.body) == (
        403,
        b'{"error":"unauthorized"}',
    )
    assert (revoked_response.status, revoked_response.body) == (
        403,
        b'{"error":"unauthorized"}',
    )
    auth_rejections = [
        event
        for event in plane.audit_events
        if event.action == "certificate.authenticate" and event.decision == "rejected"
    ]
    assert [event.reason for event in auth_rejections] == [
        "certificate endpoint or public key is unknown",
        "certificate identity is revoked",
    ]
    assert plane.observations == ()


def test_rotation_keeps_history_and_rejects_the_previous_identity(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    previous = plane.get_identity(agent.identity_id)
    replacement_id = uuid4()
    replacement_fingerprint = "sha256:" + "9" * 64
    with psycopg.connect(postgres_dsn) as connection, connection.cursor() as cursor:
        cursor.execute("SET CONSTRAINTS ALL DEFERRED")
        cursor.execute(
            """
            INSERT INTO endpoint_identities (
                identity_id, endpoint_id, public_key_fingerprint, created_at,
                identity_status, previous_identity_id
            ) VALUES (%s, %s, %s, %s, 'active', %s)
            """,
            (
                replacement_id,
                agent.endpoint_id,
                replacement_fingerprint,
                NOW + timedelta(minutes=1),
                previous.identity_id,
            ),
        )
        cursor.execute(
            """
            UPDATE endpoint_identities
            SET identity_status = 'retired'
            WHERE identity_id = %s
            """,
            (previous.identity_id,),
        )
        cursor.execute(
            "UPDATE endpoints SET identity_id = %s WHERE endpoint_id = %s",
            (replacement_id, agent.endpoint_id),
        )

    with pytest.raises(AuthorizationError, match="unauthorized"):
        plane.authenticate_endpoint_certificate(
            endpoint_id=agent.endpoint_id,
            public_key_fingerprint=previous.public_key_fingerprint,
            authenticated_at=NOW + timedelta(minutes=2),
            correlation_id=uuid4(),
        )
    replacement = plane.authenticate_endpoint_certificate(
        endpoint_id=agent.endpoint_id,
        public_key_fingerprint=replacement_fingerprint,
        authenticated_at=NOW + timedelta(minutes=2),
        correlation_id=uuid4(),
    )
    assert replacement.identity_id == replacement_id
    assert plane.get_endpoint(agent.endpoint_id).identity_id == replacement_id
    assert plane.get_identity(previous.identity_id) == previous
    with pytest.raises(AuthorizationError, match="not current"):
        plane.ingest_heartbeat(
            authenticated_identity_id=previous.identity_id,
            message=agent.heartbeat(now=NOW + timedelta(minutes=2)),
            received_at=NOW + timedelta(minutes=2, seconds=1),
        )
    rejected_authentication = next(
        event
        for event in plane.audit_events
        if event.action == "certificate.authenticate" and event.decision == "rejected"
    )
    assert rejected_authentication.reason == "certificate identity is not current"


def test_inventory_binding_and_both_replay_classes_fail_closed(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    mismatched = agent.inventory(now=NOW, fields={"os": "synthetic"})
    mismatched = replace(
        mismatched,
        payload=replace(mismatched.payload, architecture="arm64"),
    )
    with pytest.raises(ValidationError, match="inventory binding"):
        plane.ingest_inventory(
            authenticated_identity_id=agent.identity_id,
            message=mismatched,
            received_at=NOW + timedelta(seconds=1),
        )

    accepted = agent.heartbeat(now=NOW + timedelta(seconds=2))
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=accepted,
        received_at=NOW + timedelta(seconds=3),
    )
    with pytest.raises(ReplayError, match="message ID"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=accepted,
            received_at=NOW + timedelta(seconds=4),
        )

    later = agent.heartbeat(now=NOW + timedelta(seconds=5))
    out_of_order = replace(
        later, envelope=replace(later.envelope, sequence=accepted.envelope.sequence)
    )
    with pytest.raises(ReplayError, match="sequence"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=out_of_order,
            received_at=NOW + timedelta(seconds=6),
        )

    agent.restart()
    after_restart = agent.heartbeat(now=NOW + timedelta(seconds=7))
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=after_restart,
        received_at=NOW + timedelta(seconds=8),
    )
    assert len(plane.observations) == 2


def test_delayed_cross_boot_receipts_cannot_regress_freshness(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    delayed = agent.heartbeat(now=NOW)
    agent.restart()
    newer = agent.heartbeat(now=NOW + timedelta(seconds=1))
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=newer,
        received_at=NOW + timedelta(seconds=10),
    )
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=delayed,
        received_at=NOW + timedelta(seconds=5),
    )

    endpoint = plane.get_endpoint(agent.endpoint_id)
    assert endpoint.last_receipt_at == NOW + timedelta(seconds=10)
    assert endpoint.last_heartbeat_at == NOW + timedelta(seconds=10)


def test_concurrent_duplicate_enrollment_has_one_winner(postgres_dsn: str) -> None:
    fingerprint = "sha256:" + "a" * 64

    def enroll(index: int) -> bool:
        plane = PostgresControlPlane(postgres_dsn)
        try:
            plane.enroll_synthetic_endpoint(
                display_name=f"concurrent-{index}",
                platform=Platform.LINUX,
                architecture="x86_64",
                public_key_fingerprint=fingerprint,
                now=NOW,
            )
        except ValidationError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(enroll, range(2)))

    assert sorted(results) == [False, True]
    plane = PostgresControlPlane(postgres_dsn)
    assert len(plane.list_endpoints()) == 1
    assert [event.decision for event in plane.audit_events].count("rejected") == 1


def test_concurrent_message_replay_has_one_winner(postgres_dsn: str) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    message = agent.heartbeat(now=NOW)

    def ingest(receipt_offset: int) -> Observation | ReplayError:
        worker = PostgresControlPlane(postgres_dsn)
        try:
            return worker.ingest_heartbeat(
                authenticated_identity_id=agent.identity_id,
                message=message,
                received_at=NOW + timedelta(seconds=receipt_offset),
            )
        except ReplayError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(ingest, (1, 2)))

    assert sum(isinstance(result, Observation) for result in results) == 1
    assert sum(isinstance(result, ReplayError) for result in results) == 1
    assert len(plane.observations) == 1
    assert [event.decision for event in plane.audit_events].count("rejected") == 1


def test_revocation_is_atomic_idempotent_and_blocks_ingest(postgres_dsn: str) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    correlation_id = uuid4()
    revoked = plane.revoke_identity(
        agent.identity_id,
        reason="synthetic compromise",
        actor_id="security-admin",
        now=NOW + timedelta(seconds=1),
        correlation_id=correlation_id,
    )
    duplicate = plane.revoke_identity(
        agent.identity_id,
        reason="duplicate request",
        actor_id="security-admin",
        now=NOW + timedelta(seconds=2),
        correlation_id=correlation_id,
    )

    assert revoked.lifecycle is EndpointLifecycle.REVOKED
    assert duplicate == revoked
    with pytest.raises(AuthorizationError, match="revoked"):
        plane.ingest_heartbeat(
            authenticated_identity_id=agent.identity_id,
            message=agent.heartbeat(now=NOW + timedelta(seconds=3)),
            received_at=NOW + timedelta(seconds=4),
        )
    correlated = [
        event for event in plane.audit_events if event.correlation_id == correlation_id
    ]
    assert [event.decision for event in correlated] == ["accepted", "no_change"]
    assert plane.audit_events[-1].decision == "rejected"


def test_invalid_or_missing_revocation_target_fails_without_state_change(
    postgres_dsn: str,
) -> None:
    plane, agent = enrolled_plane(postgres_dsn)
    with pytest.raises(ValidationError, match="reason"):
        plane.revoke_identity(
            agent.identity_id,
            reason="",
            actor_id="security-admin",
            now=NOW,
        )
    with pytest.raises(NotFoundError, match="identity"):
        plane.revoke_identity(
            uuid4(),
            reason="missing target",
            actor_id="security-admin",
            now=NOW,
        )
    assert plane.get_identity(agent.identity_id).lifecycle is EndpointLifecycle.ACTIVE


def test_database_dump_and_isolated_restore_preserve_revocation(
    postgres_dsn: str,
    tmp_path: Path,
) -> None:
    pg_dump = shutil.which("pg_dump")
    pg_restore = shutil.which("pg_restore")
    assert pg_dump is not None, "pg_dump is required for the Phase 1 recovery test"
    assert pg_restore is not None, (
        "pg_restore is required for the Phase 1 recovery test"
    )

    plane, agent = enrolled_plane(postgres_dsn)
    plane.revoke_identity(
        agent.identity_id,
        reason="restore must preserve this revocation",
        actor_id="security-admin",
        now=NOW + timedelta(seconds=1),
    )
    backup_path = tmp_path / "phase1.dump"
    # Executable paths are resolved locally; every argument is controlled here.
    subprocess.run(  # noqa: S603
        [
            pg_dump,
            "--format=custom",
            "--no-owner",
            "--no-privileges",
            "--file",
            str(backup_path),
            postgres_dsn,
        ],
        check=True,
    )
    assert backup_path.stat().st_size > 0

    restore_database = f"northgate_restore_{uuid4().hex}"
    admin_dsn = _replace_database(postgres_dsn, "postgres")
    restore_dsn = _replace_database(postgres_dsn, restore_database)
    with psycopg.connect(admin_dsn, autocommit=True) as connection:
        connection.execute(
            sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restore_database))
        )
    try:
        # Same bounded local-tool invocation against the isolated restore database.
        subprocess.run(  # noqa: S603
            [
                pg_restore,
                "--no-owner",
                "--no-privileges",
                "--dbname",
                restore_dsn,
                str(backup_path),
            ],
            check=True,
        )
        restored = PostgresControlPlane(restore_dsn)
        restored_identity = restored.get_identity(agent.identity_id)
        assert restored_identity.lifecycle is EndpointLifecycle.REVOKED
        with pytest.raises(AuthorizationError, match="revoked"):
            restored.ingest_heartbeat(
                authenticated_identity_id=agent.identity_id,
                message=agent.heartbeat(now=NOW + timedelta(seconds=2)),
                received_at=NOW + timedelta(seconds=3),
            )
        assert restored.audit_events[-1].decision == "rejected"
    finally:
        with psycopg.connect(admin_dsn, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                    sql.Identifier(restore_database)
                )
            )


def _replace_database(dsn: str, database: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, ""))
