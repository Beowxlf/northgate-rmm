from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

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
            TRUNCATE audit_events, observations, message_sequences,
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
    source = (
        Path(__file__).parents[1]
        / "src"
        / "northgate_rmm"
        / "migrations"
        / "0001_phase1.sql"
    )
    changed_directory = tmp_path / "migrations"
    changed_directory.mkdir()
    (changed_directory / source.name).write_text(
        source.read_text(encoding="utf-8") + "\n-- changed after application\n",
        encoding="utf-8",
    )
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
    source = (
        Path(__file__).parents[1]
        / "src"
        / "northgate_rmm"
        / "migrations"
        / "0001_phase1.sql"
    )
    migration_directory = tmp_path / "out-of-order-migrations"
    migration_directory.mkdir()
    source_text = source.read_text(encoding="utf-8")
    (migration_directory / source.name).write_text(source_text, encoding="utf-8")
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
