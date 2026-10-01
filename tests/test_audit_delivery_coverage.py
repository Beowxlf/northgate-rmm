"""Exercise signed audit delivery and retention against an isolated database."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import psycopg
import pytest

import northgate_rmm.audit_exporter as audit_exporter
import northgate_rmm.retention as retention
from northgate_rmm.errors import ValidationError
from northgate_rmm.workload_service import canonical
from tests.test_operational_audit_recovery import private_file, setup_sink
from tests.test_postgres_control_plane import enrolled_plane
from tests.test_postgres_control_plane import postgres_dsn as postgres_dsn

pytestmark = [
    pytest.mark.postgresql,
    pytest.mark.skipif(
        not os.environ.get("DATABASE_URL"), reason="isolated PostgreSQL required"
    ),
]


@pytest.fixture(autouse=True)
def delivery_state(postgres_dsn: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # The isolated CI service is loopback-only and deliberately has no TLS.
    # Production DSN policy has its own validation tests; inject only this boundary.
    monkeypatch.setattr(audit_exporter, "load_database_dsn", lambda path: postgres_dsn)
    monkeypatch.setattr(retention, "load_database_dsn", lambda path: postgres_dsn)
    with psycopg.connect(postgres_dsn) as connection:
        connection.execute(
            "TRUNCATE audit_events, observations, message_sequences, "
            "enrollment_grants, endpoint_identities, endpoints, audit_outbox "
            "RESTART IDENTITY CASCADE"
        )
        connection.execute(
            "UPDATE audit_delivery_state SET last_sequence=0, "
            "last_hash=repeat('0',64), acknowledged_sequence=0, "
            "acknowledged_hash=repeat('0',64), acknowledged_at=NULL, "
            "enforce_delivery=false"
        )
        connection.execute("UPDATE retention_hold SET active=false WHERE singleton")


def test_export_signatures_chain_acknowledgement_and_repeat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, postgres_dsn: str
) -> None:
    sink, _, config = setup_sink(tmp_path)
    dsn_file = private_file(tmp_path / "database-dsn", postgres_dsn.encode())
    config.update(database_dsn_credential=str(dsn_file), sink={})
    plane, _ = enrolled_plane(postgres_dsn)
    plane.begin_shutdown()

    def rpc(_service: object, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return sink.handle(path, canonical(body), None)[1]

    monkeypatch.setattr(audit_exporter, "call", rpc)
    assert audit_exporter.export(config) >= 1
    assert audit_exporter.export(config) == 0
    with psycopg.connect(postgres_dsn) as connection:
        row = connection.execute(
            "SELECT last_sequence, acknowledged_sequence, last_hash, "
            "acknowledged_hash FROM audit_delivery_state"
        ).fetchone()
    assert row is not None and row[0] == row[1] and row[2] == row[3]
    config_path = private_file(tmp_path / "config.json", canonical(config))
    assert audit_exporter.main(["--config", str(config_path)]) == 0


@pytest.mark.parametrize(
    "failure",
    [
        "fields",
        "deployment",
        "negative",
        "hash",
        "ahead",
        "diverged",
        "missing",
        "acknowledgement",
    ],
)
def test_export_rejects_invalid_signed_checkpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, postgres_dsn: str, failure: str
) -> None:
    sink, key, config = setup_sink(tmp_path)
    config.update(
        database_dsn_credential=str(
            private_file(tmp_path / "dsn", postgres_dsn.encode())
        ),
        sink={},
    )
    plane, _ = enrolled_plane(postgres_dsn)
    plane.begin_shutdown()
    with psycopg.connect(postgres_dsn) as connection:
        row = connection.execute(
            "SELECT last_sequence FROM audit_delivery_state"
        ).fetchone()
        assert row is not None
        last_sequence = int(row[0])
        if failure == "missing":
            connection.execute(
                "DELETE FROM audit_outbox WHERE chain_sequence=%s", (last_sequence,)
            )

    def rpc(_service: object, path: str, body: dict[str, Any]) -> dict[str, Any]:
        value = sink.handle(path, canonical(body), None)[1]
        if path.endswith("events") and failure == "acknowledgement":
            value["sequence"] += 1
        elif path.endswith("checkpoint"):
            if failure == "fields":
                value["unexpected"] = True
            elif failure == "deployment":
                value["deployment_id"] = "untrusted"
            elif failure == "negative":
                value["sequence"] = -1
            elif failure == "hash":
                value["hash"] = "invalid"
            elif failure == "ahead":
                value["sequence"] = last_sequence + 1
            elif failure == "missing":
                value["sequence"] = last_sequence
            elif failure == "diverged":
                value["hash"] = "f" * 64
        signed = {name: value[name] for name in ("deployment_id", "sequence", "hash")}
        value["signature"] = base64.b64encode(key.sign(canonical(signed))).decode()
        return value

    monkeypatch.setattr(audit_exporter, "call", rpc)
    expected = {
        "fields": "checkpoint fields invalid",
        "deployment": "checkpoint fields invalid",
        "negative": "checkpoint fields invalid",
        "hash": "checkpoint fields invalid",
        "ahead": "independent audit checkpoint",
        "diverged": "audit checkpoint diverged",
        "missing": "source checkpoint missing",
        "acknowledgement": "audit acknowledgement mismatch",
    }
    with pytest.raises(ValidationError, match=expected[failure]):
        audit_exporter.export(config)
    with psycopg.connect(postgres_dsn) as connection:
        row = connection.execute(
            "SELECT acknowledged_sequence FROM audit_delivery_state"
        ).fetchone()
    assert row == (0,)


def test_export_cli_failure_is_sanitized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("{}")
    assert audit_exporter.main(["--config", str(path)]) == 1
    assert (
        capsys.readouterr().err
        == "audit delivery unavailable or reconciliation required\n"
    )


def test_retention_hold_lock_and_audited_execution(
    tmp_path: Path, postgres_dsn: str
) -> None:
    path = private_file(tmp_path / "dsn", postgres_dsn.encode())
    args = ["--dsn-file", str(path)]
    with psycopg.connect(postgres_dsn) as connection:
        connection.execute("UPDATE retention_hold SET active=true WHERE singleton")
    assert retention.main(args) == 0
    with psycopg.connect(postgres_dsn) as connection:
        connection.execute("UPDATE retention_hold SET active=false WHERE singleton")
    with psycopg.connect(postgres_dsn) as lock:
        lock.execute("SELECT pg_advisory_xact_lock(742119)")
        assert retention.main(args) == 0
    assert retention.main(args) == 0
    with psycopg.connect(postgres_dsn) as connection:
        rows = connection.execute(
            "SELECT action, decision FROM audit_events WHERE actor_id='retention'"
        ).fetchall()
    assert rows == [("retention.apply", "accepted")]


def test_retention_failure_does_not_report_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        retention,
        "load_database_dsn",
        Mock(side_effect=ValidationError("synthetic unavailable")),
    )
    assert retention.main(["--dsn-file", str(tmp_path / "dsn")]) == 1
    assert capsys.readouterr().err == "retention unavailable\n"
