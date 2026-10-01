"""Recovery input, stream and archive failure boundaries using isolated fixtures."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from uuid import uuid4

import psycopg
import pytest

from northgate_rmm import operations_backup as recovery
from tests.test_operations_backup import setup


@pytest.mark.parametrize(
    "field,value",
    [
        ("maximum_archive_bytes", 0),
        ("maximum_archive_bytes", True),
        ("sqlite_sources", []),
        ("sqlite_sources", ["secrets.sqlite3", "secrets.sqlite3"]),
        ("sqlite_sources", ["unapproved.sqlite3"]),
        ("sqlite_sources", [{}]),
        ("remote_root", "/does-not-exist"),
        ("remote_root", 23),
    ],
)
def test_backup_settings_reject_invalid_scope_or_budget(
    tmp_path: Path, field: str, value: object
) -> None:
    config, _, _ = setup(tmp_path)
    config[field] = value
    with pytest.raises(ValueError):
        recovery.settings(config)


def test_backup_paths_keys_and_metadata_remain_private(tmp_path: Path) -> None:
    config, _, _ = setup(tmp_path)
    key_path = Path(cast(str, config["remote_key_credential"]))
    key_path.write_text("invalid")
    with pytest.raises(ValueError, match="evidence key"):
        recovery.evidence_key(config)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "remote")
    with pytest.raises(ValueError, match="symbolic"):
        recovery.source_path(link, "secrets.sqlite3")
    for destination in (Path("relative"), tmp_path, link):
        with pytest.raises(ValueError):
            recovery.new_directory(destination)
    with pytest.raises(ValueError, match="ancestors"):
        recovery.new_directory(link / "new")
    assert recovery.new_directory(tmp_path / "new").stat().st_mode & 0o777 == 0o700
    config["pg_restore"] = "overridden"
    base, _, _, _ = recovery.settings(config)
    assert base["pg_restore"] == "overridden"
    path = Path(cast(str, config["recovery_config"]))
    base["recipient"] = "invalid"
    path.write_text(json.dumps(base))
    with pytest.raises(ValueError, match="recipient"):
        recovery.settings(config)


@pytest.mark.parametrize(
    "record",
    [
        {
            "snapshot_id": "bad",
            "sha256": "a" * 64,
            "created_at": "2026-01-01T00:00:00Z",
        },
        {
            "snapshot_id": str(uuid4()),
            "sha256": "bad",
            "created_at": "2026-01-01T00:00:00Z",
        },
        {"snapshot_id": str(uuid4()), "sha256": "a" * 64, "created_at": "2026-01-01"},
        {},
    ],
)
def test_snapshot_receipt_requires_identity_digest_and_timezone(
    tmp_path: Path, record: object
) -> None:
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        recovery.snapshot_link({"openbao_snapshot_receipt": str(path)})
    with pytest.raises(ValueError):
        recovery.snapshot_link({"openbao_snapshot_receipt": 7})
    assert recovery.snapshot_link({}) is None


@pytest.mark.parametrize(
    "mode",
    [
        "root-link",
        "identifier",
        "sequence",
        "chunk-size",
        "chunk-digest",
        "artifact-size",
        "artifact-digest",
    ],
)
def test_completed_evidence_integrity_failures(tmp_path: Path, mode: str) -> None:
    config, record, chunk = setup(tmp_path)
    root = chunk.parent
    if mode == "root-link":
        link = tmp_path / "evidence-link"
        link.symlink_to(root)
        root = link
    elif mode == "identifier":
        record["id"] = "not-an-identifier"
    elif mode == "sequence":
        record["chunks"][0]["chunk_index"] = 1
    elif mode == "chunk-size":
        record["chunks"][0]["size"] = 0
    elif mode == "chunk-digest":
        record["chunks"][0]["sha256"] = "0" * 64
    elif mode == "artifact-size":
        record["size"] += 1
    elif mode == "artifact-digest":
        record["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        recovery.verify_chunks(record, root, recovery.evidence_key(config))


def test_bundle_enforces_names_duplicate_and_expansion_budget() -> None:
    with tarfile.open(fileobj=io.BytesIO(), mode="w|") as archive:
        bundle = recovery.Bundle(archive, 4)
        with pytest.raises(ValueError, match="member"):
            bundle.add("../escape", io.BytesIO(b"a"), 1)
        with pytest.raises(ValueError, match="budget"):
            bundle.add("operations.dump", io.BytesIO(b"a"), -1)
        with pytest.raises(ValueError, match="budget"):
            bundle.add("operations.dump", io.BytesIO(b"12345"), 5)
        bundle.add("operations.dump", io.BytesIO(b"a"), 1)
        with pytest.raises(ValueError, match="duplicate"):
            bundle.add("operations.dump", io.BytesIO(b"a"), 1)
    assert recovery.valid_member(f"operations-evidence/{uuid4()}.127.aes")
    assert not recovery.valid_member(f"operations-evidence/{uuid4()}.128.aes")
    assert not recovery.valid_member("operations-evidence/" + "-" * 36 + ".0.aes")


def test_bounded_subprocess_success_and_failure(tmp_path: Path) -> None:
    output = tmp_path / "result"
    recovery.stream_process([sys.executable, "-c", "print('ok')"], {}, output, 16)
    assert output.read_bytes() == b"ok\n"
    with pytest.raises(ValueError, match="failed"):
        recovery.stream_process(
            [sys.executable, "-c", "raise SystemExit(2)"], {}, tmp_path / "failed", 16
        )


class EncryptionProcess:
    def __init__(self, code: int, missing_pipe: bool = False) -> None:
        self.stdin: io.BytesIO | None = None if missing_pipe else io.BytesIO()
        self.code = code
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        return self.code

    def poll(self) -> int | None:
        return None if self.code else 0

    def kill(self) -> None:
        self.killed = True


@pytest.mark.parametrize("code,missing", [(0, False), (1, False), (1, True)])
def test_age_writer_checks_completion_and_closes_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int, missing: bool
) -> None:
    process = EncryptionProcess(code, missing)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(recovery, "executable", lambda value: value)
    base: recovery.Configuration = {
        "age": "/synthetic/age",
        "recipient": "age1synthetic",
    }
    if code:
        with (
            pytest.raises(ValueError),
            recovery.age_writer(tmp_path / "archive", base) as writer,
        ):
            writer.write(b"retained evidence")
        assert process.killed
    else:
        with recovery.age_writer(tmp_path / "archive", base) as writer:
            writer.write(b"retained evidence")
    assert process.stdin is None or process.stdin.closed


@pytest.mark.parametrize(
    "mode",
    [
        "link",
        "duplicate",
        "budget",
        "missing-manifest",
        "wrong-digest",
        "wrong-files",
        "incomplete",
    ],
)
def test_unpack_rejects_unsafe_or_unbound_archives(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "archive.tar"
    manifest = json.dumps({"format": recovery.FORMAT, "files": {}}).encode()
    with tarfile.open(path, "w") as archive:
        if mode in {"link", "duplicate", "budget", "wrong-files"}:
            member = tarfile.TarInfo("operations.dump")
            if mode == "link":
                member.type, member.linkname = tarfile.SYMTYPE, "/elsewhere"
            else:
                member.size = 1
            archive.addfile(member, io.BytesIO(b"a"))
            if mode == "duplicate":
                archive.addfile(member, io.BytesIO(b"a"))
        if mode != "missing-manifest":
            member = tarfile.TarInfo("manifest.json")
            member.size = len(manifest)
            archive.addfile(member, io.BytesIO(manifest))
    expected = (
        "0" * 64 if mode == "wrong-digest" else hashlib.sha256(manifest).hexdigest()
    )
    destination = tmp_path / "unpacked"
    destination.mkdir()
    monkey_budget = -(recovery.MAX_MANIFEST + 1) if mode == "budget" else 65536
    with pytest.raises(ValueError):
        recovery.unpack(path, destination, monkey_budget, expected)


class QueryResult:
    def __init__(
        self, row: object = None, rows: list[dict[str, object]] | None = None
    ) -> None:
        self.row, self.rows = row, rows or []

    def fetchone(self) -> object:
        return self.row

    def fetchall(self) -> list[dict[str, object]]:
        return self.rows


class ArtifactCursor:
    def __init__(self, artifacts: list[dict[str, object]]) -> None:
        self.artifacts = artifacts

    def __enter__(self) -> ArtifactCursor:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str) -> None:
        assert "state='complete'" in query

    def __iter__(self) -> Iterator[dict[str, object]]:
        return iter(self.artifacts)


class SnapshotDatabase:
    def __init__(self, mode: str, record: recovery.BackupArtifact) -> None:
        self.mode, self.record = mode, record
        self.statements: list[str] = []

    def __enter__(self) -> SnapshotDatabase:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, params: object = None) -> QueryResult:
        self.statements.append(query)
        if "max(version)" in query:
            return QueryResult(
                None
                if self.mode == "missing-version"
                else {"version": 2 if self.mode == "bad-version" else 1}
            )
        if "pg_export_snapshot" in query:
            return QueryResult(
                None
                if self.mode == "missing-snapshot"
                else {
                    "snapshot": "invalid snapshot"
                    if self.mode == "bad-snapshot"
                    else "1234-ABCD"
                }
            )
        if "pg_tables" in query:
            return QueryResult((1 if self.mode == "occupied" else 0,))
        if "ops_chunks" in query and query.startswith("SELECT"):
            return QueryResult(rows=[dict(chunk) for chunk in self.record["chunks"]])
        return QueryResult()

    def cursor(self, *, name: str, row_factory: object) -> ArtifactCursor:
        assert name == "ops_recovery_artifacts"
        return ArtifactCursor(
            [{key: dict(self.record)[key] for key in ("id", "size", "sha256")}]
        )


@pytest.mark.parametrize(
    "mode",
    ["success", "missing-version", "bad-version", "missing-snapshot", "bad-snapshot"],
)
def test_postgres_snapshot_holds_read_transaction_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    _, record, _ = setup(tmp_path)
    database = SnapshotDatabase(mode, record)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: database)
    monkeypatch.setattr(recovery, "load_database_dsn", lambda path: "dbname=synthetic")
    monkeypatch.setattr(recovery, "environment", lambda dsn: {})
    monkeypatch.setattr(recovery, "executable", lambda value: value)
    commands: list[list[str]] = []

    def dump(
        arguments: list[str], env: dict[str, str], destination: Path, limit: int
    ) -> None:
        commands.append(arguments)
        destination.write_bytes(b"synthetic dump")

    monkeypatch.setattr(recovery, "stream_process", dump)
    base: recovery.Configuration = {
        "database_dsn_credential": "unused",
        "pg_dump": "/synthetic/pg_dump",
    }
    if mode == "success":
        with recovery.postgres_snapshot(base, tmp_path, 65536) as (path, records):
            assert path.read_bytes() == b"synthetic dump"
            assert list(records) == [record]
            assert "ROLLBACK" not in database.statements
        assert "--snapshot=1234-ABCD" in commands[0]
    else:
        with (
            pytest.raises(ValueError),
            recovery.postgres_snapshot(base, tmp_path, 65536),
        ):
            pytest.fail("An invalid database snapshot must never be exposed")
        assert commands == []
    assert database.statements[0] == "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"
    assert database.statements[-1] == "ROLLBACK"


@pytest.mark.parametrize(
    "mode", ["success", "occupied", "bad-version", "mismatch", "extra-index"]
)
def test_restore_database_validates_database_and_retained_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    config, record, chunk = setup(tmp_path)
    destination = chunk.parent.parent
    index = destination / "evidence-index.jsonl"
    data = json.dumps({} if mode == "mismatch" else record) + "\n"
    index.write_text(data + ("unexpected" if mode == "extra-index" else ""))
    database = SnapshotDatabase(mode, record)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: database)
    monkeypatch.setattr(
        recovery, "load_database_dsn", lambda path: "dbname=northgate_restore_synthetic"
    )
    monkeypatch.setattr(recovery, "environment", lambda dsn: {})
    monkeypatch.setattr(recovery, "executable", lambda value: value)
    commands: list[list[str]] = []
    monkeypatch.setattr(
        recovery, "run", lambda arguments, env: commands.append(arguments)
    )
    base: recovery.Configuration = {
        "database_dsn_credential": "unused",
        "pg_restore": "/synthetic/pg_restore",
    }
    if mode == "success":
        recovery.restore_database(base, destination, recovery.evidence_key(config))
        assert commands[0][1:3] == ["--dbname", "northgate_restore_synthetic"]
        assert any(
            query.startswith("DELETE FROM ops_chunks") for query in database.statements
        )
        assert any(
            query.startswith("UPDATE ops_artifacts SET state='cancelled'")
            for query in database.statements
        )
    else:
        with pytest.raises(ValueError):
            recovery.restore_database(base, destination, recovery.evidence_key(config))
        assert not any(
            query.startswith("DELETE FROM ops_chunks") for query in database.statements
        )


def test_recovery_cli_routes_without_reconnecting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(recovery, "load_configuration", lambda path: {})
    calls: list[tuple[str, Path]] = []

    def backup(config: recovery.Configuration, destination: Path) -> dict[str, str]:
        calls.append(("backup", destination))
        return {"format": recovery.FORMAT}

    def restore(
        config: recovery.Configuration, source: Path, destination: Path
    ) -> dict[str, str]:
        calls.append(("restore", destination))
        return {"format": recovery.FORMAT}

    monkeypatch.setattr(recovery, "backup", backup)
    monkeypatch.setattr(recovery, "verify_restore", restore)
    for command in ("backup", "backup-auto", "verify-restore"):
        args = ["--config", "unused", command]
        if command == "verify-restore":
            args.append(str(tmp_path / "source"))
        args.append(str(tmp_path))
        assert recovery.main(args) == 0
        assert json.loads(capsys.readouterr().out)["reconnection"] is False
    assert calls[1][1].parent == tmp_path
    assert calls[-1][0] == "restore"

    def fail(config: recovery.Configuration, destination: Path) -> None:
        raise ValueError("private diagnostic")

    monkeypatch.setattr(recovery, "backup", fail)
    assert recovery.main(["--config", "unused", "backup", str(tmp_path)]) == 1
    assert "private diagnostic" not in capsys.readouterr().err
