"""Recovery validates signatures, isolation and contents before restore commands."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import psycopg
import pytest

import northgate_rmm.recovery as recovery
from northgate_rmm.errors import ValidationError
from tests.test_operational_audit_recovery import private_file, signing_key


def recovery_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, Any], Mock]:
    from cryptography.hazmat.primitives import serialization

    key_path = tmp_path / "signing.pem"
    key = signing_key(key_path)
    public = private_file(
        tmp_path / "public.pem",
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    tool = private_file(tmp_path / "synthetic-tool", b"synthetic executable")
    tool.chmod(0o700)
    config: dict[str, Any] = {
        "database_dsn_credential": str(tmp_path / "dsn"),
        "manifest_private_key": str(key_path),
        "manifest_public_key": str(public),
        "deployment_id": "synthetic-deployment",
        "pg_dump": str(tool),
        "pg_restore": str(tool),
        "age": str(tool),
        "recipient": "synthetic-public-recipient",
        "recovery_identity": str(tmp_path / "offline-identity"),
        "isolated_restore": True,
    }
    monkeypatch.setattr(
        recovery,
        "load_database_dsn",
        lambda path: "postgresql://synthetic@127.0.0.1/northgate_restore_fixture",
    )
    # disk_usage is a named tuple in production; preserve its public free field.
    monkeypatch.setattr(shutil, "disk_usage", Mock(return_value=Mock(free=2**40)))

    def run(arguments: list[str], environment: dict[str, str]) -> None:
        assert "synthetic@" not in " ".join(arguments)
        assert environment["PGDATABASE"].startswith("northgate_restore_")
        if "--format=custom" in arguments:
            Path(arguments[arguments.index("--file") + 1]).write_bytes(
                b"synthetic-dump"
            )
        elif "--encrypt" in arguments:
            Path(arguments[arguments.index("--output") + 1]).write_bytes(
                b"synthetic-ciphertext"
            )
        elif "--decrypt" in arguments:
            Path(arguments[arguments.index("--output") + 1]).write_bytes(
                b"synthetic-dump"
            )

    runner = Mock(side_effect=run)
    monkeypatch.setattr(recovery, "run", runner)
    connection = MagicMock()
    connection.__enter__.return_value.execute.return_value.fetchone.return_value = (0,)
    monkeypatch.setattr(psycopg, "connect", Mock(return_value=connection))
    monkeypatch.setattr(recovery, "PostgresControlPlane", Mock(return_value=Mock()))
    return config, runner


def test_backup_restore_manifest_and_isolated_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, runner = recovery_fixture(tmp_path, monkeypatch)
    destination = tmp_path / "backup"
    recovery.backup(config, destination)
    assert destination.stat().st_mode & 0o777 == 0o700
    envelope = json.loads((destination / "manifest.json").read_text())
    assert envelope["manifest"]["ciphertext_sha256"] == recovery.digest(
        destination / "database.dump.age"
    )
    assert not list(destination.glob(".staging-*"))
    recovery.restore(config, destination)
    assert runner.call_count == 4
    restore_args = runner.call_args.args[0]
    assert "--single-transaction" in restore_args
    assert "--exit-on-error" in restore_args
    assert (
        restore_args[restore_args.index("--dbname") + 1] == "northgate_restore_fixture"
    )


@pytest.mark.parametrize("invalid", ["relative", "existing", "space", "budget"])
def test_backup_rejects_invalid_destination_or_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    config, runner = recovery_fixture(tmp_path, monkeypatch)
    destination = tmp_path / "backup"
    if invalid == "relative":
        destination = Path("relative-backup")
    elif invalid == "existing":
        destination.mkdir()
    elif invalid == "space":
        monkeypatch.setattr(shutil, "disk_usage", Mock(return_value=Mock(free=0)))
    else:
        config["maximum_dump_bytes"] = 1
    with pytest.raises(ValidationError):
        recovery.backup(config, destination)
    assert runner.call_count == (1 if invalid == "budget" else 0)
    assert not (destination / "manifest.json").exists()


@pytest.mark.parametrize(
    "failure",
    [
        "ciphertext",
        "isolation",
        "deployment",
        "prefix",
        "nonempty",
        "plaintext",
        "signature",
    ],
)
def test_restore_rejects_tampering_and_nonisolated_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from cryptography.exceptions import InvalidSignature

    config, runner = recovery_fixture(tmp_path, monkeypatch)
    destination = tmp_path / "backup"
    recovery.backup(config, destination)
    runner.reset_mock()
    if failure == "ciphertext":
        (destination / "database.dump.age").write_bytes(b"tampered")
    elif failure == "isolation":
        config["isolated_restore"] = False
    elif failure == "deployment":
        config["deployment_id"] = "another-deployment"
    elif failure == "prefix":
        monkeypatch.setattr(
            recovery,
            "load_database_dsn",
            lambda path: "postgresql://synthetic@127.0.0.1/live",
        )
    elif failure == "nonempty":
        connection = MagicMock()
        connection.__enter__.return_value.execute.return_value.fetchone.return_value = (
            1,
        )
        monkeypatch.setattr(psycopg, "connect", Mock(return_value=connection))
    elif failure == "plaintext":

        def wrong_plaintext(arguments: list[str], _environment: dict[str, str]) -> None:
            Path(arguments[arguments.index("--output") + 1]).write_bytes(b"tampered")

        runner.side_effect = wrong_plaintext
    else:
        envelope = json.loads((destination / "manifest.json").read_text())
        envelope["manifest"]["bytes"] += 1
        (destination / "manifest.json").write_text(json.dumps(envelope))
    with pytest.raises((ValidationError, InvalidSignature)):
        recovery.restore(config, destination)
    assert runner.call_count == (1 if failure == "plaintext" else 0)


@pytest.mark.parametrize("operation", ["backup", "backup-auto", "restore"])
def test_recovery_cli_success_does_not_reconnect_services(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
) -> None:
    config = tmp_path / "config.json"
    config.write_text("{}")
    backup = Mock()
    restore = Mock()
    monkeypatch.setattr(recovery, "backup", backup)
    monkeypatch.setattr(recovery, "restore", restore)
    assert recovery.main(["--config", str(config), operation, str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "operation": operation,
        "completed": True,
        "reconnection": False,
    }
    chosen = restore if operation == "restore" else backup
    chosen.assert_called_once()
    if operation == "backup-auto":
        assert chosen.call_args.args[1].parent == tmp_path
        assert chosen.call_args.args[1] != tmp_path


def test_recovery_cli_failure_is_sanitized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        recovery.main(["--config", str(tmp_path / "missing"), "restore", str(tmp_path)])
        == 1
    )
    assert "reconnection" not in capsys.readouterr().out
