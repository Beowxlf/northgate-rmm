"""Exercise durable audit recovery and signed certificate status on real files."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from northgate_rmm import audit_reconcile, certificate_status
from northgate_rmm.audit_sink import AuditSink
from northgate_rmm.errors import ValidationError
from northgate_rmm.issuer_service import open_ledger
from northgate_rmm.workload_service import canonical

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX durable service files"
)


def private_file(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def signing_key(path: Path) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    private_file(
        path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    return key


def setup_sink(tmp_path: Path) -> tuple[AuditSink, Ed25519PrivateKey, dict[str, Any]]:
    ledger = tmp_path / "ledger"
    ledger.mkdir(mode=0o700)
    archive = tmp_path / "archive"
    archive.mkdir(mode=0o700)
    key_path = tmp_path / "key.pem"
    key = signing_key(key_path)
    public_path = private_file(
        tmp_path / "public.pem",
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    config = {
        "ledger": str(ledger / "audit.sqlite"),
        "deployment_id": str(uuid4()),
        "checkpoint_directory": str(archive),
        "checkpoint_private_key": str(key_path),
        "checkpoint_public_key": str(public_path),
    }
    return AuditSink(config), key, config


def event(
    sink: AuditSink,
    sequence: int = 1,
    previous: str = "0" * 64,
    payload: str = "bounded event",
) -> dict[str, Any]:
    return {
        "deployment_id": sink.deployment,
        "sequence": sequence,
        "previous_hash": previous,
        "payload": payload,
        "hash": hashlib.sha256((previous + payload).encode()).hexdigest(),
    }


def test_audit_archive_rebuild_and_idempotent_delivery(tmp_path: Path) -> None:
    sink, key, config = setup_sink(tmp_path)
    first = event(sink)
    status, checkpoint = sink.handle("/v1/audit/events", canonical(first), None)
    assert status == 200
    signed = {k: checkpoint[k] for k in ("deployment_id", "sequence", "hash")}
    key.public_key().verify(
        base64.b64decode(checkpoint["signature"]), canonical(signed)
    )
    assert sink.handle("/v1/audit/events", canonical(first), None) == (
        status,
        checkpoint,
    )
    second = event(sink, 2, first["hash"], "second event")
    sink.handle("/v1/audit/events", canonical(second), None)
    with open_ledger(sink.path) as db:
        assert db.execute("SELECT count(*) FROM audit").fetchone()[0] == 2
        db.execute("DELETE FROM audit WHERE sequence=2")
    with pytest.raises(ValidationError, match="reconciliation"):
        sink.handle(
            "/v1/audit/checkpoint", canonical({"deployment_id": sink.deployment}), None
        )
    configuration = private_file(tmp_path / "reconcile.json", canonical(config))
    rebuilt = sink.path.parent / "rebuilt.sqlite"
    args = [
        "--config",
        str(configuration),
        "--new-ledger",
        str(rebuilt),
        "--minimum-sequence",
        "2",
        "--minimum-hash",
        second["hash"],
    ]
    assert audit_reconcile.main(args) == 0
    with open_ledger(rebuilt) as db:
        rows = db.execute(
            "SELECT sequence,payload FROM audit ORDER BY sequence"
        ).fetchall()
        assert [(r[0], r[1]) for r in rows] == [
            (1, "bounded event"),
            (2, "second event"),
        ]
    assert audit_reconcile.main(args) == 1  # never overwrite an existing ledger
    # Replaying a durable archive record after ledger rollback repairs the ledger.
    assert sink.handle("/v1/audit/events", canonical(second), None)[0] == 200


@pytest.mark.parametrize(
    "change", ["deployment", "hash", "gap", "previous", "bool", "size", "extra"]
)
def test_audit_rejects_invalid_events_without_archiving(
    tmp_path: Path, change: str
) -> None:
    sink, _key, _config = setup_sink(tmp_path)
    value = event(sink)
    if change == "deployment":
        value["deployment_id"] = str(uuid4())
    elif change == "hash":
        value["hash"] = "f" * 64
    elif change == "gap":
        value["sequence"] = 2
    elif change == "previous":
        value = event(sink, 1, "1" * 64)
    elif change == "bool":
        value["sequence"] = True
    elif change == "size":
        value["payload"] = "x" * 32769
    else:
        value["unexpected"] = True
    with pytest.raises(ValidationError):
        sink.handle("/v1/audit/events", canonical(value), None)
    assert list(sink.archive.iterdir()) == []
    with open_ledger(sink.path) as db:
        assert db.execute("SELECT count(*) FROM audit").fetchone()[0] == 0


def test_audit_rejects_divergent_replay_and_archive(tmp_path: Path) -> None:
    sink, _key, _config = setup_sink(tmp_path)
    original = event(sink)
    sink.handle("/v1/audit/events", canonical(original), None)
    with pytest.raises(ValidationError, match="replay diverged"):
        sink.handle("/v1/audit/events", canonical(event(sink, payload="changed")), None)
    with open_ledger(sink.path) as db:
        db.execute("DELETE FROM audit")
    record = next(sink.archive.glob("*.json"))
    record.chmod(0o600)
    record.write_text("{}")
    with pytest.raises(ValidationError, match="archive checkpoint diverged"):
        sink.handle("/v1/audit/events", canonical(original), None)


@pytest.mark.parametrize(
    "tamper", ["signature", "payload", "minimum_hash", "minimum_sequence"]
)
def test_reconciliation_requires_signed_contiguous_external_anchor(
    tmp_path: Path, tamper: str
) -> None:
    sink, _key, config = setup_sink(tmp_path)
    value = event(sink)
    sink.handle("/v1/audit/events", canonical(value), None)
    record = next(sink.archive.glob("*.json"))
    if tamper in {"signature", "payload"}:
        data = json.loads(record.read_text())
        if tamper == "signature":
            data["checkpoint"]["signature"] = base64.b64encode(b"x" * 64).decode()
        else:
            data["payload"] = "tampered"
        record.chmod(0o600)
        record.write_bytes(canonical(data))
    configuration = private_file(tmp_path / "reconcile.json", canonical(config))
    assert (
        audit_reconcile.main(
            [
                "--config",
                str(configuration),
                "--new-ledger",
                str(sink.path.parent / "new.sqlite"),
                "--minimum-sequence",
                "2" if tamper == "minimum_sequence" else "1",
                "--minimum-hash",
                "f" * 64 if tamper == "minimum_hash" else value["hash"],
            ]
        )
        == 1
    )


def test_status_publication_signature_expiry_and_revocation(tmp_path: Path) -> None:
    key_path = tmp_path / "key.pem"
    key = signing_key(key_path)
    fingerprint = "a" * 64
    registry = private_file(
        tmp_path / "registry.json", canonical({fingerprint: "good"})
    )
    destination = tmp_path / "public"
    destination.mkdir()
    config = private_file(
        tmp_path / "status.json",
        canonical(
            {
                "registry": str(registry),
                "private_key": str(key_path),
                "output_directory": str(destination),
            }
        ),
    )
    for state in ("good", "revoked"):
        registry.write_bytes(canonical({fingerprint: state}))
        assert certificate_status.main(["--config", str(config)]) == 0
        record = json.loads((destination / (fingerprint + ".json")).read_text())
        payload = base64.b64decode(record["payload"])
        key.public_key().verify(base64.b64decode(record["signature"]), payload)
        assertion = json.loads(payload)
        assert assertion["sha256"] == fingerprint and assertion["status"] == state
        assert assertion["expires"] - assertion["issued"] == 120
        assert list(destination.glob("*.pending")) == []
    registry.write_bytes(canonical({fingerprint: "unknown"}))
    assert certificate_status.main(["--config", str(config)]) == 1
    assert (
        json.loads(
            base64.b64decode(
                json.loads((destination / (fingerprint + ".json")).read_text())[
                    "payload"
                ]
            )
        )["status"]
        == "revoked"
    )
