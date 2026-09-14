from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
from contextlib import closing, contextmanager
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from northgate_rmm.management_protocol import derive
from northgate_rmm.operations_backup import (
    backup,
    restore_database,
    stream_process,
    unpack,
    verify_chunks,
    verify_restore,
)


def setup(tmp_path):
    root = tmp_path / "remote"
    root.mkdir()
    (root / "operations-evidence").mkdir()
    for name in ("remote-sessions.sqlite3", "secrets.sqlite3"):
        path = root / name
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("CREATE TABLE sample(value TEXT)")
            db.execute("INSERT INTO sample VALUES('consistent snapshot')")
        path.chmod(0o600)
    key = b"s" * 16
    key_file = tmp_path / "remote-key"
    key_file.write_text(key.hex() + "\n")
    key_file.chmod(0o600)
    signer = Ed25519PrivateKey.generate()
    signing = tmp_path / "signing.pem"
    signing.write_bytes(
        signer.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signing.chmod(0o600)
    public = tmp_path / "signing-public.pem"
    public.write_bytes(
        signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    identity = tmp_path / "offline-identity"
    identity.write_text("synthetic offline identity used by the test transport")
    identity.chmod(0o600)
    base = {
        "deployment_id": str(uuid4()),
        "recipient": "age1" + "a" * 58,
        "age": str(Path(sys.executable).resolve()),
        "manifest_private_key": str(signing),
        "manifest_public_key": str(public),
        "recovery_identity": str(identity),
    }
    configuration = tmp_path / "recovery.json"
    configuration.write_text(json.dumps(base))
    configuration.chmod(0o600)
    config = {
        "recovery_config": str(configuration),
        "remote_root": str(root),
        "remote_key_credential": str(key_file),
        "maximum_archive_bytes": 8 * 1024**2,
        "isolated_restore": True,
    }
    value, identifier = b"retained case evidence", str(uuid4())
    checksum = hashlib.sha256(value).hexdigest()
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(derive(key, "operations-evidence")).encrypt(
        nonce, value, (identifier + "/0").encode()
    )
    chunk = root / "operations-evidence" / (identifier + ".0.aes")
    chunk.write_bytes(encrypted)
    chunk.chmod(0o600)
    record = {
        "id": identifier,
        "size": len(value),
        "sha256": checksum,
        "chunks": [{"chunk_index": 0, "size": len(value), "sha256": checksum}],
    }
    return config, record, chunk


@contextmanager
def test_archive_transport(path, _base):
    """Transparent fixture transport; this does not qualify the real age binary."""
    with path.open("xb") as stream:
        path.chmod(0o600)
        yield stream


test_archive_transport.__test__ = False


def snapshot_fixture(record):
    @contextmanager
    def snapshot(_base, staging, _budget):
        dump = staging / "operations.dump"
        dump.write_bytes(b"synthetic PostgreSQL custom dump placeholder")
        dump.chmod(0o600)
        yield dump, iter([record])

    return snapshot


def test_bundle_roundtrip_checks_sqlite_evidence_manifest_and_no_live_overwrite(
    tmp_path,
):
    config, record, _chunk = setup(tmp_path)
    destination, restored = tmp_path / "backup", tmp_path / "restored"
    receipt = backup(
        config,
        destination,
        snapshot=snapshot_fixture(record),
        encrypt=test_archive_transport,
    )
    assert receipt["format"] == "northgate-operations-v1"
    assert receipt["openbao_snapshot"] is None
    assert not list(destination.glob(".staging-*"))
    with pytest.raises(ValueError):
        backup(
            config,
            destination,
            snapshot=snapshot_fixture(record),
            encrypt=test_archive_transport,
        )
    calls = []

    def decrypt(arguments, _env, target, limit):
        assert arguments[1:3] == ["--decrypt", "--identity"]
        assert limit > (destination / "operations.tar.age").stat().st_size
        shutil.copyfile(arguments[-1], target)

    def restore(_base, path, key):
        calls.append(path)
        verify_chunks(record, path / "operations-evidence", key)
        with closing(sqlite3.connect(path / "secrets.sqlite3")) as db:
            assert (
                db.execute("SELECT value FROM sample").fetchone()[0]
                == "consistent snapshot"
            )

    result = verify_restore(
        config, destination, restored, decrypt=decrypt, restore=restore
    )
    assert result["verified"] and not result["reconnection"]
    assert calls == [restored]
    assert (restored / "restore-verification.json").is_file()
    assert not list(restored.glob(".decrypt-*"))
    assert not (tmp_path / "remote" / "restore-verification.json").exists()


def test_corrupt_completed_chunk_prevents_a_completed_backup_manifest(tmp_path):
    config, record, chunk = setup(tmp_path)
    data = bytearray(chunk.read_bytes())
    data[-1] ^= 1
    chunk.write_bytes(data)
    destination = tmp_path / "failed"
    with pytest.raises(InvalidTag):
        backup(
            config,
            destination,
            snapshot=snapshot_fixture(record),
            encrypt=test_archive_transport,
        )
    assert not (destination / "manifest.json").exists()
    assert not list(destination.glob(".staging-*"))


def test_modified_signed_manifest_rejected_before_restore_directory_creation(tmp_path):
    config, record, _chunk = setup(tmp_path)
    destination, restored = tmp_path / "backup", tmp_path / "restored"
    backup(
        config,
        destination,
        snapshot=snapshot_fixture(record),
        encrypt=test_archive_transport,
    )
    path = destination / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["manifest"]["ciphertext_bytes"] += 1
    path.write_text(json.dumps(manifest))
    with pytest.raises(InvalidSignature):
        verify_restore(config, destination, restored)
    assert not restored.exists()


@pytest.mark.parametrize(
    "name",
    ["../outside", "/absolute", "secret.txt", "operations-evidence/../secret.aes"],
)
def test_restore_rejects_non_allowlisted_paths(tmp_path, name):
    archive = tmp_path / "bad.tar"
    with tarfile.open(archive, "w") as tar:
        member = tarfile.TarInfo(name)
        member.size = 1
        tar.addfile(member, io.BytesIO(b"x"))
    destination = tmp_path / "target"
    destination.mkdir()
    with pytest.raises(ValueError, match="non-allowlisted"):
        unpack(archive, destination, 1024**2, "0" * 64)
    assert list(destination.iterdir()) == []


def test_streaming_subprocess_limit_stops_excess_output(tmp_path):
    destination = tmp_path / "bounded"
    with pytest.raises(ValueError, match="output budget"):
        stream_process(
            [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*2000000)"],
            os.environ.copy(),
            destination,
            1000000,
        )
    assert destination.stat().st_size <= 1000000


def test_snapshot_link_is_preserved_under_signature(tmp_path):
    config, record, _chunk = setup(tmp_path)
    receipt = {
        "snapshot_id": str(uuid4()),
        "sha256": "b" * 64,
        "created_at": "2026-09-10T00:00:00+00:00",
    }
    path = tmp_path / "raft-receipt.json"
    path.write_text(json.dumps(receipt))
    path.chmod(0o600)
    config["openbao_snapshot_receipt"] = str(path)
    public = backup(
        config,
        tmp_path / "backup",
        snapshot=snapshot_fixture(record),
        encrypt=test_archive_transport,
    )
    assert public["openbao_snapshot"] == receipt


@pytest.mark.parametrize(
    "dbname", ["northgate_rmm", "northgate_restore_x host=other", "northgate_restore_"]
)
def test_restore_database_rejects_live_name_before_connecting(
    tmp_path, monkeypatch, dbname
):
    from psycopg.conninfo import make_conninfo

    monkeypatch.setattr(
        "northgate_rmm.operations_backup.load_database_dsn",
        lambda _: make_conninfo(dbname=dbname, user="restore"),
    )

    def forbidden_connect(*_args, **_kwargs):
        pytest.fail("A live database must not be contacted")

    monkeypatch.setattr(
        "northgate_rmm.operations_backup.psycopg.connect", forbidden_connect
    )
    with pytest.raises(ValueError, match="isolated recovery database"):
        restore_database({"database_dsn_credential": "synthetic"}, tmp_path, b"x" * 32)


def test_modified_ciphertext_rejected_without_decryption(tmp_path):
    config, record, _chunk = setup(tmp_path)
    destination, restored = tmp_path / "backup", tmp_path / "restored"
    backup(
        config,
        destination,
        snapshot=snapshot_fixture(record),
        encrypt=test_archive_transport,
    )
    with (destination / "operations.tar.age").open("ab") as output:
        output.write(b"unexpected trailing data")
    with pytest.raises(ValueError, match="Encrypted backup integrity"):
        verify_restore(config, destination, restored)
    assert not restored.exists()


def test_missing_selected_database_does_not_silently_complete(tmp_path):
    config, record, _chunk = setup(tmp_path)
    (tmp_path / "remote" / "secrets.sqlite3").unlink()
    from northgate_rmm.errors import ValidationError

    with pytest.raises(ValidationError):
        backup(
            config,
            tmp_path / "backup",
            snapshot=snapshot_fixture(record),
            encrypt=test_archive_transport,
        )
    assert not (tmp_path / "backup" / "manifest.json").exists()
