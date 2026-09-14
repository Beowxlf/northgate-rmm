"""Streaming, age-encrypted operations backups and isolated restore verification.

The v1 operations bundle supplements existing core/management backups. It neither
changes their formats nor reconnects restored state to a running RMM service.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

from northgate_rmm.agent_service import load_database_dsn
from northgate_rmm.management_protocol import derive
from northgate_rmm.operations_models import MAX_CHUNK
from northgate_rmm.recovery import digest, environment, executable, run
from northgate_rmm.secure_files import regular_file_reference
from northgate_rmm.workload_service import canonical, load_configuration, read_private

FORMAT = "northgate-operations-v1"
SQLITE_SOURCES = frozenset(
    {
        "management/management.sqlite3",
        "captures/capture.sqlite3",
        "inspection.sqlite3",
        "remote-sessions.sqlite3",
        "secrets.sqlite3",
    }
)
FIXED_MEMBERS = SQLITE_SOURCES | {
    "operations.dump",
    "evidence-index.jsonl",
    "remote-credentials.aes",
}
MAX_MEMBERS = 20000
MAX_MANIFEST = 16 * 1024 * 1024
DEFAULT_BUDGET = 8 * 1024**3
CHUNK_NAME = re.compile(r"operations-evidence/([0-9a-f-]{36})\.([0-9]{1,3})\.aes\Z")


def private_bytes(path, maximum):
    with regular_file_reference(
        Path(path), label="recovery input", maximum_bytes=maximum, private=True
    ) as held:
        return held.read_bytes()


def evidence_key(config):
    encoded = private_bytes(config["remote_key_credential"], 64).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", encoded):
        raise ValueError("The preserved remote evidence key is invalid")
    return derive(bytes.fromhex(encoded), "operations-evidence")


def source_path(root, name):
    path = root / name
    if any(part.is_symlink() for part in [path, *path.parents]):
        raise ValueError("Backup source path must not traverse symbolic links")
    return path


def new_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError("A new absolute directory is required")
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Recovery directory ancestors must not be symbolic links")
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def exclusive(path):
    return os.fdopen(
        os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        ),
        "wb",
    )


def settings(config):
    base = load_configuration(Path(config["recovery_config"]))
    for name in (
        "database_dsn_credential",
        "manifest_private_key",
        "manifest_public_key",
        "recovery_identity",
        "pg_restore",
    ):
        if name in config:
            base[name] = config[name]
    recipient = base["recipient"]
    if not isinstance(recipient, str) or not re.fullmatch(
        r"age1[0-9a-z]{50,100}", recipient
    ):
        raise ValueError("Configured independent age recipient is required")
    budget = config.get("maximum_archive_bytes", DEFAULT_BUDGET)
    if type(budget) is not int or not 1024**2 <= budget <= 64 * 1024**3:
        raise ValueError("Invalid archive budget")
    selected = config.get(
        "sqlite_sources", ["remote-sessions.sqlite3", "secrets.sqlite3"]
    )
    if (
        not isinstance(selected, list)
        or not selected
        or len(selected) != len(set(selected))
        or not set(selected) <= SQLITE_SOURCES
    ):
        raise ValueError("Invalid SQLite snapshot selection")
    root = Path(config["remote_root"])
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ValueError("Existing private RMM state root is required")
    return base, budget, selected, root


def stream_process(arguments, env, destination, limit):
    """Bound subprocess output on disk and in memory; suppress raw diagnostics."""
    with exclusive(destination) as output:
        process = subprocess.Popen(  # noqa: S603 - installed executables, no shell
            arguments,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        timer = threading.Timer(1800, process.kill)
        timer.daemon = True
        timer.start()
        try:
            count = 0
            while chunk := process.stdout.read(1024 * 1024):
                count += len(chunk)
                if count > limit:
                    raise ValueError("Recovery subprocess exceeded its output budget")
                output.write(chunk)
            if process.wait(timeout=30) != 0:
                raise ValueError("Recovery subprocess failed")
            output.flush()
            os.fsync(output.fileno())
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


@contextmanager
def age_writer(path, base):
    with exclusive(path) as output:
        arguments = [
            executable(base["age"]),
            "--encrypt",
            "--recipient",
            base["recipient"],
        ]
        process = subprocess.Popen(  # noqa: S603 - installed age executable, no shell
            arguments,
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=subprocess.DEVNULL,
        )
        timer = threading.Timer(1800, process.kill)
        timer.daemon = True
        timer.start()
        try:
            yield process.stdin
            process.stdin.close()
            if process.wait(timeout=30) != 0:
                raise ValueError("Age encryption failed")
            output.flush()
            os.fsync(output.fileno())
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            if not process.stdin.closed:
                process.stdin.close()


class Bundle:
    def __init__(self, archive, budget):
        self.archive, self.budget = archive, budget
        self.members, self.total = {}, 0

    def add(self, name, stream, size):
        if (
            not valid_member(name)
            or name in self.members
            or len(self.members) >= MAX_MEMBERS
        ):
            raise ValueError("Invalid or duplicate backup member")
        if type(size) is not int or size < 0 or self.total + size > self.budget:
            raise ValueError("Backup exceeds its archive budget")
        checksum = hashlib.sha256()

        class Reader:
            def read(self, amount):
                value = stream.read(amount)
                checksum.update(value)
                return value

        member = tarfile.TarInfo(name)
        member.size, member.mode = size, 0o600
        self.archive.addfile(member, Reader())
        self.members[name] = {"size": size, "sha256": checksum.hexdigest()}
        self.total += size

    def file(self, name, path):
        with (
            regular_file_reference(
                Path(path),
                label="backup member",
                maximum_bytes=self.budget,
                private=True,
            ) as held,
            held.open("rb") as stream,
        ):
            self.add(name, stream, os.fstat(stream.fileno()).st_size)


def valid_member(name):
    if name in FIXED_MEMBERS:
        return True
    matched = CHUNK_NAME.fullmatch(name)
    if not matched:
        return False
    try:
        return str(UUID(matched[1])) == matched[1] and 0 <= int(matched[2]) < 128
    except ValueError:
        return False


def sqlite_snapshot(source, target, limit):
    # Hold and validate the source inode while SQLite takes its online snapshot.
    with regular_file_reference(
        source, label="SQLite state", maximum_bytes=limit, private=True
    ):
        with exclusive(target):
            pass
        started = datetime.now(UTC)

        def progress(_status, _remaining, _total):
            if (
                datetime.now(UTC) - started
            ).total_seconds() > 120 or target.stat().st_size > limit:
                raise ValueError("SQLite snapshot exceeded its budget")

        with (
            closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as db,
            closing(sqlite3.connect(target)) as out,
        ):
            db.backup(out, pages=256, progress=progress, sleep=0.01)
            if out.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("SQLite snapshot integrity failed")


def artifact_rows(connection):
    with connection.cursor(
        name="ops_recovery_artifacts", row_factory=dict_row
    ) as cursor:
        cursor.execute(
            "SELECT id,size,sha256 FROM ops_artifacts "
            "WHERE state='complete' ORDER BY id"
        )
        for row in cursor:
            chunks = connection.execute(
                "SELECT chunk_index,size,sha256 FROM ops_chunks "
                "WHERE artifact=%s ORDER BY chunk_index",
                (row["id"],),
            ).fetchall()
            yield {
                "id": row["id"],
                "size": row["size"],
                "sha256": row["sha256"],
                "chunks": [dict(c) for c in chunks],
            }


def verify_chunks(record, root, key, add=None):
    if root.is_symlink():
        raise ValueError("Evidence root must not be a symbolic link")
    identifier = str(UUID(record["id"]))
    if (
        identifier != record["id"]
        or not isinstance(record["chunks"], list)
        or len(record["chunks"]) > 128
    ):
        raise ValueError("Invalid completed artifact")
    checksum, size = hashlib.sha256(), 0
    for position, chunk in enumerate(record["chunks"]):
        if (
            chunk["chunk_index"] != position
            or type(chunk["size"]) is not int
            or not 0 < chunk["size"] <= MAX_CHUNK
        ):
            raise ValueError("Invalid completed chunk sequence")
        name = f"{identifier}.{position}.aes"
        encrypted = private_bytes(source_path(root, name), MAX_CHUNK + 64)
        value = AESGCM(key).decrypt(
            encrypted[:12], encrypted[12:], f"{identifier}/{position}".encode()
        )
        if (
            len(value) != chunk["size"]
            or hashlib.sha256(value).hexdigest() != chunk["sha256"]
        ):
            raise ValueError("Completed chunk integrity failed")
        checksum.update(value)
        size += len(value)
        if add:
            add("operations-evidence/" + name, io.BytesIO(encrypted), len(encrypted))
    if size != record["size"] or checksum.hexdigest() != record["sha256"]:
        raise ValueError("Completed artifact integrity failed")


@contextmanager
def postgres_snapshot(base, staging, budget):
    dsn = load_database_dsn(Path(base["database_dsn_credential"]))
    with psycopg.connect(
        dsn, connect_timeout=5, autocommit=True, row_factory=dict_row
    ) as connection:
        connection.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        try:
            connection.execute("SET LOCAL statement_timeout='30s'")
            version = connection.execute(
                "SELECT max(version) AS version FROM ops_schema"
            ).fetchone()
            if version["version"] != 1:
                raise ValueError("Unsupported operations schema")
            snapshot = connection.execute(
                "SELECT pg_export_snapshot() AS snapshot"
            ).fetchone()["snapshot"]
            if not re.fullmatch(r"[0-9A-Fa-f-]{1,128}", snapshot):
                raise ValueError("Invalid PostgreSQL snapshot identity")
            dump = staging / "operations.dump"
            stream_process(
                [
                    executable(base["pg_dump"]),
                    "--format=custom",
                    "--no-owner",
                    "--no-acl",
                    "--strict-names",
                    "--table=public.ops_*",
                    "--snapshot=" + snapshot,
                ],
                environment(dsn),
                dump,
                budget,
            )
            yield dump, artifact_rows(connection)
        finally:
            connection.execute("ROLLBACK")


def snapshot_link(config):
    path = config.get("openbao_snapshot_receipt")
    if path is None:
        return None
    record = json.loads(private_bytes(path, 8192))
    if set(record) != {"snapshot_id", "sha256", "created_at"}:
        raise ValueError("Invalid independent OpenBao snapshot receipt")
    if str(UUID(record["snapshot_id"])) != record["snapshot_id"] or not re.fullmatch(
        r"[0-9a-f]{64}", record["sha256"]
    ):
        raise ValueError("Invalid OpenBao snapshot reference")
    if (
        datetime.fromisoformat(record["created_at"].replace("Z", "+00:00")).tzinfo
        is None
    ):
        raise ValueError("Snapshot receipt requires a timezone")
    return record


def backup(config, destination, *, snapshot=postgres_snapshot, encrypt=age_writer):
    base, budget, selected, root = settings(config)
    key = evidence_key(config)
    signing_key = serialization.load_pem_private_key(
        read_private(base["manifest_private_key"]), None
    )
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise ValueError("Expected approved Ed25519 backup signing identity")
    if shutil.disk_usage(Path(destination).parent).free < 3 * budget:
        raise ValueError("Backup capacity budget unavailable")
    destination = new_directory(destination)
    archive = destination / "operations.tar.age"
    with tempfile.TemporaryDirectory(dir=destination, prefix=".staging-") as temporary:
        staging = Path(temporary)
        staging.chmod(0o700)
        with (
            snapshot(base, staging, budget) as (dump, records),
            encrypt(archive, base) as stream,
            tarfile.open(fileobj=stream, mode="w|", format=tarfile.USTAR_FORMAT) as tar,
        ):
            bundle = Bundle(tar, budget)
            bundle.file("operations.dump", dump)
            for name in selected:
                target = staging / (
                    hashlib.sha256(name.encode()).hexdigest() + ".sqlite3"
                )
                sqlite_snapshot(source_path(root, name), target, budget - bundle.total)
                bundle.file(name, target)
            if config.get("credentials_file"):
                bundle.file("remote-credentials.aes", Path(config["credentials_file"]))
            index = staging / "evidence-index.jsonl"
            count = 0
            with exclusive(index) as output:
                for record in records:
                    count += 1
                    if count > MAX_MEMBERS:
                        raise ValueError("Too many completed artifacts")
                    verify_chunks(record, root / "operations-evidence", key, bundle.add)
                    line = canonical(record) + b"\n"
                    if output.tell() + len(line) > MAX_MANIFEST:
                        raise ValueError("Evidence index exceeded its budget")
                    output.write(line)
            bundle.file("evidence-index.jsonl", index)
            manifest = {
                "format": FORMAT,
                "deployment_id": base["deployment_id"],
                "created_at": datetime.now(UTC).isoformat(),
                "files": bundle.members,
                "completed_artifacts": count,
                "transient_uploads_excluded": True,
                "openbao_snapshot": snapshot_link(config),
            }
            encoded = canonical(manifest)
            if len(encoded) > MAX_MANIFEST:
                raise ValueError("Archive manifest exceeds its budget")
            member = tarfile.TarInfo("manifest.json")
            member.size, member.mode = len(encoded), 0o600
            tar.addfile(member, io.BytesIO(encoded))
        public = {
            "format": FORMAT,
            "deployment_id": base["deployment_id"],
            "ciphertext_sha256": digest(archive),
            "ciphertext_bytes": archive.stat().st_size,
            "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
            "openbao_snapshot": manifest["openbao_snapshot"],
        }
        if public["ciphertext_bytes"] > budget + 32 * 1024 * 1024:
            raise ValueError("Ciphertext exceeds its budget")
        envelope = {
            "manifest": public,
            "signature": base64.b64encode(signing_key.sign(canonical(public))).decode(),
        }
        with exclusive(destination / "manifest.json") as output:
            output.write(canonical(envelope))
            output.flush()
            os.fsync(output.fileno())
    return public


def unpack(archive, destination, budget, expected_hash):
    observed, total, encoded = {}, 0, None
    with tarfile.open(archive, mode="r|") as tar:
        for member in tar:
            if (
                not member.isfile()
                or member.size < 0
                or member.name in observed
                or len(observed) >= MAX_MEMBERS + 1
            ):
                raise ValueError("Invalid recovery archive member")
            if member.name == "manifest.json":
                if encoded is not None or member.size > MAX_MANIFEST:
                    raise ValueError("Invalid archive manifest")
            elif not valid_member(member.name):
                raise ValueError("Archive contains a non-allowlisted path")
            total += member.size
            if total > budget + MAX_MANIFEST:
                raise ValueError("Recovery expansion exceeded its budget")
            reader = tar.extractfile(member)
            if reader is None:
                raise ValueError("Missing member data")
            if member.name == "manifest.json":
                encoded = reader.read(MAX_MANIFEST + 1)
                continue
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            checksum, copied = hashlib.sha256(), 0
            with exclusive(target) as output:
                while value := reader.read(1024 * 1024):
                    copied += len(value)
                    checksum.update(value)
                    output.write(value)
            if copied != member.size:
                raise ValueError("Incomplete recovery archive member")
            observed[member.name] = {"size": copied, "sha256": checksum.hexdigest()}
    if encoded is None or hashlib.sha256(encoded).hexdigest() != expected_hash:
        raise ValueError("Archive manifest authentication mismatch")
    manifest = json.loads(encoded)
    if manifest.get("format") != FORMAT or manifest.get("files") != observed:
        raise ValueError("Recovery files do not match their manifest")
    if not {"operations.dump", "evidence-index.jsonl"} <= observed.keys():
        raise ValueError("Recovery bundle is incomplete")
    for name in observed.keys() & SQLITE_SOURCES:
        with closing(
            sqlite3.connect((destination / name).as_uri() + "?mode=ro", uri=True)
        ) as db:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Restored SQLite state failed verification")
    return manifest


def restore_database(base, destination, key):
    dsn = load_database_dsn(Path(base["database_dsn_credential"]))
    fields = conninfo_to_dict(dsn)
    if not re.fullmatch(
        r"northgate_restore_[a-z0-9_]{1,45}", str(fields.get("dbname", ""))
    ):
        raise ValueError("Only an isolated recovery database is permitted")
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        count = connection.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
        ).fetchone()[0]
        if count:
            raise ValueError("The isolated recovery database must be empty")
    run(
        [
            executable(base["pg_restore"]),
            "--dbname",
            fields["dbname"],
            "--no-owner",
            "--no-acl",
            "--single-transaction",
            "--exit-on-error",
            str(destination / "operations.dump"),
        ],
        environment(dsn),
    )
    with psycopg.connect(dsn, connect_timeout=5, row_factory=dict_row) as connection:
        version = connection.execute(
            "SELECT max(version) AS version FROM ops_schema"
        ).fetchone()
        if version["version"] != 1:
            raise ValueError("Unsupported restored operations schema")
        with (destination / "evidence-index.jsonl").open("rb") as index:
            for record in artifact_rows(connection):
                expected = json.loads(index.readline(65537))
                if expected != record:
                    raise ValueError(
                        "Restored evidence differs from PostgreSQL snapshot"
                    )
                verify_chunks(record, destination / "operations-evidence", key)
            if index.read(1):
                raise ValueError("Restored evidence index has unexpected records")
        # In-flight uploads are not completed evidence and cannot resume after restore.
        connection.execute(
            "DELETE FROM ops_chunks WHERE artifact IN "
            "(SELECT id FROM ops_artifacts WHERE state <> 'complete')"
        )
        connection.execute(
            "UPDATE ops_artifacts SET state='cancelled',retained=0 "
            "WHERE state <> 'complete'"
        )


def verify_restore(
    config, source, destination, *, decrypt=stream_process, restore=restore_database
):
    base, budget, _selected, _root = settings(config)
    if config.get("isolated_restore") is not True:
        raise ValueError("Explicit isolated restore configuration is required")
    source = Path(source)
    envelope = json.loads(private_bytes(source / "manifest.json", MAX_MANIFEST))
    public = envelope["manifest"]
    with regular_file_reference(
        Path(base["manifest_public_key"]),
        label="independent backup public key",
        maximum_bytes=65536,
        private=False,
    ) as held:
        signing_key = serialization.load_pem_public_key(held.read_bytes())
    if not isinstance(signing_key, Ed25519PublicKey):
        raise ValueError("An independently pinned Ed25519 key is required")
    signing_key.verify(
        base64.b64decode(envelope["signature"], validate=True), canonical(public)
    )
    archive = source / "operations.tar.age"
    with regular_file_reference(
        archive,
        label="encrypted backup",
        maximum_bytes=budget + 32 * 1024 * 1024,
        private=True,
    ):
        if (
            public.get("format") != FORMAT
            or public.get("deployment_id") != base["deployment_id"]
            or archive.stat().st_size != public["ciphertext_bytes"]
            or digest(archive) != public["ciphertext_sha256"]
        ):
            raise ValueError("Encrypted backup integrity mismatch")
    if shutil.disk_usage(Path(destination).parent).free < 3 * budget:
        raise ValueError("Isolated restore capacity budget unavailable")
    destination = new_directory(destination)
    key = evidence_key(config)
    # Validate custody; the installed age process alone reads the private identity.
    with (
        regular_file_reference(
            Path(base["recovery_identity"]),
            label="offline age identity",
            maximum_bytes=65536,
            private=True,
        ),
        tempfile.TemporaryDirectory(dir=destination, prefix=".decrypt-") as temporary,
    ):
        tar_path = Path(temporary) / "operations.tar"
        decrypt(
            [
                executable(base["age"]),
                "--decrypt",
                "--identity",
                base["recovery_identity"],
                str(archive),
            ],
            {},
            tar_path,
            budget + 32 * 1024 * 1024,
        )
        manifest = unpack(tar_path, destination, budget, public["manifest_sha256"])
    if manifest["deployment_id"] != base["deployment_id"] or manifest.get(
        "openbao_snapshot"
    ) != public.get("openbao_snapshot"):
        raise ValueError("Bundle deployment linkage mismatch")
    restore(base, destination, key)
    result = {
        "format": FORMAT,
        "verified": True,
        "reconnection": False,
        "completed_artifacts": manifest["completed_artifacts"],
        "openbao_snapshot": manifest.get("openbao_snapshot"),
    }
    with exclusive(destination / "restore-verification.json") as output:
        output.write(canonical(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("backup", "backup-auto"):
        sub.add_parser(command).add_argument("destination", type=Path)
    verify = sub.add_parser("verify-restore")
    verify.add_argument("source", type=Path)
    verify.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        config = load_configuration(args.config)
        if args.command == "verify-restore":
            result = verify_restore(config, args.source, args.destination)
        else:
            destination = args.destination
            if args.command == "backup-auto":
                destination = destination / (
                    datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + str(uuid4())
                )
            result = backup(config, destination)
    except Exception:
        print(
            "Operations recovery incomplete; retained state requires reconciliation",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "operation": args.command,
                "completed": True,
                "reconnection": False,
                "format": result["format"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
