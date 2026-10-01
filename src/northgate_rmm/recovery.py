"""Encrypted database snapshots and deliberately isolated logical restores.

The backup recipient is public; the online backup identity never holds the
decryption key. Secret stores and independent audit archives are backed up by
their own owners, not bundled with the application database.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from psycopg.conninfo import conninfo_to_dict

from northgate_rmm.agent_service import load_database_dsn
from northgate_rmm.errors import ValidationError
from northgate_rmm.persistence import PostgresControlPlane
from northgate_rmm.workload_service import canonical, load_configuration, read_private


def executable(value: str) -> str:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValidationError("absolute installed executable required")
    if os.name == "posix" and path.stat().st_mode & 0o022:
        raise ValidationError("executable is writable by non-owner")
    return str(path)


def run(arguments: list[str], environment: dict[str, str]) -> None:
    # No shell; credentials are never command arguments or captured diagnostics.
    subprocess.run(  # noqa: S603 - absolute owner-protected tools, no shell
        arguments,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=1800,
        check=True,
    )


def environment(dsn: str) -> dict[str, str]:
    result = {
        key: value for key, value in os.environ.items() if not key.startswith("PG")
    }
    fields = conninfo_to_dict(dsn)
    names = {
        "host": "PGHOST",
        "port": "PGPORT",
        "dbname": "PGDATABASE",
        "user": "PGUSER",
        "password": "PGPASSWORD",
        "sslmode": "PGSSLMODE",
        "sslrootcert": "PGSSLROOTCERT",
        "gssencmode": "PGGSSENCMODE",
    }
    if set(fields) - names.keys():
        raise ValidationError("unsupported recovery connection option")
    result.update({names[key]: str(value) for key, value in fields.items()})
    result["PGCONNECT_TIMEOUT"] = "5"
    return result


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def backup(config: dict[str, Any], destination: Path) -> None:
    if (
        not destination.is_absolute()
        or destination.exists()
        or destination.is_symlink()
    ):
        raise ValidationError("new absolute backup directory required")
    if shutil.disk_usage(destination.parent).free < 1024**3:
        raise ValidationError("backup capacity unavailable")
    dsn = load_database_dsn(Path(config["database_dsn_credential"]))
    destination.mkdir(mode=0o700)
    # A failed directory is deliberately retained and has no completed manifest.
    with tempfile.TemporaryDirectory(dir=destination, prefix=".staging-") as directory:
        dump = Path(directory) / "database.dump"
        run(
            [
                executable(config["pg_dump"]),
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--file",
                str(dump),
            ],
            environment(dsn),
        )
        if dump.stat().st_size > config.get("maximum_dump_bytes", 10 * 1024**3):
            raise ValidationError("backup exceeds capacity budget")
        archive = destination / "database.dump.age"
        run(
            [
                executable(config["age"]),
                "--encrypt",
                "--recipient",
                config["recipient"],
                "--output",
                str(archive),
                str(dump),
            ],
            environment(dsn),
        )
        manifest = {
            "format": 1,
            "deployment_id": config["deployment_id"],
            "ciphertext_sha256": digest(archive),
            "plaintext_sha256": digest(dump),
            "bytes": archive.stat().st_size,
        }
        signing_key = serialization.load_pem_private_key(
            read_private(config["manifest_private_key"]), None
        )
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise ValidationError("backup signing key invalid")
        signature = base64.b64encode(signing_key.sign(canonical(manifest))).decode(
            "ascii"
        )
        with (destination / "manifest.json").open("xb") as output:
            output.write(canonical({"manifest": manifest, "signature": signature}))
            output.flush()
            os.fsync(output.fileno())


def restore(config: dict[str, Any], source: Path) -> None:
    envelope = load_configuration(source / "manifest.json")
    public_key = serialization.load_pem_public_key(
        Path(config["manifest_public_key"]).read_bytes()
    )
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValidationError("independently pinned backup key invalid")
    manifest = envelope["manifest"]
    public_key.verify(
        base64.b64decode(envelope["signature"], validate=True), canonical(manifest)
    )
    archive = source / "database.dump.age"
    if archive.is_symlink() or manifest["ciphertext_sha256"] != digest(archive):
        raise ValidationError("backup integrity mismatch")
    if (
        config.get("isolated_restore") is not True
        or config["deployment_id"] != manifest["deployment_id"]
    ):
        raise ValidationError("isolated recovery configuration required")
    dsn = load_database_dsn(Path(config["database_dsn_credential"]))
    fields = conninfo_to_dict(dsn)
    if not str(fields.get("dbname", "")).startswith("northgate_restore_"):
        raise ValidationError("restore database must use the isolated recovery prefix")
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        row = connection.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'"
        ).fetchone()
        if row is None or row[0] != 0:
            raise ValidationError("restore target must be empty")
    with tempfile.TemporaryDirectory(prefix="northgate-recovery-") as directory:
        dump = Path(directory) / "database.dump"
        run(
            [
                executable(config["age"]),
                "--decrypt",
                "--identity",
                config["recovery_identity"],
                "--output",
                str(dump),
                str(archive),
            ],
            environment(dsn),
        )
        if digest(dump) != manifest["plaintext_sha256"]:
            raise ValidationError("decrypted backup integrity mismatch")
        run(
            [
                executable(config["pg_restore"]),
                "--dbname",
                str(fields["dbname"]),
                "--no-owner",
                "--no-acl",
                "--single-transaction",
                "--exit-on-error",
                str(dump),
            ],
            environment(dsn),
        )
    store = PostgresControlPlane(dsn)
    try:
        store.verify_schema_state()
    finally:
        store.begin_shutdown()
    # This command cannot reconnect services or clear the independent audit gate.


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("command", choices=("backup", "backup-auto", "restore"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        config = load_configuration(args.config)
        if args.command == "backup-auto":
            destination = args.directory / (
                datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + str(uuid4())
            )
            backup(config, destination)
        else:
            (backup if args.command == "backup" else restore)(config, args.directory)
    except Exception:
        print(
            "recovery operation incomplete; retained state requires reconciliation",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {"operation": args.command, "completed": True, "reconnection": False}
        )
    )
    return 0
