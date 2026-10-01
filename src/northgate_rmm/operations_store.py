"""Transactional operations records and encrypted, resumable evidence custody.

PostgreSQL is the deployment adapter. SQLite is an explicit test adapter, with
the same transactions, constraints, idempotency and evidence implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from northgate_rmm.management_protocol import derive
from northgate_rmm.operations_models import (
    MAX_ARTIFACT,
    MAX_CHUNK,
    bounded_json,
    check_secrets,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS ops_schema (version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS ops_records (
 kind TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
 created DOUBLE PRECISION NOT NULL, updated DOUBLE PRECISION NOT NULL,
 subject TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS ops_versions (
 kind TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
 created DOUBLE PRECISION NOT NULL, subject TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(kind,id,revision));
CREATE TABLE IF NOT EXISTS ops_scopes (
 kind TEXT NOT NULL, id TEXT NOT NULL, endpoint TEXT NOT NULL,
 PRIMARY KEY(kind,id,endpoint), FOREIGN KEY(kind,id) REFERENCES ops_records(kind,id));
CREATE TABLE IF NOT EXISTS ops_events (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, record_id TEXT NOT NULL,
 created DOUBLE PRECISION NOT NULL, subject TEXT NOT NULL, action TEXT NOT NULL,
 payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ops_events_record ON ops_events(kind,record_id,created,id);
CREATE TABLE IF NOT EXISTS ops_enrollments (
 endpoint TEXT NOT NULL, identity TEXT NOT NULL, asset TEXT NOT NULL,
 created DOUBLE PRECISION NOT NULL, subject TEXT NOT NULL, reason TEXT NOT NULL,
 PRIMARY KEY(endpoint,identity));
CREATE TABLE IF NOT EXISTS ops_requests (
 subject TEXT NOT NULL, id TEXT NOT NULL, digest TEXT NOT NULL,
 created DOUBLE PRECISION NOT NULL, response TEXT NOT NULL, PRIMARY KEY(subject,id));
CREATE TABLE IF NOT EXISTS ops_alert_sources (
 source TEXT NOT NULL, external_id TEXT NOT NULL, digest TEXT NOT NULL,
 record_id TEXT NOT NULL, received DOUBLE PRECISION NOT NULL,
 repeats INTEGER NOT NULL, PRIMARY KEY(source,external_id));
CREATE TABLE IF NOT EXISTS ops_artifacts (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL, subject TEXT NOT NULL,
 created DOUBLE PRECISION NOT NULL, updated DOUBLE PRECISION NOT NULL,
 state TEXT NOT NULL, name TEXT NOT NULL, size BIGINT NOT NULL,
 sha256 TEXT NOT NULL, media_type TEXT NOT NULL, retained INTEGER NOT NULL,
 provenance TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL);
CREATE INDEX IF NOT EXISTS ops_artifacts_case ON ops_artifacts(case_id,created);
CREATE TABLE IF NOT EXISTS ops_chunks (
 artifact TEXT NOT NULL, chunk_index INTEGER NOT NULL, size INTEGER NOT NULL,
 sha256 TEXT NOT NULL, PRIMARY KEY(artifact,chunk_index),
 FOREIGN KEY(artifact) REFERENCES ops_artifacts(id));
"""


class Conflict(ValueError):
    """Stale revision or reused idempotency key with different intent."""


class Database:
    def __init__(self, connection: Any, postgres: Any) -> None:
        self.connection, self.postgres = connection, postgres

    def execute(self, sql: Any, params: Any = ()) -> Any:
        return self.connection.execute(
            sql.replace("?", "%s") if self.postgres else sql, params
        )


class OperationsStore:
    def __init__(
        self, dsn: Any, artifact_root: Any, key: bytes, *, test_sqlite: bool = False
    ) -> None:
        self.dsn, self.test_sqlite = str(dsn), test_sqlite
        self.root = Path(artifact_root)
        if self.root.is_symlink():
            raise ValueError("Artifact root cannot be a symbolic link")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            self.root.chmod(0o700)
        self.key = derive(key, "operations-evidence")
        self.lock = threading.RLock()

    @classmethod
    def postgres(cls, dsn: Any, artifact_root: Any, key: bytes) -> Any:
        return cls(dsn, artifact_root, key)

    @classmethod
    def sqlite_for_tests(cls, database: Any, artifact_root: Any, key: bytes) -> Any:
        result = cls(database, artifact_root, key, test_sqlite=True)
        result.migrate()
        return result

    @contextmanager
    def connection(self, write: bool = False) -> Iterator[Database]:
        connection: Any
        if self.test_sqlite:
            connection = sqlite3.connect(self.dsn, timeout=15)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            if write:
                connection.execute("BEGIN IMMEDIATE")
        else:
            import psycopg
            from psycopg.rows import dict_row

            connection = psycopg.connect(
                self.dsn, row_factory=dict_row, connect_timeout=10
            )
            connection.execute("SET LOCAL statement_timeout = '15s'")
            if write:
                connection.execute("SELECT pg_advisory_xact_lock(7104771042)")
        try:
            with connection:
                yield Database(connection, not self.test_sqlite)
        finally:
            connection.close()

    def migrate(self) -> None:
        """Explicit deployment migration; application startup only verifies it."""
        with self.lock, self.connection(write=True) as db:
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    db.execute(statement)
            db.execute(
                "INSERT INTO ops_schema(version) VALUES(1) "
                "ON CONFLICT(version) DO NOTHING"
            )

    def verify(self) -> None:
        with self.connection() as db:
            row = db.execute(
                "SELECT version FROM ops_schema ORDER BY version DESC LIMIT 1"
            ).fetchone()
            if row is None or row["version"] != 1:
                raise ValueError("Operations schema migration is required")

    def transaction(
        self, subject: str, request_id: str, value: Any, callback: Any
    ) -> Any:
        digest = hashlib.sha256(bounded_json(value, 2 * MAX_CHUNK).encode()).hexdigest()
        with self.lock, self.connection(write=True) as db:
            row = db.execute(
                "SELECT * FROM ops_requests WHERE subject=? AND id=?",
                (subject, request_id),
            ).fetchone()
            if row:
                if row["digest"] != digest:
                    raise Conflict(
                        "Request identifier was already used for different content"
                    )
                return json.loads(row["response"])
            response = callback(db)
            encoded = bounded_json(response, MAX_ARTIFACT * 2)
            db.execute(
                "INSERT INTO ops_requests VALUES(?,?,?,?,?)",
                (subject, request_id, digest, time.time(), encoded),
            )
            return response

    @staticmethod
    def decode(row: Any) -> Any:
        return {
            **{
                k: row[k]
                for k in ("kind", "id", "revision", "created", "updated", "subject")
            },
            "value": json.loads(row["payload"]),
        }

    def get(self, kind: str, identifier: Any, db: Any = None) -> Any:
        if db is None:
            with self.connection() as connection:
                return self.get(kind, identifier, connection)
        row = db.execute(
            "SELECT * FROM ops_records WHERE kind=? AND id=?", (kind, identifier)
        ).fetchone()
        if row is None:
            raise KeyError("Record not found")
        return self.decode(row)

    def records(self, kind: str, limit: int = 2000, db: Any = None) -> Any:
        if db is None:
            with self.connection() as connection:
                return self.records(kind, limit, connection)
        return [
            self.decode(r)
            for r in db.execute(
                "SELECT * FROM ops_records WHERE kind=? "
                "ORDER BY updated DESC,id LIMIT ?",
                (kind, limit),
            ).fetchall()
        ]

    def put(
        self,
        db: Any,
        kind: str,
        identifier: Any,
        value: Any,
        subject: str,
        revision: Any,
        action: str = "record.saved",
    ) -> Any:
        now = time.time()
        payload = bounded_json(value)
        old = db.execute(
            "SELECT revision FROM ops_records WHERE kind=? AND id=?", (kind, identifier)
        ).fetchone()
        if (
            type(revision) is not int
            or revision < 0
            or (old is None and revision != 0)
            or (old is not None and old["revision"] != revision)
        ):
            raise Conflict("Record changed; reload it before saving")
        if old is None:
            count = db.execute("SELECT count(*) AS n FROM ops_records").fetchone()["n"]
            if count >= 100000:
                raise ValueError("Operations record capacity reached")
            db.execute(
                "INSERT INTO ops_records VALUES(?,?,?,?,?,?,?)",
                (kind, identifier, 1, now, now, subject, payload),
            )
        else:
            db.execute(
                "UPDATE ops_records SET revision=?,updated=?,subject=?,payload=? "
                "WHERE kind=? AND id=?",
                (revision + 1, now, subject, payload, kind, identifier),
            )
        db.execute(
            "INSERT INTO ops_versions VALUES(?,?,?,?,?,?)",
            (kind, identifier, revision + 1, now, subject, payload),
        )
        db.execute("DELETE FROM ops_scopes WHERE kind=? AND id=?", (kind, identifier))
        for endpoint in value.get("endpoints", []):
            db.execute(
                "INSERT INTO ops_scopes VALUES(?,?,?)", (kind, identifier, endpoint)
            )
        self.event(db, kind, identifier, subject, action, {"revision": revision + 1})
        return self.get(kind, identifier, db)

    @staticmethod
    def event(
        db: Any, kind: str, identifier: Any, subject: str, action: str, value: Any
    ) -> dict[str, Any]:
        event = {
            "id": str(uuid4()),
            "kind": kind,
            "record_id": identifier,
            "created": time.time(),
            "subject": subject,
            "action": action,
            "value": value,
        }
        db.execute(
            "INSERT INTO ops_events VALUES(?,?,?,?,?,?,?)",
            (
                event["id"],
                kind,
                identifier,
                event["created"],
                subject,
                action,
                bounded_json(value),
            ),
        )
        return event

    def history(
        self, kind: str, identifier: Any, before: Any = None, limit: int = 200
    ) -> Any:
        before = float(before) if before is not None else time.time() + 1
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM ops_events WHERE kind=? AND record_id=? "
                "AND created<? ORDER BY created DESC,id DESC LIMIT ?",
                (kind, identifier, before, limit),
            ).fetchall()
            return [{**dict(r), "value": json.loads(r["payload"])} for r in rows]

    def versions(self, kind: str, identifier: Any) -> Any:
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM ops_versions WHERE kind=? AND id=? "
                "ORDER BY revision DESC LIMIT 100",
                (kind, identifier),
            ).fetchall()
            return [
                {
                    "revision": r["revision"],
                    "created": r["created"],
                    "subject": r["subject"],
                    "value": json.loads(r["payload"]),
                }
                for r in rows
            ]

    def artifact(self, identifier: Any, db: Any = None) -> Any:
        if db is None:
            with self.connection() as connection:
                return self.artifact(identifier, connection)
        row = db.execute(
            "SELECT * FROM ops_artifacts WHERE id=?", (identifier,)
        ).fetchone()
        if row is None:
            raise KeyError("Evidence not found")
        result = dict(row)
        result["provenance"] = json.loads(result["provenance"])
        result["chunks"] = [
            dict(r)
            for r in db.execute(
                "SELECT chunk_index,size,sha256 FROM ops_chunks WHERE artifact=? "
                "ORDER BY chunk_index",
                (identifier,),
            ).fetchall()
        ]
        result["received"] = sum(v["size"] for v in result["chunks"])
        return result

    def artifacts(self, case: Any) -> Any:
        with self.connection() as db:
            rows = db.execute(
                "SELECT id FROM ops_artifacts WHERE case_id=? "
                "ORDER BY created DESC LIMIT 1000",
                (case,),
            ).fetchall()
            return [self.artifact(r["id"], db) for r in rows]

    def begin_artifact(
        self, db: Any, case: Any, subject: str, value: Any, provenance: Any
    ) -> Any:
        size = value["size"]
        if type(size) is not int or not 0 < size <= MAX_ARTIFACT:
            raise ValueError("Evidence must be between one byte and 128 MiB")
        active = db.execute(
            "SELECT count(*) AS n FROM ops_artifacts WHERE state='uploading'"
        ).fetchone()["n"]
        count = db.execute("SELECT count(*) AS n FROM ops_artifacts").fetchone()["n"]
        if active >= 100 or count >= 100000:
            raise ValueError("Evidence upload capacity reached")
        total = db.execute(
            "SELECT COALESCE(sum(size),0) AS n FROM ops_artifacts "
            "WHERE state NOT IN ('cancelled','purged')"
        ).fetchone()["n"]
        if total + size > 2 * 1024 * MAX_CHUNK:
            raise ValueError(
                "Evidence quota reached; review retention before uploading"
            )
        now, identifier = time.time(), str(uuid4())
        db.execute(
            "INSERT INTO ops_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                case,
                subject,
                now,
                now,
                "uploading",
                value["name"],
                size,
                value["sha256"],
                value["media_type"],
                1,
                bounded_json(provenance),
                now + 86400,
            ),
        )
        self.event(
            db,
            "case",
            case,
            subject,
            "evidence.upload.started",
            {"artifact": identifier, "name": value["name"], "size": size},
        )
        return self.artifact(identifier, db)

    def _path(self, identifier: Any, index: int) -> Path:
        from northgate_rmm.operations_models import identifier as valid_id

        valid_id(identifier)
        if type(index) is not int or not 0 <= index < 128:
            raise ValueError("Invalid chunk index")
        return self.root / f"{identifier}.{index}.aes"

    def write_chunk(
        self, db: Any, identifier: Any, index: int, data: Any, digest: Any
    ) -> Any:
        artifact = self.artifact(identifier, db)
        if artifact["state"] != "uploading" or artifact["expires"] < time.time():
            raise Conflict("Upload expired or is no longer accepting chunks")
        expected = min(MAX_CHUNK, artifact["size"] - index * MAX_CHUNK)
        if (
            not 0 < expected <= MAX_CHUNK
            or len(data) != expected
            or hashlib.sha256(data).hexdigest() != digest
        ):
            raise ValueError("Chunk size or digest does not match")
        old = db.execute(
            "SELECT sha256 FROM ops_chunks WHERE artifact=? AND chunk_index=?",
            (identifier, index),
        ).fetchone()
        if old:
            if old["sha256"] != digest:
                raise Conflict("A different chunk already occupies this position")
            return self.artifact(identifier, db)
        # File writes are immutable; a transaction rollback may leave an encrypted
        # orphan, which a retry can verify and adopt without overwriting content.
        nonce = os.urandom(12)
        aad = (identifier + "/" + str(index)).encode()
        encrypted = nonce + AESGCM(self.key).encrypt(nonce, data, aad)
        path = self._path(identifier, index)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            if hashlib.sha256(self.read_chunk(identifier, index)).hexdigest() != digest:
                raise Conflict("Staged chunk differs from retry") from None
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
        db.execute(
            "INSERT INTO ops_chunks VALUES(?,?,?,?)",
            (identifier, index, len(data), digest),
        )
        db.execute(
            "UPDATE ops_artifacts SET updated=? WHERE id=?", (time.time(), identifier)
        )
        return self.artifact(identifier, db)

    def read_chunk(self, identifier: Any, index: int) -> bytes:
        from northgate_rmm.secure_files import regular_file_reference

        with regular_file_reference(
            self._path(identifier, index),
            label="evidence chunk",
            maximum_bytes=MAX_CHUNK + 64,
            private=True,
        ) as held:
            encrypted = held.read_bytes()
        return AESGCM(self.key).decrypt(
            encrypted[:12], encrypted[12:], (identifier + "/" + str(index)).encode()
        )

    def finish_artifact(self, db: Any, identifier: Any, subject: str) -> Any:
        artifact = self.artifact(identifier, db)
        if artifact["state"] == "complete":
            return artifact
        if artifact["state"] != "uploading" or artifact["expires"] < time.time():
            raise Conflict("Upload expired or cancelled")
        if artifact["received"] != artifact["size"]:
            raise Conflict("Upload still has missing chunks")
        digest, previous = hashlib.sha256(), ""
        for chunk in artifact["chunks"]:
            data = self.read_chunk(identifier, chunk["chunk_index"])
            if hashlib.sha256(data).hexdigest() != chunk["sha256"]:
                raise ValueError("Stored evidence chunk failed integrity verification")
            digest.update(data)
            if artifact["media_type"] in {
                "application/json",
                "text/plain",
                "text/csv",
                "application/x-ndjson",
            }:
                decoded = data.decode("utf-8", errors="replace")
                check_secrets(previous + decoded)
                previous = decoded[-4096:]
        if digest.hexdigest() != artifact["sha256"]:
            raise ValueError("Completed artifact digest does not match its manifest")
        db.execute(
            "UPDATE ops_artifacts SET state='complete',updated=? WHERE id=?",
            (time.time(), identifier),
        )
        self.event(
            db,
            "case",
            artifact["case_id"],
            subject,
            "evidence.retained",
            {
                "artifact": identifier,
                "sha256": artifact["sha256"],
                "size": artifact["size"],
            },
        )
        return self.artifact(identifier, db)

    def cancel_artifact(self, db: Any, identifier: Any, subject: str) -> Any:
        artifact = self.artifact(identifier, db)
        if artifact["state"] not in {"uploading", "cancelled"}:
            raise Conflict("Completed evidence cannot be cancelled")
        db.execute(
            "UPDATE ops_artifacts SET state='cancelled',retained=0,updated=? "
            "WHERE id=?",
            (time.time(), identifier),
        )
        self.event(
            db,
            "case",
            artifact["case_id"],
            subject,
            "evidence.upload.cancelled",
            {"artifact": identifier},
        )
        return self.artifact(identifier, db)

    def cleanup_partials(self) -> int:
        """Only abandoned uploads are pruned; complete case evidence stays retained."""
        with self.lock, self.connection(write=True) as db:
            rows = db.execute(
                "SELECT id FROM ops_artifacts WHERE (state='cancelled' "
                "AND EXISTS(SELECT 1 FROM ops_chunks WHERE artifact=ops_artifacts.id)) "
                "OR (state='uploading' AND expires<?) LIMIT 1000",
                (time.time(),),
            ).fetchall()
            for row in rows:
                artifact = self.artifact(row["id"], db)
                for chunk in artifact["chunks"]:
                    self._path(row["id"], chunk["chunk_index"]).unlink(missing_ok=True)
                db.execute("DELETE FROM ops_chunks WHERE artifact=?", (row["id"],))
                if artifact["state"] == "uploading":
                    self.event(
                        db,
                        "case",
                        artifact["case_id"],
                        "system:retention",
                        "evidence.upload.expired",
                        {"artifact": row["id"]},
                    )
                db.execute(
                    "UPDATE ops_artifacts SET state='cancelled',retained=0 WHERE id=?",
                    (row["id"],),
                )
            return len(rows)
