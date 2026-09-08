"""Versioned encrypted fleet records inside the existing recovery-covered database."""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from northgate_rmm.fleet_models import KINDS
from northgate_rmm.management_protocol import canonical, seal, unseal
from northgate_rmm.management_store import ManagementStore


class Conflict(ValueError):
    """A stale editor or scheduler must refresh instead of overwriting work."""


class FleetStore:
    def __init__(self, management: ManagementStore) -> None:
        self.management = management
        with management.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS fleet_records (
                    kind TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
                    created REAL NOT NULL, updated REAL NOT NULL, subject TEXT NOT NULL,
                    payload BLOB NOT NULL, PRIMARY KEY(kind,id));
                CREATE INDEX IF NOT EXISTS fleet_recent ON fleet_records(kind,updated);
            """)

    def get(self, kind: str, key: str) -> dict[str, Any]:
        with self.management.connect() as db:
            row = db.execute(
                "SELECT * FROM fleet_records WHERE kind=? AND id=?", (kind, key)
            ).fetchone()
        if row is None:
            raise KeyError("Record not found")
        return self.decode(row)

    def decode(self, row: sqlite3.Row) -> dict[str, Any]:
        kind, key = row["kind"], row["id"]
        return {
            "id": key,
            "kind": kind,
            "revision": row["revision"],
            "created": row["created"],
            "updated": row["updated"],
            "subject": row["subject"],
            "value": unseal(
                self.management.key, row["payload"], "fleet/" + kind + "/" + key
            ),
        }

    def list(self, kind: str, limit: int = 5000) -> list[dict[str, Any]]:
        if kind not in KINDS or not 1 <= limit <= 10000:
            raise ValueError("Invalid record query")
        with self.management.connect() as db:
            rows = db.execute(
                "SELECT * FROM fleet_records WHERE kind=? "
                "ORDER BY updated DESC LIMIT ?",
                (kind, limit),
            ).fetchall()
        return [self.decode(row) for row in rows]

    def put(
        self,
        kind: str,
        key: str,
        value: dict[str, Any],
        subject: str,
        revision: int = 0,
    ) -> dict[str, Any]:
        if (
            kind not in KINDS
            or type(revision) is not int
            or revision < 0
            or len(canonical(value)) > 2 * 1024 * 1024
        ):
            raise ValueError("Invalid record")
        now = time.time()
        payload = seal(self.management.key, value, "fleet/" + kind + "/" + key)
        with self.management.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT revision FROM fleet_records WHERE kind=? AND id=?", (kind, key)
            ).fetchone()
            if (row is None and revision != 0) or (
                row is not None and row[0] != revision
            ):
                raise Conflict("This record changed. Refresh before saving.")
            if row is None:
                if (
                    db.execute(
                        "SELECT count(*) FROM fleet_records WHERE kind=?", (kind,)
                    ).fetchone()[0]
                    >= 10000
                ):
                    raise ValueError(
                        "Record capacity reached; export and archive old work"
                    )
                db.execute(
                    "INSERT INTO fleet_records VALUES (?,?,?,?,?,?,?)",
                    (kind, key, 1, now, now, subject, payload),
                )
            else:
                db.execute(
                    "UPDATE fleet_records SET revision=revision+1,"
                    "updated=?,subject=?,payload=? WHERE kind=? AND id=?",
                    (now, subject, payload, kind, key),
                )
        return self.get(kind, key)

    def delete(self, kind: str, key: str, revision: int) -> None:
        with self.management.connect() as db:
            cursor = db.execute(
                "DELETE FROM fleet_records WHERE kind=? AND id=? AND revision=?",
                (kind, key, revision),
            )
            if cursor.rowcount != 1:
                raise Conflict("This record changed. Refresh before deleting.")

    def prune_previews(self) -> None:
        with self.management.connect() as db:
            db.execute(
                "DELETE FROM fleet_records WHERE kind='preview' AND created<?",
                (time.time() - 1800,),
            )
