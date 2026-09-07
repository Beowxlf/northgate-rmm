"""Transactional job custody; encrypted payloads, receipts, scripts and escrow."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from northgate_rmm.management_protocol import SECRET_ACTIONS, TERMINAL, seal, unseal
from northgate_rmm.operator_api import OperatorPrincipal

Rows = list[dict[str, Any]]


class ManagementStore:
    def __init__(self, root: Path, key: bytes) -> None:
        self.root, self.key = root, key
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if root.is_symlink():
            raise ValueError("Unsafe management state")
        root.chmod(0o700)
        self.path = root / "management.sqlite3"
        if self.path.is_symlink():
            raise ValueError("Unsafe management database")
        with self.connect() as db:
            db.executescript(
                "\n            CREATE TABLE IF NOT EXISTS jobs (\n         "
                "     id TEXT PRIMARY KEY, endpoint TEXT NOT NULL, "
                "identity TEXT NOT NULL,\n              subject TEXT NOT "
                "NULL, session TEXT NOT NULL, action TEXT NOT NULL,\n     "
                "         state TEXT NOT NULL, created REAL NOT NULL, "
                "expires REAL NOT NULL,\n              updated REAL NOT "
                "NULL, cancel INTEGER NOT NULL DEFAULT 0,\n              "
                "exercise TEXT NOT NULL, payload BLOB NOT NULL, receipt "
                "BLOB);\n            CREATE INDEX IF NOT EXISTS "
                "jobs_endpoint ON jobs(endpoint,created);\n            "
                "CREATE TABLE IF NOT EXISTS workers (endpoint TEXT "
                "PRIMARY KEY, identity TEXT NOT NULL,\n              seen "
                "REAL NOT NULL, capabilities BLOB NOT NULL);\n            "
                "CREATE TABLE IF NOT EXISTS scripts (id TEXT NOT NULL, "
                "version TEXT NOT NULL,\n              created REAL NOT "
                "NULL, payload BLOB NOT NULL, PRIMARY KEY(id,version));\n "
                "           CREATE TABLE IF NOT EXISTS escrow (endpoint "
                "TEXT NOT NULL, kind TEXT NOT NULL,\n              job "
                "TEXT NOT NULL UNIQUE, created REAL NOT NULL, payload "
                "BLOB NOT NULL);\n            CREATE TABLE IF NOT EXISTS "
                "terminal_io (job TEXT NOT NULL, direction TEXT NOT "
                "NULL,\n              sequence INTEGER NOT NULL, payload "
                "BLOB NOT NULL, PRIMARY KEY(job,direction,sequence));\n   "
                "         CREATE TABLE IF NOT EXISTS evidence (id TEXT "
                "PRIMARY KEY, exercise TEXT NOT NULL,\n              "
                "endpoint TEXT NOT NULL, action TEXT NOT NULL, created "
                "REAL NOT NULL, payload BLOB NOT NULL);\n            "
            )
        self.path.chmod(0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def add(
        self,
        endpoint: UUID | str,
        identity: UUID | str,
        principal: OperatorPrincipal,
        action: str,
        params: dict[str, Any],
        authorization: str,
        exercise: str = "",
        seconds: int = 300,
    ) -> str:
        now = time.time()
        identifier = str(uuid4())
        expires = min(now + seconds, principal.expires_at.timestamp())
        if expires <= now:
            raise ValueError("Expired operator session")
        self.maintain()
        payload = {
            "params": params,
            "authorization": authorization,
            "session_expiry": expires,
            "boot_id": self.worker(endpoint).get("capabilities", {}).get("boot_id"),
        }
        with self.connect() as db:
            if (
                db.execute(
                    "SELECT count(*) FROM jobs WHERE state NOT IN "
                    "('completed','failed','cancelled','expired','result_unkn"
                    "own')"
                ).fetchone()[0]
                >= 64
            ):
                raise ValueError("Management queue full")
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?,NULL)",
                (
                    identifier,
                    str(endpoint),
                    str(identity),
                    principal.subject,
                    principal.session_id,
                    action,
                    "queued",
                    now,
                    expires,
                    now,
                    exercise,
                    seal(self.key, payload, identifier),
                ),
            )
        return identifier

    def job(self, identifier: str, *, private: bool = False) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE id=?", (str(identifier),)
            ).fetchone()
        if row is None:
            raise KeyError("Unknown job")
        result = {k: row[k] for k in dict(row) if k not in {"payload", "receipt"}}
        if private:
            result["payload"] = unseal(self.key, row["payload"], row["id"])
        if row["receipt"] is not None and (
            private or row["action"] not in SECRET_ACTIONS
        ):
            result[("receipt")] = unseal(
                self.key, row[("receipt")], row[("id")] + ("/receipt")
            )
        result["secret_result"] = row["action"] in SECRET_ACTIONS
        return result

    def list(self, endpoint: UUID | str) -> Rows:
        self.maintain()
        with self.connect() as db:
            ids = [
                r[0]
                for r in db.execute(
                    (
                        "SELECT id FROM jobs WHERE endpoint=? ORDER BY created "
                        "DESC LIMIT 100"
                    ),
                    (str(endpoint),),
                )
            ]
        jobs = [self.job(i) for i in ids]
        for job in jobs:
            if job["action"] == "reboot":
                detail = self.job(job["id"], private=True)
                before = detail["payload"].get("boot_id")
                worker = self.worker(endpoint)
                after = worker.get("capabilities", {}).get("boot_id")
                job["restart_verification"] = (
                    "Returned after restart"
                    if before
                    and after
                    and before != after
                    and worker.get("ready")
                    and worker.get("identity") == job["identity"]
                    and worker.get("last_seen", 0) > job["created"]
                    else "Return not verified within 10 minutes"
                    if time.time() - job["created"] > 600
                    else "Waiting for a new boot and authenticated worker return"
                )
            receipt = job.get("receipt")
            if receipt and job["action"] == "files.read":
                try:
                    metadata = json.loads(receipt["output"])
                    metadata.pop("data", None)
                    receipt["output"] = json.dumps(metadata)
                except (ValueError, KeyError, TypeError):
                    receipt["output"] = "Invalid file result"
            if receipt and len(receipt.get("output", "")) > 16384:
                receipt["output"] = receipt["output"][:16384] + "\n[Preview truncated]"
        return jobs

    def pending(self, endpoint: UUID | str, identity: UUID | str) -> Rows:
        now = time.time()
        with self.connect() as db:
            db.execute(
                (
                    "UPDATE jobs SET state=CASE WHEN state='queued' THEN "
                    "'expired' ELSE 'result_unknown' END,updated=? WHERE "
                    "expires<? AND state IN ('queued','dispatched','running')"
                ),
                (now, now),
            )
            ids = [
                r[0]
                for r in db.execute(
                    (
                        "SELECT id FROM jobs WHERE endpoint=? AND identity=? AND "
                        "state IN ('queued','dispatched','running') ORDER BY "
                        "created LIMIT 16"
                    ),
                    (str(endpoint), str(identity)),
                )
            ]
        return [self.job(i, private=True) for i in ids]

    def dispatch(self, identifier: str) -> bool:
        with self.connect() as db:
            return (
                db.execute(
                    (
                        "UPDATE jobs SET state='dispatched',updated=? WHERE id=? "
                        "AND state='queued' AND cancel=0 AND expires>?"
                    ),
                    (time.time(), identifier, time.time()),
                ).rowcount
                == 1
            )

    def cancel(self, identifier: str) -> None:
        with self.connect() as db:
            db.execute(
                (
                    "UPDATE jobs SET cancel=1,state=CASE WHEN state='queued' "
                    "THEN 'cancelled' ELSE state END,updated=? WHERE id=?"
                ),
                (time.time(), identifier),
            )

    def result(
        self, endpoint: UUID | str, identity: UUID | str, identifier: str, receipt: Any
    ) -> None:
        if (
            not isinstance(receipt, dict)
            or not isinstance(receipt.get("state"), str)
            or receipt.get("state") not in TERMINAL
            or type(receipt.get("exit_code")) is not int
            or not isinstance(receipt.get("output"), str)
            or type(receipt.get("truncated")) is not bool
            or not isinstance(receipt.get("execution_identity"), str)
        ):
            raise ValueError("Invalid receipt")
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE id=? AND endpoint=? AND identity=?",
                (identifier, str(endpoint), str(identity)),
            ).fetchone()
            if row is None or row["state"] == "queued":
                raise ValueError("Receipt has no dispatched job")
            if row["receipt"] is not None:
                return
            db.execute(
                "UPDATE jobs SET state=?,updated=?,receipt=? WHERE id=?",
                (
                    receipt["state"],
                    time.time(),
                    seal(self.key, receipt, identifier + "/receipt"),
                    identifier,
                ),
            )
            if row["action"] in SECRET_ACTIONS and receipt["state"] == "completed":
                db.execute(
                    "INSERT OR IGNORE INTO escrow VALUES (?,?,?,?,?)",
                    (
                        str(endpoint),
                        row["action"],
                        identifier,
                        time.time(),
                        seal(self.key, receipt, identifier + "/escrow"),
                    ),
                )
        self.event(
            row["exercise"],
            str(endpoint),
            "job." + receipt["state"],
            {"job": identifier, "operation": row["action"]},
        )

    def seen(
        self, endpoint: UUID | str, identity: UUID | str, capabilities: Any
    ) -> None:
        if not isinstance(capabilities, dict) or len(json.dumps(capabilities)) > 65536:
            raise ValueError("Invalid capabilities")
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO workers VALUES (?,?,?,?)",
                (
                    str(endpoint),
                    str(identity),
                    time.time(),
                    seal(self.key, capabilities, str(endpoint) + "/worker"),
                ),
            )

    def worker(self, endpoint: UUID | str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM workers WHERE endpoint=?", (str(endpoint),)
            ).fetchone()
        if row is None:
            return {"ready": False, "reason": "Privileged worker not enrolled"}
        result = unseal(self.key, row["capabilities"], str(endpoint) + "/worker")
        return {
            "ready": time.time() - row["seen"] < 20,
            "last_seen": row["seen"],
            "identity": row["identity"],
            "capabilities": result,
        }

    def io(self, job: Any, direction: str, sequence: int, payload: Any) -> None:
        if (
            direction not in {"in", "out"}
            or type(sequence) is not int
            or not 1 <= sequence <= 100000
        ):
            raise ValueError("Invalid terminal sequence")
        raw = json.dumps(payload)
        if len(raw) > 65536:
            raise ValueError("Terminal frame too large")
        with self.connect() as db:
            existing = db.execute(
                (
                    "SELECT payload FROM terminal_io WHERE job=? AND "
                    "direction=? AND sequence=?"
                ),
                (job, direction, sequence),
            ).fetchone()
            context = f"{job}/{direction}/{sequence}"
            if existing:
                if unseal(self.key, existing[0], context) != payload:
                    raise ValueError("Conflicting terminal retry")
                return
            count = db.execute(
                "SELECT count(*) FROM terminal_io WHERE job=?", (job,)
            ).fetchone()[0]
            if count >= 1024:
                raise ValueError("Terminal buffer full")
            db.execute(
                "INSERT INTO terminal_io VALUES (?,?,?,?)",
                (job, direction, sequence, seal(self.key, payload, context)),
            )

    def frames(self, job: Any, direction: str, after: int) -> Rows:
        with self.connect() as db:
            rows = db.execute(
                (
                    "SELECT * FROM terminal_io WHERE job=? AND direction=? "
                    "AND sequence>? ORDER BY sequence LIMIT 32"
                ),
                (job, direction, after),
            ).fetchall()
        return [
            {
                "sequence": r["sequence"],
                "value": unseal(
                    self.key, r["payload"], f"{job}/{direction}/{r['sequence']}"
                ),
            }
            for r in rows
        ]

    def prune_frames(self, job: Any, direction: str, through: int) -> None:
        with self.connect() as db:
            db.execute(
                "DELETE FROM terminal_io WHERE job=? AND direction=? AND sequence<=?",
                (job, direction, through),
            )

    def event(
        self, exercise: str, endpoint: UUID | str, action: str, payload: Any
    ) -> None:
        identifier = str(uuid4())
        with self.connect() as db:
            db.execute(
                "INSERT INTO evidence VALUES (?,?,?,?,?,?)",
                (
                    identifier,
                    exercise,
                    endpoint,
                    action,
                    time.time(),
                    seal(self.key, payload, identifier),
                ),
            )

    def backup(self, destination: Path) -> None:
        """Consistent encrypted DB backup; the master key is backed up separately."""
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with (
                self.connect() as source,
                closing(sqlite3.connect(destination)) as target,
            ):
                source.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Backup integrity failure")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    def maintain(self) -> None:
        now = time.time()
        with self.connect() as db:
            db.execute(
                (
                    "UPDATE jobs SET state=CASE WHEN state='queued' THEN "
                    "'expired' ELSE 'result_unknown' END,updated=? WHERE "
                    "expires<? AND state IN ('queued','dispatched','running')"
                ),
                (now, now),
            )
            # Terminal buffers are temporary transport, not permanent transcripts.
            db.execute(
                (
                    "DELETE FROM terminal_io WHERE job IN (SELECT id FROM "
                    "jobs WHERE state IN ('completed','failed','cancelled','e"
                    "xpired','result_unknown') AND updated<?)"
                ),
                (now - 60,),
            )
            db.execute(
                (
                    "DELETE FROM jobs WHERE created<? AND action NOT IN "
                    "('bitlocker.escrow','recovery.rotate') AND state IN "
                    "('completed','failed','cancelled','expired','result_unkn"
                    "own')"
                ),
                (now - 30 * 86400,),
            )
            db.execute("DELETE FROM evidence WHERE created<?", (now - 90 * 86400,))
            if (
                db.execute("PRAGMA page_count").fetchone()[0]
                - db.execute("PRAGMA freelist_count").fetchone()[0]
            ) * db.execute("PRAGMA page_size").fetchone()[0] > 512 * 1024 * 1024:
                raise ValueError(
                    "Management storage limit reached; back up and archive history"
                )
