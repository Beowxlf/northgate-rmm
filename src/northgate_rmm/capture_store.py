"""Private capture history. Tokens and endpoint keys are never persisted here."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class CaptureStore:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.is_symlink():
            raise ValueError("Capture state must not be a symlink")
        root.chmod(0o700)
        self.path = root / "capture.sqlite3"
        if self.path.is_symlink():
            raise ValueError("Capture database must not be a symlink")
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, "
                "endpoint TEXT NOT NULL, identity TEXT NOT NULL, "
                "subject TEXT NOT NULL, session TEXT NOT NULL, "
                "created REAL NOT NULL, updated REAL NOT NULL, payload TEXT NOT NULL)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS capture_endpoint "
                "ON jobs(endpoint, created DESC)"
            )
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def prune(self):
        with self.connect() as db:
            db.execute("DELETE FROM jobs WHERE created < ?", (time.time() - 7 * 86400,))

    def add(self, endpoint, identity, principal, job):
        self.prune()
        with self.connect() as db:
            if db.execute("SELECT count(*) FROM jobs").fetchone()[0] >= 2000:
                raise ValueError("Capture history is full; delete older jobs")
            db.execute(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?)",
                (
                    job["id"],
                    str(endpoint),
                    str(identity),
                    principal.subject,
                    principal.session_id,
                    time.time(),
                    time.time(),
                    json.dumps(job),
                ),
            )

    def update(self, job):
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET payload=?, updated=? WHERE id=?",
                (json.dumps(job), time.time(), job["id"]),
            )

    def get(self, endpoint, identity, subject, job_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE id=? AND endpoint=? "
                "AND identity=? AND subject=?",
                (job_id, str(endpoint), str(identity), subject),
            ).fetchone()
            return dict(row) if row else None

    def history(self, endpoint, identity, subject):
        self.prune()
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM jobs WHERE endpoint=? AND identity=? "
                    "AND subject=? ORDER BY created DESC LIMIT 50",
                    (str(endpoint), str(identity), subject),
                )
            ]

    def delete(self, job_id):
        with self.connect() as db:
            db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
