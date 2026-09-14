"""Metadata-only remote session receipts; never stores credentials or screen data."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path


class RemoteSessionStore:
    def __init__(self, path: Path | str = ":memory:"):
        self.lock = threading.RLock()
        if str(path) != ":memory:":
            path = Path(path)
            if path.is_symlink():
                raise ValueError("session database must not be a symbolic link")
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, "
            "endpoint TEXT NOT NULL, identity TEXT NOT NULL, value TEXT NOT NULL)"
        )
        # A restarted gateway cannot keep its in-memory connection leases alive.
        with self.lock, self.db:
            for sid, raw in self.db.execute("SELECT id,value FROM sessions").fetchall():
                value = json.loads(raw)
                if not value.get("ended_at"):
                    value.update(
                        ended_at=datetime.now(UTC).isoformat(),
                        status="interrupted",
                        outcome="gateway_restarted",
                    )
                    self.db.execute(
                        "UPDATE sessions SET value=? WHERE id=?",
                        (json.dumps(value), sid),
                    )
        if str(path) != ":memory:":
            path.chmod(0o600)

    def create(self, lease, method, case_id):
        value = {
            "id": str(lease.session_id),
            "endpoint_id": str(lease.endpoint_id),
            "identity_id": str(lease.identity_id),
            "subject": lease.subject,
            "method": method,
            "case_id": case_id,
            "created_at": lease.created_at.isoformat(),
            "expires_at": lease.expires_at.isoformat(),
            "started_at": None,
            "ended_at": None,
            "status": "authorized",
            "outcome": "pending_connection",
        }
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO sessions VALUES(?,?,?,?)",
                (
                    value["id"],
                    value["endpoint_id"],
                    value["identity_id"],
                    json.dumps(value),
                ),
            )

    def update(self, session_id, *, status, outcome):
        if status not in {"connected", "closed", "expired", "failed"}:
            raise ValueError("invalid session receipt state")
        if outcome not in {
            "transport_connected",
            "operator_disconnected",
            "transport_closed",
            "authorization_expired",
            "connection_failed",
            "gateway_stopped",
        }:
            raise ValueError("invalid session receipt outcome")
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT value FROM sessions WHERE id=?", (str(session_id),)
            ).fetchone()
            if row is None:
                return
            value = json.loads(row[0])
            if value.get("ended_at"):
                return
            value.update(status=status, outcome=outcome)
            value["started_at" if status == "connected" else "ended_at"] = datetime.now(
                UTC
            ).isoformat()
            self.db.execute(
                "UPDATE sessions SET value=? WHERE id=?",
                (json.dumps(value), str(session_id)),
            )

    def list(self, endpoint, identity, limit=100):
        with self.lock:
            rows = self.db.execute(
                "SELECT value FROM sessions WHERE endpoint=? AND identity=? "
                "ORDER BY rowid DESC LIMIT ?",
                (str(endpoint), str(identity), min(max(int(limit), 1), 100)),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]
