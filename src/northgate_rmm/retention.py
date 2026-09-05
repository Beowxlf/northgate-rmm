"""Bounded scheduled retention preserving replay counters and current inventory."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from northgate_rmm.agent_service import load_database_dsn
from northgate_rmm.persistence import PostgresControlPlane


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn-file", required=True, type=Path)
    args = parser.parse_args(argv)
    store = None
    try:
        store = PostgresControlPlane(load_database_dsn(args.dsn_file))
        store.verify_schema_state()
        with store._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_xact_lock(742119)")
            locked = cursor.fetchone()
            if locked is None or not next(iter(locked.values())):
                return 0
            cursor.execute("SELECT active FROM retention_hold WHERE singleton")
            hold = cursor.fetchone()
            if hold is None or hold["active"]:
                return 0
            cursor.execute("""
                DELETE FROM observations WHERE observation_id IN (
                    SELECT o.observation_id FROM observations o
                    WHERE received_at < clock_timestamp() -
                      CASE observation_type WHEN 'heartbeat' THEN interval '30 days'
                           ELSE interval '90 days' END
                    AND EXISTS (SELECT 1 FROM observations newer
                         WHERE newer.endpoint_id=o.endpoint_id
                         AND newer.observation_type=o.observation_type
                         AND newer.received_at>o.received_at)
                    ORDER BY received_at LIMIT 1000
                )
            """)
            removed = cursor.rowcount
            cursor.execute("""
                DELETE FROM audit_outbox WHERE chain_sequence IN (
                    SELECT chain_sequence FROM audit_outbox
                    WHERE chain_sequence < (SELECT acknowledged_sequence
                        FROM audit_delivery_state WHERE singleton)
                    AND created_at < clock_timestamp() - interval '365 days'
                    ORDER BY chain_sequence LIMIT 1000
                )
            """)
            store._insert_audit(
                cursor,
                server_time=datetime.now(UTC),
                actor_type="service",
                actor_id="retention",
                subject="observations",
                action="retention.apply",
                decision="accepted",
                reason="bounded retention batch",
                correlation_id=uuid4(),
                metadata=(("removed", str(removed)),),
            )
    except Exception:
        print("retention unavailable", file=sys.stderr)
        return 1
    finally:
        if store is not None:
            store.begin_shutdown()
    return 0
