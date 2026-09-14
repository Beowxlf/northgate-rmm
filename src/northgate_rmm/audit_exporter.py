"""Bounded outbox delivery with independently pinned signed checkpoints."""

from __future__ import annotations

import argparse
import base64
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from northgate_rmm.agent_service import load_database_dsn
from northgate_rmm.errors import ValidationError
from northgate_rmm.persistence import PostgresControlPlane
from northgate_rmm.rpc_client import call
from northgate_rmm.workload_service import canonical, load_configuration


def export(configuration: dict[str, Any]) -> int:
    key = serialization.load_pem_public_key(
        Path(configuration["checkpoint_public_key"]).read_bytes()
    )
    if not isinstance(key, Ed25519PublicKey):
        raise ValidationError("checkpoint public key invalid")
    store = PostgresControlPlane(
        load_database_dsn(Path(configuration["database_dsn_credential"]))
    )

    def verify(response: dict[str, Any]) -> tuple[int, str]:
        if (
            set(response) != {"deployment_id", "sequence", "hash", "signature"}
            or response["deployment_id"] != configuration["deployment_id"]
            or type(response["sequence"]) is not int
            or response["sequence"] < 0
            or type(response["hash"]) is not str
            or len(response["hash"]) != 64
        ):
            raise ValidationError("checkpoint fields invalid")
        signed = {
            name: response[name] for name in ("deployment_id", "sequence", "hash")
        }
        key.verify(
            base64.b64decode(response["signature"], validate=True), canonical(signed)
        )
        return response["sequence"], response["hash"]

    try:
        store.verify_schema_state()
        sequence, digest = verify(
            call(
                configuration["sink"],
                "/v1/audit/checkpoint",
                {"deployment_id": configuration["deployment_id"]},
            )
        )
        with store._connect() as db, db.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM audit_delivery_state WHERE singleton FOR UPDATE"
            )
            anchor = cursor.fetchone()
            if (
                anchor is None
                or sequence < anchor["acknowledged_sequence"]
                or sequence > anchor["last_sequence"]
            ):
                raise ValidationError(
                    "independent audit checkpoint regressed or exceeds source"
                )
            if sequence == anchor["acknowledged_sequence"]:
                expected = anchor["acknowledged_hash"]
            else:
                cursor.execute(
                    "SELECT event_hash FROM audit_outbox WHERE chain_sequence=%s",
                    (sequence,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ValidationError("source checkpoint missing")
                expected = row["event_hash"]
            if digest != expected:
                raise ValidationError("audit checkpoint diverged")
            cursor.execute(
                "SELECT * FROM audit_outbox WHERE chain_sequence>%s ORDER BY "
                "chain_sequence LIMIT 100",
                (sequence,),
            )
            pending = cursor.fetchall()
        for row in pending:
            received_sequence, received_hash = verify(
                call(
                    configuration["sink"],
                    "/v1/audit/events",
                    {
                        "deployment_id": configuration["deployment_id"],
                        "sequence": row["chain_sequence"],
                        "previous_hash": row["previous_hash"],
                        "hash": row["event_hash"],
                        "payload": row["payload"],
                    },
                )
            )
            if (
                received_sequence != row["chain_sequence"]
                or received_hash != row["event_hash"]
            ):
                raise ValidationError("audit acknowledgement mismatch")
            sequence, digest = received_sequence, received_hash
        with store._connect() as db, db.cursor() as cursor:
            cursor.execute(
                "UPDATE audit_delivery_state SET "
                "acknowledged_sequence=%s,acknowledged_hash=%s,"
                "acknowledged_at=clock_timestamp() "
                "WHERE singleton AND acknowledged_sequence<=%s",
                (sequence, digest, sequence),
            )
        return len(pending)
    finally:
        store.begin_shutdown()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        count = export(load_configuration(arguments.config))
    except Exception:
        print("audit delivery unavailable or reconciliation required", file=sys.stderr)
        return 1
    print(f"audit records acknowledged: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
