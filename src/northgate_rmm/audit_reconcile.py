"""Rebuild a stopped sink ledger from independently signed archive records."""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from northgate_rmm.errors import ValidationError
from northgate_rmm.issuer_service import open_ledger
from northgate_rmm.workload_service import canonical, load_configuration


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--new-ledger", type=Path, required=True)
    parser.add_argument("--minimum-sequence", type=int, required=True)
    parser.add_argument("--minimum-hash", required=True)
    args = parser.parse_args(argv)
    try:
        config = load_configuration(args.config)
        if args.new_ledger.exists() or args.minimum_sequence < 1:
            raise ValidationError("fresh ledger and external checkpoint required")
        key = serialization.load_pem_public_key(
            Path(config["checkpoint_public_key"]).read_bytes()
        )
        if not isinstance(key, Ed25519PublicKey):
            raise ValidationError("independent checkpoint key invalid")
        previous, sequence = "0" * 64, 0
        with open_ledger(args.new_ledger) as db:
            db.execute(
                "CREATE TABLE audit (sequence INTEGER PRIMARY KEY, digest TEXT NOT "
                "NULL, previous TEXT NOT NULL, payload TEXT NOT NULL)"
            )
            for path in sorted(
                Path(config["checkpoint_directory"]).glob(
                    config["deployment_id"] + "-*.json"
                )
            ):
                record = load_configuration(path)
                checkpoint = record["checkpoint"]
                signed = {
                    name: checkpoint[name]
                    for name in ("deployment_id", "sequence", "hash")
                }
                key.verify(
                    base64.b64decode(checkpoint["signature"], validate=True),
                    canonical(signed),
                )
                digest = hashlib.sha256(
                    (previous + record["payload"]).encode("utf-8")
                ).hexdigest()
                if (
                    signed["deployment_id"] != config["deployment_id"]
                    or signed["sequence"] != sequence + 1
                    or record["previous_hash"] != previous
                    or signed["hash"] != digest
                ):
                    raise ValidationError("archive chain diverged")
                sequence += 1
                if sequence == args.minimum_sequence and digest != args.minimum_hash:
                    raise ValidationError("external checkpoint mismatch")
                db.execute(
                    "INSERT INTO audit VALUES(?,?,?,?)",
                    (sequence, digest, previous, record["payload"]),
                )
                previous = digest
            if sequence < args.minimum_sequence:
                raise ValidationError("archive has regressed")
    except Exception:
        print(
            "audit reconciliation incomplete; do not activate new ledger",
            file=sys.stderr,
        )
        return 1
    print(f"reconciled audit sequence: {sequence}; service remains stopped")
    return 0
