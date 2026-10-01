"""Independent append-only audit intake and signed checkpoint service."""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from northgate_rmm.errors import ValidationError
from northgate_rmm.issuer_service import open_ledger
from northgate_rmm.workload_service import (
    Operation,
    canonical,
    read_private,
    service_main,
    strict_object,
)


class AuditSink:
    def __init__(self, configuration: dict[str, Any]) -> None:
        self.path = Path(configuration["ledger"])
        self.deployment = str(UUID(configuration["deployment_id"]))
        self.archive = Path(configuration["checkpoint_directory"])
        if (
            not self.archive.is_absolute()
            or not self.archive.is_dir()
            or self.archive.is_symlink()
            or self.archive.resolve() == self.path.parent.resolve()
        ):
            raise ValidationError("independent checkpoint directory required")
        loaded_key = serialization.load_pem_private_key(
            read_private(configuration["checkpoint_private_key"]), password=None
        )
        if not isinstance(loaded_key, Ed25519PrivateKey):
            raise ValidationError("checkpoint signing key must be Ed25519")
        self.key = loaded_key
        with open_ledger(self.path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, "
                "digest TEXT NOT NULL, previous TEXT NOT NULL, payload TEXT NOT "
                "NULL)"
            )

    def checkpoint(self, sequence: int, digest: str) -> dict[str, Any]:
        record = {
            "deployment_id": self.deployment,
            "sequence": sequence,
            "hash": digest,
        }
        return {
            **record,
            "signature": base64.b64encode(self.key.sign(canonical(record))).decode(
                "ascii"
            ),
        }

    def handle(
        self, path: str, body: bytes, _authorization: str | None
    ) -> tuple[int, dict[str, Any]]:
        request = strict_object(body)
        if request.get("deployment_id") != self.deployment:
            raise ValidationError("audit deployment mismatch")
        with open_ledger(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT sequence,digest FROM audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence, digest = (
                (row["sequence"], row["digest"]) if row else (0, "0" * 64)
            )
            if path == "/v1/audit/checkpoint":
                if set(request) != {"deployment_id"}:
                    raise ValidationError("checkpoint fields invalid")
                # A ledger rollback cannot silently issue an older checkpoint.
                if (
                    self.archive / f"{self.deployment}-{sequence + 1:020d}.json"
                ).exists():
                    raise ValidationError(
                        "audit ledger requires archive reconciliation"
                    )
                return 200, self.checkpoint(sequence, digest)
            if (
                set(request)
                != {"deployment_id", "sequence", "previous_hash", "hash", "payload"}
                or type(request["sequence"]) is not int
                or request["sequence"] < 1
                or type(request["payload"]) is not str
                or len(request["payload"].encode("utf-8")) > 32768
            ):
                raise ValidationError("audit schema invalid")
            incoming = request["sequence"]
            calculated = hashlib.sha256(
                (request["previous_hash"] + request["payload"]).encode("utf-8")
            ).hexdigest()
            if calculated != request["hash"]:
                raise ValidationError("audit hash invalid")
            if incoming <= sequence:
                old = db.execute(
                    "SELECT digest FROM audit WHERE sequence=?", (incoming,)
                ).fetchone()
                if old is None or old["digest"] != calculated:
                    raise ValidationError("audit replay diverged")
                return 200, self.checkpoint(incoming, calculated)
            if incoming != sequence + 1 or request["previous_hash"] != digest:
                raise ValidationError("audit chain discontinuity")
            if (
                min(
                    shutil.disk_usage(self.path.parent).free,
                    shutil.disk_usage(self.archive).free,
                )
                < 128 * 1024 * 1024
            ):
                raise ValidationError("audit capacity exhausted")
            checkpoint = self.checkpoint(incoming, calculated)
            archived = canonical(
                {
                    "checkpoint": checkpoint,
                    "payload": request["payload"],
                    "previous_hash": digest,
                }
            )
            destination = self.archive / f"{self.deployment}-{incoming:020d}.json"
            try:
                descriptor = os.open(
                    destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400
                )
            except FileExistsError:
                if (
                    destination.is_symlink()
                    or destination.stat().st_size > 65536
                    or destination.read_bytes() != archived
                ):
                    raise ValidationError("archive checkpoint diverged") from None
            else:
                with os.fdopen(descriptor, "wb") as file:
                    file.write(archived)
                    file.flush()
                    os.fsync(file.fileno())
                directory = os.open(self.archive, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            db.execute(
                "INSERT INTO audit(sequence,digest,previous,payload) VALUES(?,?,?,?)",
                (incoming, calculated, digest, request["payload"]),
            )
        return 200, checkpoint


def factory(configuration: dict[str, Any]) -> tuple[Operation, frozenset[str]]:
    return AuditSink(configuration).handle, frozenset(
        {"/v1/audit/checkpoint", "/v1/audit/events"}
    )


def main(argv: Sequence[str] | None = None) -> int:
    return service_main(factory, argv)


if __name__ == "__main__":
    raise SystemExit(main())
