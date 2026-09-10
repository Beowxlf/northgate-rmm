"""Local fleet administration and a resumable, credential-free SIEM event export."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any
from uuid import uuid4

from northgate_rmm.fleet_access import load_grants
from northgate_rmm.management_protocol import unseal
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.secure_files import regular_file_reference


def read_json(path: Path, maximum: int = 524288) -> dict[str, Any]:
    with regular_file_reference(
        path, label="fleet configuration", maximum_bytes=maximum, private=True
    ) as ref:
        result = json.loads(ref.read_bytes())
    if not isinstance(result, dict):
        raise ValueError("Configuration must be an object")
    return result


def validate_access(operator: Path, bridge: Path) -> dict[str, Any]:
    """Verify both independent identity gates agree before restarting services."""
    config, identity = read_json(operator), read_json(bridge)
    grants = load_grants(config.get("policy_operator_grants", []))
    expected = {config["policy_subject"], *(grant.subject for grant in grants)}
    actual = {identity["subject"], *identity.get("allowed_subjects", [])}
    if expected != actual or config["policy_subject"] != identity["subject"]:
        raise ValueError("Operator and identity-provider subject allowlists differ")
    if (
        config["policy_issuer"] != identity["issuer"]
        or config["policy_client_id"] != identity["client_id"]
    ):
        raise ValueError("Operator and identity-provider scope differs")
    return {
        "valid": True,
        "additional_operators": len(grants),
        "permissions": sorted({p for g in grants for p in g.permissions}),
    }


def export_events(store: ManagementStore, output: Path, checkpoint: Path) -> int:
    """Append stable event IDs for Splunk/Wazuh file collectors; safe to deduplicate.

    Appending precedes checkpoint persistence. A crash may repeat event IDs but
    cannot silently advance the cursor past an event that was not written.
    """
    for path in (output, checkpoint):
        if (
            not path.is_absolute()
            or path.is_symlink()
            or any(p.is_symlink() for p in path.parents)
        ):
            raise ValueError("Use absolute, non-symlink export paths")
        if path.resolve().is_relative_to(store.root.resolve()):
            raise ValueError("Export paths must be outside management state")
        if path.exists() and path.samefile(store.path):
            raise ValueError("Export destination aliases management state")
    if output.resolve() == checkpoint.resolve() or (
        output.exists() and checkpoint.exists() and output.samefile(checkpoint)
    ):
        raise ValueError("Output and checkpoint must be different files")
    after = 0
    if checkpoint.exists():
        cursor = read_json(checkpoint)
        after = cursor["sequence"]
        if (
            type(after) is not int
            or after < 0
            or (
                cursor.get("output") != str(output.resolve())
                or not output.is_file()
                or type(cursor.get("offset")) is not int
                or output.stat().st_size < cursor["offset"]
            )
        ):
            raise ValueError(
                "Export output/cursor changed; use a fresh output and cursor"
            )
    with store.connect() as db:
        rows = db.execute(
            "SELECT s.sequence AS position,e.* FROM fleet_event_sequence s "
            "JOIN evidence e ON e.id=s.event WHERE s.sequence>? "
            "ORDER BY s.sequence LIMIT 1000",
            (after,),
        ).fetchall()
    if not rows:
        return 0
    descriptor = os.open(
        output,
        os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or (
            os.name == "posix" and metadata.st_mode & 0o077
        ):
            raise ValueError("Export destination must be a private regular file")
        for row in rows:
            detail = unseal(store.key, row["payload"], row["id"])
            # Fixed fields only. Never export arbitrary notes, policy inputs,
            # authorization tokens, terminal output or recovery receipts.
            event = {
                "schema": "northgate.fleet.event.v1",
                "event_id": row["id"],
                "timestamp": row["created"],
                "endpoint": row["endpoint"],
                "action": row["action"],
                "exercise": row["exercise"],
                "detail": {
                    name: detail[name]
                    for name in (
                        "subject",
                        "run",
                        "job",
                        "action",
                        "eligible",
                        "excluded",
                        "progress",
                        "alert",
                        "severity",
                        "condition",
                        "cycle",
                    )
                    if name in detail
                },
            }
            stream.write(json.dumps(event, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        offset = os.fstat(stream.fileno()).st_size
    temporary = checkpoint.with_name(checkpoint.name + "." + uuid4().hex + ".pending")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(
            {
                "sequence": rows[-1]["position"],
                "output": str(output.resolve()),
                "offset": offset,
            },
            stream,
        )
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, checkpoint)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    access = commands.add_parser("validate-access")
    access.add_argument("--operator", type=Path, required=True)
    access.add_argument("--bridge", type=Path, required=True)
    events = commands.add_parser("export-events")
    for name in ("root", "key", "output", "checkpoint"):
        events.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.command == "validate-access":
        print(json.dumps(validate_access(args.operator, args.bridge)))
    else:
        for destination in (args.output, args.checkpoint):
            if destination.resolve() == args.key.resolve() or (
                destination.exists() and destination.samefile(args.key)
            ):
                raise ValueError("Export paths must not overwrite the encryption key")
        with regular_file_reference(
            args.key, label="management storage key", maximum_bytes=64, private=True
        ) as ref:
            key = bytes.fromhex(ref.read_text().strip())
        if len(key) != 16:
            raise ValueError("Existing management key required")
        count = export_events(
            ManagementStore(args.root, key), args.output, args.checkpoint
        )
        print(json.dumps({"exported": count}))


if __name__ == "__main__":
    main()
