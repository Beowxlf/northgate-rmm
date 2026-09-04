"""Local administrative entry point; never exposes an HTTP mutation route."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from northgate_rmm.agent_service import load_database_dsn
from northgate_rmm.domain import Platform
from northgate_rmm.persistence import PostgresControlPlane, apply_migrations


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="northgate-rmm-admin")
    parser.add_argument("--dsn-file", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate")
    commands.add_parser("check-schema")
    grant = commands.add_parser("create-grant")
    grant.add_argument("--name", required=True)
    grant.add_argument("--platform", required=True, choices=["linux", "windows"])
    grant.add_argument("--output", type=Path, required=True)
    grant.add_argument("--ttl-minutes", type=int, choices=range(1, 16), default=10)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--identity-id", required=True, type=UUID)
    revoke.add_argument("--reason", required=True)
    arguments = parser.parse_args(argv)
    store: PostgresControlPlane | None = None
    try:
        dsn = load_database_dsn(arguments.dsn_file)
        if arguments.command == "migrate":
            result: object = {"applied": apply_migrations(dsn)}
        else:
            store = PostgresControlPlane(dsn)
            versions = store.verify_schema_state()
            now = datetime.now(UTC)
            # Local credentials are the authority; the invoker cannot choose
            # another actor name through a command-line argument.
            get_uid = getattr(os, "getuid", None)
            if get_uid is None:
                raise RuntimeError("administration requires the Debian server")
            actor = f"local-uid:{get_uid()}"
            if arguments.command == "check-schema":
                result = {"schema": versions}
            elif arguments.command == "create-grant":
                if not arguments.output.is_absolute():
                    raise ValueError("output must be absolute")
                # Reserve exclusively before consuming database authority.
                descriptor = os.open(
                    arguments.output,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "w", encoding="ascii") as output:
                    enrollment, token = store.create_enrollment_grant(
                        display_name=arguments.name,
                        platform=Platform(arguments.platform),
                        architecture="amd64",
                        now=now,
                        actor_id=actor,
                        ttl=timedelta(minutes=arguments.ttl_minutes),
                    )
                    output.write(token + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                result = {
                    "grant_id": str(enrollment.grant_id),
                    "expires_at": enrollment.expires_at.isoformat(),
                }
            else:
                identity = store.revoke_identity(
                    arguments.identity_id,
                    reason=arguments.reason,
                    actor_id=actor,
                    now=now,
                )
                result = {"identity_id": str(identity.identity_id), "revoked": True}
        print(json.dumps(result))
        return 0
    except Exception:
        # Database errors may contain credentials. Output only a fixed code.
        print(
            "administrative operation failed; reconcile state before retry",
            file=sys.stderr,
        )
        return 1
    finally:
        if store is not None:
            store.begin_shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
