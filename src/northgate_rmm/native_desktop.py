"""Owner-bound Windows DPAPI envelopes for native lab desktop downloads.

The server cannot create a portable RDP password. An authorized workstation
protects it with its user's DPAPI key. A keyed credential binding rejects stale
envelopes after a password, username, address or enrollment changes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import cast
from uuid import UUID

from northgate_rmm.remote_policy import RemoteTarget
from northgate_rmm.secure_files import regular_file_reference


def credential_binding(
    key: bytes,
    endpoint: UUID | str,
    identity: UUID | str,
    address: str,
    username: str,
    password: str,
) -> str:
    value = json.dumps(
        [str(endpoint), str(identity), address, username, password],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()
    return hmac.new(key, b"native-desktop-v1\x00" + value, hashlib.sha256).hexdigest()


class NativeDesktopProfiles:
    def __init__(self, path: Path, key: bytes):
        self.path, self.key = path, key

    def record(self, subject: str, target: RemoteTarget) -> dict[str, str] | None:
        # Read on each download so replacing/revoking a profile is immediate.
        with regular_file_reference(
            self.path,
            label="native desktop profiles",
            maximum_bytes=1024 * 1024,
            private=True,
        ) as path:
            document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schema") != 1 or not isinstance(document.get("records"), list):
            raise ValueError("Invalid native desktop profiles")
        matches = [
            r
            for r in document["records"]
            if r.get("subject") == subject
            and r.get("endpoint_id") == str(target.endpoint_id)
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError("Ambiguous native desktop profile")
        record = matches[0]
        if (
            UUID(record["identity_id"]) != target.identity_id
            or record["address"] != target.address
            or not re.fullmatch(r"[A-Za-z0-9_.\\@-]{1,128}", record["username"])
            or not re.fullmatch(r"[a-f0-9]{64}", record["credential_binding"])
            or not re.fullmatch(r"(?:[a-fA-F0-9]{2}){100,8192}", record["password51"])
            or not record["password51"]
            .lower()
            .startswith("01000000d08c9ddf0115d1118c7a00c04fc297eb")
        ):
            raise ValueError("Invalid or stale native desktop profile")
        return cast(dict[str, str], record)

    def validate(
        self, record: dict[str, str], target: RemoteTarget, fields: dict[str, str]
    ) -> str:
        username = fields["username"]
        if fields.get("domain"):
            username = fields["domain"] + "\\" + username
        actual = credential_binding(
            self.key,
            target.endpoint_id,
            target.identity_id,
            target.address,
            username,
            fields["password"],
        )
        if username != record["username"] or not hmac.compare_digest(
            actual, record["credential_binding"]
        ):
            raise ValueError("Saved workstation credentials need refreshing")
        return record["password51"]
