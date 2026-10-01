"""Machine registry and signed job authorization reject malformed/revoked scope."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from uuid import uuid4

import pytest

from northgate_rmm.integration_auth import (
    IntegrationAuth,
    IntegrationEntry,
    IntegrationJob,
)


def registry(tmp_path: Path) -> tuple[IntegrationAuth, IntegrationEntry]:
    entry: IntegrationEntry = {
        "id": "synthetic",
        "token_sha256": hashlib.sha256(b"A" * 43).hexdigest(),
        "enabled": True,
        "endpoints": {str(uuid4()): str(uuid4())},
        "actions": ["posture"],
    }
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"schema": 1, "clients": [entry]}))
    path.chmod(0o600)
    return IntegrationAuth(path, bytes(range(16))), entry


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 1),
        ("id", "UPPER"),
        ("enabled", 1),
        ("token_sha256", 1),
        ("token_sha256", "wrong"),
        ("endpoints", {}),
        ("endpoints", []),
        ("endpoints", {"invalid": "invalid"}),
        ("endpoints", {str(uuid4()): 1}),
        ("actions", {}),
        ("actions", [1]),
        ("actions", ["arbitrary_shell!"]),
    ],
)
def test_invalid_registry_entry_fails_closed(
    tmp_path: Path, field: str, value: object
) -> None:
    auth, entry = registry(tmp_path)
    invalid = dict(entry)
    invalid[field] = value
    auth.path.write_text(json.dumps({"schema": 1, "clients": [invalid]}))
    with pytest.raises(ValueError):
        auth.entries()


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        {"schema": 2},
        {"schema": 1, "clients": {}},
        {"schema": 1, "clients": [{}]},
        {"schema": 1, "clients": [{}] * 33},
    ],
)
def test_registry_envelope_validation(tmp_path: Path, envelope: object) -> None:
    auth, _ = registry(tmp_path)
    auth.path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError):
        auth.entries()


def test_registry_duplicate_and_live_revocation(tmp_path: Path) -> None:
    auth, entry = registry(tmp_path)
    assert auth.authenticate("Bearer " + "A" * 43) == entry
    assert auth.current(entry) == entry
    for malformed in ("", "Basic synthetic", "Bearer " + "B" * 43):
        with pytest.raises(ValueError):
            auth.authenticate(malformed)
    auth.path.write_text(json.dumps({"schema": 1, "clients": [entry, entry]}))
    with pytest.raises(ValueError, match="Duplicate"):
        auth.entries()
    for clients in (
        [],
        [{**entry, "enabled": False}],
        [{**entry, "token_sha256": "b" * 64}],
    ):
        auth.path.write_text(json.dumps({"schema": 1, "clients": clients}))
        with pytest.raises(ValueError, match="revoked"):
            auth.current(entry)


@pytest.mark.parametrize(
    "mode",
    [
        "valid",
        "prefix",
        "oversized",
        "signature",
        "expired",
        "deadline",
        "credential",
        "enrollment",
        "action",
        "job",
        "session",
        "subject",
        "parameters",
        "binding",
    ],
)
def test_job_ticket_is_signed_short_lived_revocable_and_fully_bound(
    tmp_path: Path, mode: str
) -> None:
    auth, entry = registry(tmp_path)
    endpoint, identity = next(iter(entry["endpoints"].items()))
    identifier = str(uuid4())
    now = time.time()
    deadline = (
        now - 1 if mode == "expired" else now + (1000 if mode == "deadline" else 60)
    )
    ticket = auth.ticket(entry, identifier, endpoint, identity, "posture", {}, deadline)
    job: IntegrationJob = {
        "id": identifier,
        "session": identifier,
        "subject": "integration:synthetic",
        "endpoint": endpoint,
        "identity": identity,
        "action": "posture",
        "created": now,
        "payload": {"authorization": ticket, "params": {}},
    }
    if mode == "prefix":
        job["payload"]["authorization"] = "wrong prefix"
    elif mode == "oversized":
        job["payload"]["authorization"] = "RMM-Integration-Job " + "x" * 4096
    elif mode == "signature":
        job["payload"]["authorization"] = ticket[:-1] + (
            "a" if ticket[-1] != "a" else "b"
        )
    elif mode == "credential":
        entry["enabled"] = False
    elif mode == "enrollment":
        entry["endpoints"][endpoint] = str(uuid4())
    elif mode == "action":
        entry["actions"] = []
    elif mode == "job":
        job["id"] = str(uuid4())
    elif mode == "session":
        job["session"] = str(uuid4())
    elif mode == "subject":
        job["subject"] = "integration:other"
    elif mode == "parameters":
        job["payload"]["params"] = {"unexpected": True}
    elif mode == "binding":
        job["identity"] = str(uuid4())
    auth.path.write_text(json.dumps({"schema": 1, "clients": [entry]}))
    if mode == "valid":
        assert auth.verify_job(job) == entry
        principal = auth.principal(entry, identifier)
        assert principal.mfa is False and principal.roles == ("integration",)
    else:
        with pytest.raises(ValueError):
            auth.verify_job(job)
