"""Explicit machine grants and short-lived, revocable job authorization.

Machine clients never impersonate an MFA-authenticated browser operator.
Only token hashes enter the registry; persistent client tokens never enter jobs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from northgate_rmm.management_protocol import canonical, derive
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.secure_files import regular_file_reference

PREFIX = "RMM-Integration-Job "


class IntegrationAuth:
    def __init__(self, path: Path, key: bytes):
        self.path, self.key = path, derive(key, "integration-jobs")

    def entries(self):
        with regular_file_reference(
            self.path, label="integration registry", maximum_bytes=65536, private=True
        ) as ref:
            value = json.loads(ref.read_text())
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise ValueError("Invalid integration registry")
        entries = value.get("clients")
        if not isinstance(entries, list) or len(entries) > 32:
            raise ValueError("Invalid integration clients")
        result = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "id",
                "token_sha256",
                "enabled",
                "endpoints",
                "actions",
            }:
                raise ValueError("Invalid integration entry")
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", entry["id"]):
                raise ValueError("Invalid integration identity")
            if entry["id"] in result or type(entry["enabled"]) is not bool:
                raise ValueError("Duplicate or invalid integration")
            if not re.fullmatch(r"[a-f0-9]{64}", entry["token_sha256"]):
                raise ValueError("Invalid integration token hash")
            endpoints = entry["endpoints"]
            if not isinstance(endpoints, dict) or not 1 <= len(endpoints) <= 256:
                raise ValueError("Explicit enrollment scope required")
            for endpoint, identity in endpoints.items():
                if str(UUID(endpoint)) != endpoint or str(UUID(identity)) != identity:
                    raise ValueError("Invalid integration enrollment")
            actions = entry["actions"]
            if (
                not isinstance(actions, list)
                or len(actions) > 64
                or any(
                    not isinstance(a, str) or not re.fullmatch(r"[a-z.]{1,48}", a)
                    for a in actions
                )
            ):
                raise ValueError("Invalid integration actions")
            result[entry["id"]] = entry
        return result

    def authenticate(self, authorization: str):
        match = re.fullmatch(r"Bearer ([A-Za-z0-9_-]{43,128})", authorization)
        if match is None:
            raise ValueError("Integration authentication required")
        digest = hashlib.sha256(match[1].encode()).hexdigest()
        for entry in self.entries().values():
            if entry["enabled"] and hmac.compare_digest(digest, entry["token_sha256"]):
                return entry
        raise ValueError("Integration authentication rejected")

    def current(self, entry):
        live = self.entries().get(entry["id"])
        if (
            not live
            or not live["enabled"]
            or not hmac.compare_digest(live["token_sha256"], entry["token_sha256"])
        ):
            raise ValueError("Integration revoked")
        return live

    @staticmethod
    def principal(entry, session):
        now = datetime.now(UTC)
        return OperatorPrincipal(
            issuer="urn:northgate:rmm:integration",
            tenant="lab",
            subject="integration:" + entry["id"],
            session_id=session,
            client_id=entry["id"],
            roles=("integration",),
            authenticated_at=now,
            expires_at=now + timedelta(minutes=15),
            mfa=False,
        )

    def ticket(self, entry, job, endpoint, identity, action, params, expires):
        claims = dict(
            client=entry["id"],
            credential=entry["token_sha256"],
            job=job,
            endpoint=str(endpoint),
            identity=str(identity),
            action=action,
            params_sha256=hashlib.sha256(canonical(params)).hexdigest(),
            expires=expires,
        )
        payload = base64.urlsafe_b64encode(canonical(claims)).decode()
        return (
            PREFIX
            + payload
            + "."
            + hmac.digest(self.key, payload.encode(), "sha256").hex()
        )

    def verify_job(self, job):
        ticket = job["payload"]["authorization"]
        if not ticket.startswith(PREFIX) or len(ticket) > 4096:
            raise ValueError("Invalid integration ticket")
        payload, signature = ticket[len(PREFIX) :].split(".")
        if not hmac.compare_digest(
            signature, hmac.digest(self.key, payload.encode(), "sha256").hex()
        ):
            raise ValueError("Invalid integration job signature")
        value = json.loads(base64.b64decode(payload, altchars=b"-_", validate=True))
        entry = self.entries()[value["client"]]
        if not entry["enabled"] or not hmac.compare_digest(
            entry["token_sha256"], value["credential"]
        ):
            raise ValueError("Integration credential revoked")
        if not datetime.now(UTC).timestamp() < value["expires"] <= job["created"] + 901:
            raise ValueError("Integration job expired")
        for name in ("endpoint", "identity", "action"):
            if value[name] != job[name]:
                raise ValueError("Integration job binding differs")
        if (
            value["job"] != job["id"]
            or job["session"] != job["id"]
            or job["subject"] != "integration:" + entry["id"]
            or value["params_sha256"]
            != hashlib.sha256(canonical(job["payload"]["params"])).hexdigest()
            or entry["endpoints"].get(job["endpoint"]) != job["identity"]
            or job["action"] not in entry["actions"]
        ):
            raise ValueError("Integration job scope revoked")
        return entry
