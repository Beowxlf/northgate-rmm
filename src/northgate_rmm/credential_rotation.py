"""Human-authorized, escrow-first local Windows password rotation.

Only encrypted candidate envelopes enter the management queue. An uncertain
apply is never reissued: a fresh human session may request authentication only.
The independent RDP verifier is mandatory and is supplied by deployment.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid5

from aiohttp import web
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from northgate_rmm.management import RECOVERY_ROLE, Management
from northgate_rmm.management_protocol import TERMINAL, validate_action
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.remote_policy import RemoteTarget
from northgate_rmm.secure_files import regular_file_reference

Record = dict[str, Any]


def load_rotation_configuration(path: Path) -> Record:
    """Public verifier configuration; root owns the opt-in on the Linux server."""
    with regular_file_reference(
        path, label="credential rotation verifier", maximum_bytes=4096, private=False
    ) as ref:
        info = ref.stat()
        if os.name == "posix" and (info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError("Rotation verifier configuration must be deployment-owned")
        value = json.loads(ref.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or frozenset(value)
        not in {
            frozenset({"schema", "executable", "executable_sha256", "timeout_seconds"}),
            frozenset(
                {
                    "schema",
                    "executable",
                    "executable_sha256",
                    "timeout_seconds",
                    "xvfb_executable",
                    "xvfb_sha256",
                }
            ),
        }
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or not isinstance(value["executable"], str)
        or not Path(value["executable"]).is_absolute()
        or not isinstance(value["executable_sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", value["executable_sha256"])
        or type(value["timeout_seconds"]) is not int
        or not 1 <= value["timeout_seconds"] <= 30
    ):
        raise ValueError("Invalid credential rotation verifier configuration")
    if "xvfb_executable" in value and (
        not isinstance(value["xvfb_executable"], str)
        or not Path(value["xvfb_executable"]).is_absolute()
        or not isinstance(value["xvfb_sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", value["xvfb_sha256"])
    ):
        raise ValueError("Invalid optional verifier display configuration")
    return value


class PasswordVerifier(Protocol):
    async def preflight(
        self,
        *,
        target: RemoteTarget,
        parameters: dict[str, str],
        fields: dict[str, str],
    ) -> bool: ...

    async def verify(
        self,
        *,
        target: RemoteTarget,
        parameters: dict[str, str],
        fields: dict[str, str],
    ) -> bool: ...


def candidate_envelope(
    recipient: str,
    endpoint: UUID,
    identity: UUID,
    job_id: str,
    params: Record,
    password: str,
) -> str:
    private = x25519.X25519PrivateKey.generate()
    public = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(recipient, validate=True)
    )
    shared = private.exchange(public)
    key = hmac.digest(shared, b"NorthGate-Credential-v1", "sha256")
    nonce = secrets.token_bytes(12)
    aad = "/".join(
        [
            "NorthGate-Credential-v1",
            str(endpoint),
            str(identity),
            job_id,
            params["rotation_id"],
            params["phase"],
            params["username"],
            params["account_sid"],
            str(params["expected_version"]),
        ]
    ).encode()
    return base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        + nonce
        + AESGCM(key).encrypt(nonce, password.encode(), aad)
    ).decode()


class CredentialRotationExecutor:
    def __init__(
        self, management: Management, verifier: PasswordVerifier | None
    ) -> None:
        self.management = management
        self.gateway: Any = management.gateway
        self.verifier = verifier
        self.api: Any = None

    def bind(self, api: Any) -> None:
        self.api = api
        self.gateway.credential_rotation_authorizer = self.authorize_job

    def capability(self, endpoint: UUID) -> tuple[Record, RemoteTarget, dict[str, str]]:
        if self.verifier is None:
            raise ValueError("Independent RDP authentication verifier unavailable")
        worker = self.management.store.worker(endpoint)
        target, parameters = self.gateway.method_target(endpoint, "rdp")
        cap = (
            worker.get("capabilities", {})
            .get("features", {})
            .get("credential_rotation", {})
        )
        pin = parameters.get("cert-fingerprints", "")
        if (
            not worker.get("ready")
            or worker.get("identity") != str(target.identity_id)
            or worker.get("capabilities", {}).get("platform") != "windows"
            or cap.get("available") is not True
            or cap.get("username") != "rmmremote"
            or not re.fullmatch(
                r"S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[1-9][0-9]{3,9}",
                cap.get("account_sid", ""),
            )
            or cap.get("protocol") != "rdp"
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", cap.get("domain", ""))
            or not re.fullmatch(r"sha256:(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}", pin)
            or parameters.get("security", "nla") != "nla"
            or any(
                parameters.get(k, "false").lower() != "false"
                for k in ("ignore-cert", "cert-tofu", "disable-auth")
            )
        ):
            raise ValueError("Qualified Windows rotation target unavailable")
        if len(base64.b64decode(cap["recipient"], validate=True)) != 32:
            raise ValueError("Worker recipient unavailable")
        return dict(cap), target, dict(parameters)

    def available(self, endpoint: UUID) -> bool:
        try:
            self.capability(endpoint)
            return True
        except (ValueError, KeyError, TypeError, web.HTTPException):
            return False

    async def authorize(
        self, request: web.Request, principal: OperatorPrincipal, record: Record
    ) -> tuple[UUID, UUID]:
        if self.api is None:
            raise ValueError("Secret authorization unavailable")
        endpoint = UUID(record["endpoint_id"])
        current, _config, identity = await self.api.authorize(
            request, endpoint, "rotate", fresh=True
        )
        managed_endpoint, managed, enrollment = await self.management.context(request)
        if (
            record["kind"] != "rdp"
            or record["retired"]
            or str(identity) != record["identity_id"]
            or managed_endpoint != endpoint
            or enrollment.identity_id != identity
            or enrollment.platform.value != "windows"
            or (managed.subject, managed.session_id)
            != (principal.subject, principal.session_id)
            or (current.subject, current.session_id)
            != (principal.subject, principal.session_id)
            or RECOVERY_ROLE not in principal.roles
            or not self.gateway.operation._policy.permits(
                principal.subject, endpoint, "recovery"
            )
        ):
            raise web.HTTPForbidden(
                text="This managed account rotation is not authorized"
            )
        return endpoint, identity

    async def prepare(
        self,
        *,
        record: Record,
        fields: dict[str, str],
        principal: OperatorPrincipal,
        request: web.Request,
    ) -> Record:
        endpoint, _identity = await self.authorize(request, principal, record)
        for other in self.api.state.records(endpoint, _identity):
            if (
                other["id"] != record["id"]
                and other["kind"] == "rdp"
                and any(
                    r["status"] not in {"completed", "failed"}
                    for r in self.api.state.rotations(other["id"])
                )
            ):
                raise web.HTTPConflict(
                    text="Resolve this device's existing account rotation first"
                )
        cap, target, parameters = self.capability(endpoint)
        password = fields.get("password", "")
        if (
            fields.get("username") != cap["username"]
            or fields.get("domain", "").casefold() != cap["domain"].casefold()
            or not re.fullmatch(r"[\x21-\x7e]{16,128}", password)
        ):
            raise web.HTTPBadRequest(
                text=(
                    "Use the configured local account and computer name, and a "
                    "16-128 character printable ASCII password without spaces"
                )
            )
        if (
            self.verifier is None
            or await self.verifier.preflight(
                target=target, parameters=parameters, fields=fields
            )
            is not True
        ):
            raise web.HTTPConflict(
                text="Qualified verifier is unavailable; no password was changed"
            )
        return {k: cap[k] for k in ("username", "account_sid", "domain", "recipient")}

    async def authorize_job(self, principal: OperatorPrincipal, job: Record) -> None:
        """Rechecked on every worker poll using its original human authorization."""
        if self.api is None or job["action"] != "credential.rotate":
            raise ValueError("Credential authorization unavailable")
        endpoint = UUID(job["endpoint"])
        _config, identity = self.api.check_grant(
            principal, endpoint, "rotate", fresh=True
        )
        params = job["payload"]["params"]
        rotation = self.api.state.get("rotations", params["rotation_id"])
        record = (
            self.api.state.get("records", rotation["secret_id"]) if rotation else None
        )
        if (
            not record
            or record["retired"]
            or record["kind"] != "rdp"
            or record["endpoint_id"] != job["endpoint"]
            or record["identity_id"] != job["identity"]
            or str(identity) != job["identity"]
            or rotation["status"] in {"completed", "failed", "commit_conflict"}
            or params["expected_version"] != rotation["expected_version"]
            or any(
                params[k] != rotation["executor_binding"][k]
                for k in ("username", "account_sid")
            )
        ):
            raise ValueError("Rotation binding or authorization changed")
        cap, _target, _parameters = self.capability(endpoint)
        if any(
            cap[k] != rotation["executor_binding"][k]
            for k in ("username", "account_sid", "domain", "recipient")
        ):
            raise ValueError("Managed account or worker recipient changed")

    async def dispatch(
        self,
        *,
        request: web.Request,
        principal: OperatorPrincipal,
        record: Record,
        rotation: Record,
        fields: dict[str, str],
        phase: str,
    ) -> Record:
        endpoint, identity = await self.authorize(request, principal, record)
        binding = await self.prepare(
            record=record, fields=fields, principal=principal, request=request
        )
        if binding != rotation["executor_binding"]:
            raise ValueError("Managed account or worker recipient changed")
        rid = rotation["id"]
        # The apply UUID is stable across sessions; a check UUID is stable for
        # each explicitly resumed human session and cannot trigger a setter.
        name = "apply" if phase == "apply" else "check/" + principal.session_id
        identifier = str(uuid5(UUID(rid), name))
        try:
            existing = self.management.store.job(identifier, private=True)
        except KeyError:
            existing = None
        if existing:
            if (existing["endpoint"], existing["identity"], existing["action"]) != (
                str(endpoint),
                str(identity),
                "credential.rotate",
            ):
                raise ValueError("Rotation job identity conflict")
            return existing
        params = {
            "rotation_id": rid,
            "phase": phase,
            "username": binding["username"],
            "account_sid": binding["account_sid"],
            "protocol": "rdp",
            "expected_version": rotation["expected_version"],
        }
        params["candidate"] = candidate_envelope(
            binding["recipient"],
            endpoint,
            identity,
            identifier,
            params,
            fields["password"],
        )
        validate_action("credential.rotate", params, "windows")
        await self.gateway.audit(
            principal, endpoint, "secret.rotation.worker_" + phase, UUID(identifier)
        )
        # The real bearer authorization is retained, never synthesized from a principal.
        self.management.store.add(
            endpoint,
            identity,
            principal,
            "credential.rotate",
            params,
            request.headers["Authorization"],
            seconds=300,
            identifier=identifier,
        )
        return self.management.store.job(identifier, private=True)

    async def apply(
        self,
        *,
        request: web.Request,
        principal: OperatorPrincipal,
        record: Record,
        rotation: Record,
        fields: dict[str, str],
        **_kwargs: Any,
    ) -> Record:
        job = await self.dispatch(
            request=request,
            principal=principal,
            record=record,
            rotation=rotation,
            fields=fields,
            phase="apply",
        )
        return {
            "status": "pending" if job["state"] not in TERMINAL else "unknown",
            "job_id": job["id"],
        }

    async def check(
        self,
        *,
        request: web.Request,
        principal: OperatorPrincipal,
        record: Record,
        rotation: Record,
        fields: dict[str, str],
        job_id: str,
        **_kwargs: Any,
    ) -> Record:
        await self.authorize(request, principal, record)
        identifier = job_id or str(uuid5(UUID(rotation["id"]), "apply"))
        try:
            job = self.management.store.job(identifier, private=True)
        except KeyError:
            # Absence cannot prove that a pre-crash dispatch did not run.
            return {"status": "unknown", "job_id": ""}
        await self.authorize_job(principal, job)
        params = job["payload"]["params"]
        if params["rotation_id"] != rotation["id"]:
            raise ValueError("Rotation job changed")
        if job["state"] not in TERMINAL:
            return {"status": "pending", "job_id": job["id"]}
        receipt = job.get("receipt", {})
        try:
            output = json.loads(receipt.get("output", ""))
        except (ValueError, TypeError):
            output = {}
        valid_receipt = (
            job["state"] == "completed"
            and receipt.get("state") == "completed"
            and receipt.get("exit_code") == 0
            and receipt.get("truncated") is False
            and output.get("rotation_id") == rotation["id"]
            and output.get("username") == rotation["executor_binding"]["username"]
            and output.get("account_sid") == rotation["executor_binding"]["account_sid"]
            and output.get("protocol") == "rdp"
        )
        if (
            valid_receipt
            and output.get("status") == "failed"
            and output.get("local_authenticated") is False
        ):
            return {"status": "failed", "job_id": job["id"]}
        local_verified = (
            valid_receipt
            and output.get("local_authenticated") is True
            and output.get("status") == "verified"
        )
        if local_verified:
            if self.verifier is None:
                raise ValueError("Independent RDP authentication verifier unavailable")
            _cap, target, parameters = self.capability(UUID(record["endpoint_id"]))
            async with asyncio.timeout(45):
                verified = await self.verifier.verify(
                    target=target, parameters=parameters, fields=fields
                )
            await self.authorize(request, principal, record)
            await self.authorize_job(principal, job)
            return {
                "status": "verified" if verified is True else "unknown",
                "job_id": job["id"],
            }
        # A check in the same human session is idempotent. After a crash, expired
        # lease or a changed session, authenticate only; never reapply a password.
        check = await self.dispatch(
            request=request,
            principal=principal,
            record=record,
            rotation=rotation,
            fields=fields,
            phase="check",
        )
        return {
            "status": "pending" if check["state"] not in TERMINAL else "unknown",
            "job_id": check["id"],
        }
