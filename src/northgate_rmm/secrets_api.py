"""Human-only secret management; ordinary responses contain provider metadata only.

Secret permissions are deployment-owned and independent of RMM owner privileges.
An optional credential rotator must implement idempotent apply/check and positively
verify the new credential before the provider's active version can be promoted.
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from aiohttp import web

from northgate_rmm.errors import ValidationError
from northgate_rmm.secrets_vault import OpenBaoKV, VaultError, relative_path
from northgate_rmm.secure_files import regular_file_reference

PERMISSIONS = {"metadata", "use", "reveal", "rotate", "admin"}
KINDS = {
    "rdp": {"username", "password", "domain"},
    "ssh": {"username", "private-key", "passphrase"},
    "api": {"token"},
    "recovery": {"key"},
}
HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class SecretState:
    """Stores references and workflow state only, never credential values."""

    def __init__(self, path):
        path = Path(path)
        if path.is_symlink():
            raise ValueError("Secret state must not be a symbolic link")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, "
            "endpoint TEXT, identity TEXT, value TEXT)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS rotations "
            "(id TEXT PRIMARY KEY, secret TEXT, value TEXT)"
        )
        self.db.commit()
        path.chmod(0o600)

    def get(self, table, identifier):
        if table not in {"records", "rotations"}:
            raise ValueError("Invalid state table")
        with self.lock:
            query = {
                "records": "SELECT value FROM records WHERE id=?",
                "rotations": "SELECT value FROM rotations WHERE id=?",
            }[table]
            row = self.db.execute(query, (str(identifier),)).fetchone()
        return json.loads(row[0]) if row else None

    def save_record(self, record):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO records VALUES(?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                (
                    record["id"],
                    record["endpoint_id"],
                    record["identity_id"],
                    json.dumps(record),
                ),
            )

    def records(self, endpoint, identity):
        with self.lock:
            rows = self.db.execute(
                "SELECT value FROM records WHERE endpoint=? AND identity=? "
                "ORDER BY rowid LIMIT 1000",
                (str(endpoint), str(identity)),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def save_rotation(self, rotation):
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO rotations VALUES(?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                (rotation["id"], rotation["secret_id"], json.dumps(rotation)),
            )

    def rotations(self, secret_id):
        with self.lock:
            rows = self.db.execute(
                "SELECT value FROM rotations WHERE secret=? "
                "ORDER BY rowid DESC LIMIT 50",
                (secret_id,),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]


def load_config(path):
    with regular_file_reference(
        Path(path),
        label="secret integration configuration",
        maximum_bytes=1024 * 1024,
        private=True,
    ) as ref:
        value = json.loads(ref.read_text())
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "provider", "prefix", "grants"}
        or value["schema"] != 1
    ):
        raise ValueError("Invalid secret integration configuration")
    relative_path(value["prefix"])
    if not isinstance(value["grants"], list) or len(value["grants"]) > 4096:
        raise ValueError("Invalid secret grants")
    for grant in value["grants"]:
        if not isinstance(grant, dict) or set(grant) != {
            "subject",
            "endpoints",
            "permissions",
        }:
            raise ValueError("Invalid secret grant")
        if (
            not isinstance(grant["subject"], str)
            or not grant["subject"]
            or len(grant["subject"]) > 256
        ):
            raise ValueError("Invalid secret subject")
        if not isinstance(grant["endpoints"], dict) or len(grant["endpoints"]) > 4096:
            raise ValueError("Invalid secret scope")
        for endpoint, identity in grant["endpoints"].items():
            if str(UUID(endpoint)) != endpoint or str(UUID(identity)) != identity:
                raise ValueError("Invalid secret enrollment")
        if (
            not isinstance(grant["permissions"], list)
            or not set(grant["permissions"]) <= PERMISSIONS
        ):
            raise ValueError("Invalid secret permissions")
    return value


def validate_fields(kind, fields):
    if (
        kind not in KINDS
        or not isinstance(fields, dict)
        or not fields
        or not set(fields) <= KINDS[kind]
    ):
        raise ValueError("Invalid credential fields")
    required = {
        "rdp": {"username", "password"},
        "ssh": {"username", "private-key"},
        "api": {"token"},
        "recovery": {"key"},
    }[kind]
    if not required <= set(fields) or any(
        not isinstance(v, str) or not v or len(v) > 32768 for v in fields.values()
    ):
        raise ValueError("Incomplete or oversized credential fields")
    if len(json.dumps(fields).encode()) > 60000:
        raise ValueError("Credential value exceeds 60 KB")
    return dict(fields)


class SecretsAPI:
    def __init__(
        self,
        gateway,
        config_path,
        *,
        state_path,
        rotation_executor=None,
        management=None,
        provider_factory=OpenBaoKV,
    ):
        self.gateway = gateway
        self.config_path = Path(config_path)
        load_config(self.config_path)
        self.state = SecretState(state_path)
        self.rotation_executor = rotation_executor
        self.management = management
        self.provider_factory = provider_factory
        self.forms = {}
        self.slots = asyncio.Semaphore(4)
        self.mutation_lock = asyncio.Lock()
        gateway.secret_resolver = self.resolve_remote
        gateway.secret_authorizer = self.authorize_remote_use
        gateway.legacy_credential_guard = self.guard_legacy_reveal
        if rotation_executor is not None and hasattr(rotation_executor, "bind"):
            rotation_executor.bind(self)

    async def authorize(self, request, endpoint, permission, *, fresh=False):
        principal = await self.gateway.principal(
            request, endpoint, require_online=False
        )
        config, identity = self.check_grant(
            principal, endpoint, permission, fresh=fresh
        )
        return principal, config, identity

    def check_grant(self, principal, endpoint, permission, *, fresh=False):
        if (
            not principal.mfa
            or principal.subject.startswith("integration:")
            or (
                fresh
                and datetime.now(UTC) - principal.authenticated_at
                > timedelta(minutes=5)
            )
        ):
            raise web.HTTPForbidden(
                text="Sign in again with MFA for this secret action"
            )
        try:
            config = load_config(self.config_path)
        except (ValidationError, OSError, ValueError, KeyError, TypeError):
            raise web.HTTPServiceUnavailable(
                text="Secret integration configuration is unavailable"
            ) from None
        identity = self.gateway.targets[endpoint][0].identity_id
        allowed = any(
            g["subject"] == principal.subject
            and g["endpoints"].get(str(endpoint)) == str(identity)
            and permission in g["permissions"]
            for g in config["grants"]
        )
        if not allowed:
            raise web.HTTPForbidden(text="This secret permission has not been granted")
        return config, identity

    def token(self, principal, endpoint):
        now = datetime.now(UTC)
        self.forms = {k: v for k, v in self.forms.items() if v[3] > now}
        if len(self.forms) >= 256:
            raise web.HTTPTooManyRequests()
        nonce = secrets.token_urlsafe(32)
        self.forms[nonce] = (
            principal.subject,
            principal.session_id,
            str(endpoint),
            now + timedelta(minutes=5),
        )
        return nonce

    def consume(self, nonce, principal, endpoint):
        item = self.forms.pop(nonce, None)
        if (
            not item
            or item[:3] != (principal.subject, principal.session_id, str(endpoint))
            or item[3] <= datetime.now(UTC)
        ):
            raise web.HTTPForbidden(text="Refresh the secrets panel before retrying")

    async def audit(self, principal, endpoint, action, identifier):
        await self.gateway.audit(
            principal, endpoint, "secret." + action, UUID(identifier)
        )

    async def provider_call(self, provider, name, *args, **kwargs):
        async with asyncio.timeout(20):
            await self.slots.acquire()
        task = asyncio.create_task(
            asyncio.to_thread(getattr(provider, name), *args, **kwargs)
        )

        def completed(result):
            self.slots.release()
            if not result.cancelled():
                result.exception()

        task.add_done_callback(completed)
        return await asyncio.shield(task)

    def record(self, identifier, endpoint, identity):
        try:
            identifier = str(UUID(identifier))
        except (ValueError, TypeError):
            raise web.HTTPNotFound() from None
        item = self.state.get("records", identifier)
        if not item or (item["endpoint_id"], item["identity_id"]) != (
            str(endpoint),
            str(identity),
        ):
            raise web.HTTPNotFound()
        return item

    async def summary(self, provider, record):
        result = {
            k: record[k] for k in ("id", "label", "kind", "retired", "use_for_remote")
        }
        result.update(
            {
                k: record[k]
                for k in ("source_job", "source_action", "expires_at")
                if k in record
            }
        )
        try:
            if provider is None:
                raise VaultError()
            metadata = await self.provider_call(provider, "metadata", record["path"])
            result.update(
                available=True,
                current_version=metadata.get("current_version", 0),
                versions=[
                    {
                        "version": int(k),
                        "created_at": v.get("created_time", ""),
                        "deleted": bool(v.get("deletion_time")),
                        "destroyed": v.get("destroyed") is True,
                    }
                    for k, v in metadata.get("versions", {}).items()
                    if str(k).isdigit()
                ],
            )
        except (VaultError, TimeoutError) as error:
            result.update(
                available=isinstance(error, VaultError) and error.status == 404,
                current_version=0
                if isinstance(error, VaultError) and error.status == 404
                else None,
                versions=[],
            )
        result["rotations"] = [
            {
                k: v
                for k, v in r.items()
                if k in {"id", "status", "job_id", "created_at", "version"}
            }
            for r in self.state.rotations(record["id"])
        ]
        return result

    async def get_state(self, request):
        endpoint = self.endpoint(request)
        principal, config, identity = await self.authorize(
            request, endpoint, "metadata"
        )
        try:
            offset = int(request.query.get("offset", "0"))
            if not 0 <= offset <= 1000:
                raise ValueError()
        except ValueError:
            raise web.HTTPBadRequest(text="Invalid credential page") from None
        provider = None
        try:
            provider = self.provider(config)
            health = await self.provider_call(provider, "health")
        except (VaultError, TimeoutError):
            health = {"available": False, "sealed": True, "initialized": False}
            provider = None
        all_records = self.state.records(endpoint, identity)
        # One page and four concurrent provider requests bound metadata work.
        records = []
        for start in range(offset, min(offset + 20, len(all_records)), 4):
            records.extend(
                await asyncio.gather(
                    *(
                        self.summary(provider, record)
                        for record in all_records[start : min(start + 4, offset + 20)]
                    )
                )
            )
        await self.authorize(request, endpoint, "metadata")
        permissions = sorted(
            {
                permission
                for g in config["grants"]
                if g["subject"] == principal.subject
                and g["endpoints"].get(str(endpoint)) == str(identity)
                for permission in g["permissions"]
            }
        )
        recovery_jobs = []
        recovery_available = False
        if self.management is not None and "admin" in permissions:
            try:
                await self.recovery_context(request, endpoint, identity)
                recovery_available = True
                jobs = await asyncio.to_thread(self.management.store.list, endpoint)
                recovery_jobs = [
                    {k: j[k] for k in ("id", "action", "created")}
                    for j in jobs
                    if j["identity"] == str(identity)
                    and j["action"] in {"bitlocker.escrow", "recovery.rotate"}
                    and j["state"] == "completed"
                ]
            except web.HTTPForbidden:
                pass
        return web.json_response(
            {
                "provider": "OpenBao",
                "health": health,
                "records": records,
                "offset": offset,
                "total": len(all_records),
                "next_offset": offset + 20 if offset + 20 < len(all_records) else None,
                "permissions": permissions,
                "nonce": self.token(principal, endpoint),
                "endpoint_rotation_available": self.rotation_executor is not None
                and (
                    not hasattr(self.rotation_executor, "available")
                    or self.rotation_executor.available(endpoint)
                ),
                "recovery_import_available": recovery_available,
                "recovery_jobs": recovery_jobs,
            },
            headers=HEADERS,
        )

    @staticmethod
    def endpoint(request):
        try:
            return UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None

    async def action(self, request):
        endpoint = self.endpoint(request)
        if request.headers.get("Origin") != self.gateway.origin:
            raise web.HTTPForbidden()
        if request.content_type != "application/json" or (
            request.content_length and request.content_length > 65536
        ):
            raise web.HTTPBadRequest(text="Use a bounded JSON secret request")
        try:
            async with asyncio.timeout(15):
                data = bytearray()
                async for chunk in request.content.iter_chunked(8192):
                    data.extend(chunk)
                    if len(data) > 65536:
                        raise ValueError()
            body = json.loads(data)
            if not isinstance(body, dict):
                raise ValueError()
            action = body.get("action")
            permission = {
                "create": "admin",
                "edit": "admin",
                "retire": "admin",
                "replace": "admin",
                "delete_version": "admin",
                "restore_version": "admin",
                "reveal": "reveal",
                "rotate": "rotate",
                "resume_rotation": "rotate",
                "import_recovery": "admin",
            }[action]
            principal, config, identity = await self.authorize(
                request,
                endpoint,
                permission,
                fresh=action
                in {
                    "create",
                    "replace",
                    "reveal",
                    "rotate",
                    "resume_rotation",
                    "import_recovery",
                },
            )
            self.consume(body.get("nonce"), principal, endpoint)
            async with self.mutation_lock:
                principal, config, identity = await self.authorize(
                    request,
                    endpoint,
                    permission,
                    fresh=action
                    in {
                        "create",
                        "replace",
                        "reveal",
                        "rotate",
                        "resume_rotation",
                        "import_recovery",
                    },
                )
                result = await self.perform(
                    request, endpoint, identity, principal, config, action, body
                )
            await self.authorize(
                request, endpoint, permission, fresh=action == "reveal"
            )
            return web.json_response(result, headers=HEADERS)
        except VaultError as error:
            if error.status == 404:
                raise web.HTTPNotFound(
                    text="The selected secret version is unavailable"
                ) from None
            if error.status == 400:
                raise web.HTTPConflict(
                    text="Secret version changed; refresh before retrying"
                ) from None
            raise web.HTTPServiceUnavailable(
                text="Secret provider unavailable; refresh to reconcile the outcome"
            ) from None
        except (ValueError, KeyError, TypeError, TimeoutError):
            raise web.HTTPBadRequest(
                text="Invalid or incomplete secret request"
            ) from None

    async def perform(
        self, request, endpoint, identity, principal, config, action, body
    ):
        provider = self.provider(config)
        if action == "import_recovery":
            return await self.import_recovery(
                request, endpoint, identity, principal, config, provider, body
            )
        if action == "create":
            identifier = str(UUID(body["request_id"]))
            if self.state.get("records", identifier):
                raise web.HTTPConflict(
                    text="Secret reference exists; refresh its state"
                )
            if len(self.state.records(endpoint, identity)) >= 1000:
                raise web.HTTPConflict(text="Secret reference limit reached")
            label = self.label(body["label"])
            kind = body["kind"]
            fields = validate_fields(kind, body["fields"])
            record = {
                "id": identifier,
                "endpoint_id": str(endpoint),
                "identity_id": str(identity),
                "label": label,
                "kind": kind,
                "retired": False,
                "use_for_remote": False,
                "path": (
                    f"{config['prefix']}/endpoints/{endpoint}/{identity}/{identifier}"
                ),
            }
            await self.audit(principal, endpoint, "create_requested", identifier)
            # Persist reference first: uncertain network results remain discoverable.
            self.state.save_record(record)
            await self.provider_call(
                provider, "configure_metadata", record["path"], label, kind
            )
            version = await self.provider_call(
                provider, "write", record["path"], fields, cas=0
            )
            await self.audit(principal, endpoint, "created", identifier)
            return {
                "id": identifier,
                "version": version,
                "message": "Credential stored in OpenBao",
            }
        record = self.record(body["secret_id"], endpoint, identity)
        identifier = record["id"]
        if record["retired"] and action not in {"edit", "restore_version"}:
            raise web.HTTPConflict(text="This secret reference is retired")
        if action == "edit":
            label = self.label(body["label"])
            enabled = body.get("use_for_remote", False)
            if type(enabled) is not bool or (
                enabled and record["kind"] not in {"rdp", "ssh"}
            ):
                raise ValueError()
            if enabled and any(
                r["id"] != identifier
                and r["kind"] == record["kind"]
                and r["use_for_remote"]
                and not r["retired"]
                for r in self.state.records(endpoint, identity)
            ):
                raise web.HTTPConflict(
                    text="Disable the existing remote credential binding first"
                )
            await self.audit(
                principal, endpoint, "metadata_update_requested", identifier
            )
            await self.provider_call(
                provider, "configure_metadata", record["path"], label, record["kind"]
            )
            record.update(
                label=label,
                use_for_remote=enabled,
                retired=False,
                managed_remote=record.get("managed_remote", False) or enabled,
            )
            self.state.save_record(record)
            return {"message": "Secret metadata updated"}
        if action == "retire":
            await self.audit(principal, endpoint, "retired", identifier)
            record.update(retired=True, use_for_remote=False)
            self.state.save_record(record)
            return {
                "message": "Reference retired; provider versions retained for recovery"
            }
        if action == "reveal":
            await self.audit(principal, endpoint, "reveal_requested", identifier)
            fields = await self.provider_call(
                provider, "read", record["path"], body.get("version")
            )
            validate_fields(record["kind"], fields)
            await self.authorize(request, endpoint, "reveal", fresh=True)
            await self.audit(principal, endpoint, "revealed", identifier)
            return {"id": identifier, "fields": fields, "clear_after_seconds": 30}
        if action == "replace":
            fields = validate_fields(record["kind"], body["fields"])
            await self.audit(principal, endpoint, "vault_version_requested", identifier)
            version = await self.provider_call(
                provider, "write", record["path"], fields, cas=body["expected_version"]
            )
            return {
                "id": identifier,
                "version": version,
                "message": (
                    "Vault version updated; the device credential was not changed"
                ),
            }
        if action in {"delete_version", "restore_version"}:
            await self.audit(principal, endpoint, action, identifier)
            await self.provider_call(
                provider,
                "versions",
                record["path"],
                "delete" if action == "delete_version" else "undelete",
                [body["version"]],
            )
            return {"message": "Version lifecycle updated"}
        if action in {"rotate", "resume_rotation"}:
            return await self.rotate(
                request, principal, endpoint, record, provider, config, body, action
            )
        raise ValueError()

    @staticmethod
    def label(value):
        if (
            not isinstance(value, str)
            or not 1 <= len(value.strip()) <= 120
            or not value.isprintable()
        ):
            raise ValueError("Invalid secret label")
        return value.strip()

    async def rotate(
        self, request, principal, endpoint, record, provider, config, body, action
    ):
        if self.rotation_executor is None:
            raise web.HTTPConflict(
                text=(
                    "Endpoint rotation requires a configured credential executor; "
                    "no device or vault credential was changed"
                )
            )
        rid = str(UUID(body["rotation_id"]))
        rotation = self.state.get("rotations", rid)
        if action == "rotate":
            if rotation:
                raise web.HTTPConflict(text="Rotation already exists; resume it")
            if any(
                r["status"] not in {"completed", "failed"}
                for r in self.state.rotations(record["id"])
            ):
                raise web.HTTPConflict(
                    text="Resolve this credential's existing rotation first"
                )
            fields = validate_fields(record["kind"], body["fields"])
            current = await self.provider_call(provider, "metadata", record["path"])
            if (
                type(body.get("expected_version")) is not int
                or body["expected_version"] != current["current_version"]
            ):
                raise web.HTTPConflict(text="Secret version changed")
            rotation = {
                "id": rid,
                "secret_id": record["id"],
                "status": "preparing",
                "job_id": "",
                "created_at": datetime.now(UTC).isoformat(),
                "expected_version": current["current_version"],
                "stage_path": f"{config['prefix']}/rotations/{rid}",
            }
            if hasattr(self.rotation_executor, "prepare"):
                rotation["executor_binding"] = await self.rotation_executor.prepare(
                    record=record, fields=fields, principal=principal, request=request
                )
            self.state.save_rotation(rotation)
            await self.audit(principal, endpoint, "rotation_staging", rid)
            await self.provider_call(
                provider, "write", rotation["stage_path"], fields, cas=0
            )
            rotation["status"] = "staged"
            self.state.save_rotation(rotation)
        if not rotation or rotation["secret_id"] != record["id"]:
            raise web.HTTPNotFound()
        if rotation["status"] == "completed":
            return {"id": rid, "status": "completed", "version": rotation["version"]}
        fields = await self.provider_call(provider, "read", rotation["stage_path"])
        await self.authorize(request, endpoint, "rotate", fresh=True)
        if rotation["status"] in {"preparing", "staged"}:
            rotation["status"] = "dispatching"
            self.state.save_rotation(rotation)
            await self.audit(principal, endpoint, "rotation_dispatching", rid)
            try:
                result = await self.rotation_executor.apply(
                    record=record,
                    rotation_id=rid,
                    fields=fields,
                    principal=principal,
                    request=request,
                    rotation=rotation,
                )
            except Exception:
                rotation["status"] = "unknown"
                self.state.save_rotation(rotation)
                return {
                    "id": rid,
                    "status": "unknown",
                    "message": (
                        "Execution outcome needs reconciliation; "
                        "no retry was dispatched"
                    ),
                }
        else:
            try:
                result = await self.rotation_executor.check(
                    record=record,
                    rotation_id=rid,
                    job_id=rotation["job_id"],
                    principal=principal,
                    request=request,
                    rotation=rotation,
                    fields=fields,
                )
            except Exception:
                rotation["status"] = "unknown"
                self.state.save_rotation(rotation)
                return {
                    "id": rid,
                    "status": "unknown",
                    "message": "Rotation status unavailable; no retry was dispatched",
                }
        if not isinstance(result, dict) or result.get("status") not in {
            "pending",
            "verified",
            "failed",
            "unknown",
        }:
            raise web.HTTPBadGateway(text="Invalid rotation executor result")
        job_id = str(result.get("job_id", ""))
        if job_id:
            job_id = str(UUID(job_id))
        rotation.update(job_id=job_id, status=result["status"])
        self.state.save_rotation(rotation)
        if result["status"] == "verified":
            await self.authorize(request, endpoint, "rotate", fresh=True)
            metadata = await self.provider_call(provider, "metadata", record["path"])
            if metadata["current_version"] == rotation["expected_version"]:
                version = await self.provider_call(
                    provider,
                    "write",
                    record["path"],
                    fields,
                    cas=rotation["expected_version"],
                )
            elif (
                metadata["current_version"] == rotation["expected_version"] + 1
                and await self.provider_call(provider, "read", record["path"]) == fields
            ):
                version = metadata["current_version"]
            else:
                rotation["status"] = "commit_conflict"
                self.state.save_rotation(rotation)
                return {
                    "id": rid,
                    "status": "commit_conflict",
                    "message": (
                        "Device verified, but vault version changed; "
                        "preserve staged credentials and reconcile"
                    ),
                }
            rotation.update(status="completed", version=version)
            self.state.save_rotation(rotation)
            await self.audit(principal, endpoint, "rotation_completed", rid)
        return {k: rotation[k] for k in ("id", "status", "job_id")}

    async def resolve_remote(self, request, principal, target, method):
        configured = self.state.records(target.endpoint_id, target.identity_id)
        records = [
            r
            for r in configured
            if r["kind"] == method and r["use_for_remote"] and not r["retired"]
        ]
        if not records:
            if any(r["kind"] == method and r.get("managed_remote") for r in configured):
                raise web.HTTPConflict(
                    text="Choose an active OpenBao credential for this connection"
                )
            return {}
        if len(records) != 1:
            raise web.HTTPConflict(text="Remote credential binding is ambiguous")
        principal, config, _identity = await self.authorize(
            request, target.endpoint_id, "use"
        )
        record = records[0]
        await self.audit(
            principal, target.endpoint_id, "remote_use_requested", record["id"]
        )
        fields = await self.provider_call(self.provider(config), "read", record["path"])
        validate_fields(method, fields)
        await self.authorize(request, target.endpoint_id, "use")
        await self.audit(principal, target.endpoint_id, "remote_used", record["id"])
        return {**fields, "__rmm_secret_id": record["id"]}

    async def authorize_remote_use(
        self, request, endpoint, secret_id, *, principal=None
    ):
        if principal is None:
            _, _, identity = await self.authorize(request, endpoint, "use")
        else:
            _, identity = self.check_grant(principal, endpoint, "use")
        record = self.record(secret_id, endpoint, identity)
        if record["retired"] or not record["use_for_remote"]:
            raise web.HTTPForbidden(text="This remote credential binding was revoked")

    async def guard_legacy_reveal(self, target):
        if any(
            r["kind"] == "rdp" and (r.get("managed_remote") or r["use_for_remote"])
            for r in self.state.records(target.endpoint_id, target.identity_id)
        ):
            raise web.HTTPConflict(
                text=(
                    "This device uses an OpenBao credential. "
                    "Use the Secrets tab to request an authorized reveal."
                )
            )

    def provider(self, config):
        try:
            return self.provider_factory(config["provider"])
        except (ValidationError, OSError, ValueError, KeyError, TypeError):
            raise VaultError() from None

    async def recovery_context(self, request, endpoint, identity):
        if self.management is None:
            raise web.HTTPConflict(text="Recovery import is not configured")
        actual_endpoint, principal, current = await self.management.context(request)
        if (
            actual_endpoint != endpoint
            or current.identity_id != identity
            or "recovery_operator" not in principal.roles
            or not self.gateway.operation._policy.permits(
                principal.subject, endpoint, "recovery"
            )
        ):
            raise web.HTTPForbidden(
                text="Recovery access is outside your assigned permissions"
            )
        return principal

    async def import_recovery(
        self, request, endpoint, identity, principal, config, provider, body
    ):
        await self.recovery_context(request, endpoint, identity)
        await self.authorize(request, endpoint, "admin", fresh=True)
        job_id = str(UUID(body["job_id"]))
        label = self.label(body["label"])
        try:
            job = await asyncio.to_thread(self.management.store.job, job_id)
        except KeyError:
            raise web.HTTPNotFound() from None
        if (
            job["endpoint"] != str(endpoint)
            or job["identity"] != str(identity)
            or job["state"] != "completed"
            or job["action"] not in {"bitlocker.escrow", "recovery.rotate"}
        ):
            raise web.HTTPNotFound()
        identifier = str(
            uuid5(
                NAMESPACE_URL,
                f"northgate-rmm:recovery-import:{endpoint}:{identity}:{job_id}",
            )
        )
        existing = self.state.get("records", identifier)
        if existing:
            if (
                existing["endpoint_id"],
                existing["identity_id"],
                existing.get("source_job"),
            ) != (
                str(endpoint),
                str(identity),
                job_id,
            ):
                raise web.HTTPConflict(text="Recovery import identity conflict")
            try:
                metadata = await self.provider_call(
                    provider, "metadata", existing["path"]
                )
                if metadata["current_version"] > 0:
                    return {
                        "id": identifier,
                        "version": metadata["current_version"],
                        "message": "This recovery result already has a vault reference",
                    }
            except VaultError as error:
                if error.status != 404:
                    raise
        elif len(self.state.records(endpoint, identity)) >= 1000:
            raise web.HTTPConflict(text="Secret reference limit reached")
        await self.audit(principal, endpoint, "recovery_import_requested", job_id)
        private = await asyncio.to_thread(
            self.management.store.job, job_id, private=True
        )
        receipt = private.get("receipt", {})
        if (
            receipt.get("state") != "completed"
            or receipt.get("exit_code") != 0
            or receipt.get("truncated") is not False
        ):
            raise web.HTTPConflict(text="Recovery worker result is incomplete")
        output = receipt.get("output", "")
        if not isinstance(output, str) or len(output.encode()) > 32768:
            raise web.HTTPConflict(text="Recovery worker result is oversized")
        value = json.loads(output)
        extra = {}
        if job["action"] == "recovery.rotate":
            if (
                not isinstance(value, dict)
                or value.get("username") != "ng-rmm-recovery"
            ):
                raise ValueError()
            expiry = datetime.fromisoformat(value["expires"].replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError()
            kind = "rdp"
            fields = validate_fields(
                kind, {"username": value["username"], "password": value["password"]}
            )
            extra["expires_at"] = expiry.isoformat()
        else:
            # Preserve only the worker's typed BitLocker recovery collection.
            if not isinstance(value, dict) or not isinstance(
                value.get("volumes"), list
            ):
                raise ValueError()
            volumes = []
            for volume in value["volumes"]:
                if not isinstance(volume, dict) or not isinstance(
                    volume.get("recovery_passwords"), list
                ):
                    raise ValueError()
                passwords = []
                for entry in volume["recovery_passwords"]:
                    if not isinstance(entry, dict):
                        raise ValueError()
                    password = entry.get("recovery_password")
                    if not isinstance(password, str) or not re.fullmatch(
                        r"[0-9]{6}(?:-[0-9]{6}){7}", password
                    ):
                        raise ValueError()
                    protector = entry["protector_id"]
                    if not isinstance(protector, str):
                        raise ValueError()
                    passwords.append(
                        {
                            "protector_id": str(UUID(protector.strip("{}"))),
                            "recovery_password": password,
                        }
                    )
                if passwords:
                    mount = volume.get("mount_point")
                    if not isinstance(mount, str) or len(mount) > 256:
                        raise ValueError()
                    volumes.append(
                        {"mount_point": mount, "recovery_passwords": passwords}
                    )
            if not volumes:
                raise web.HTTPConflict(
                    text="This escrow result contains no recovery passwords"
                )
            kind = "recovery"
            fields = validate_fields(kind, {"key": json.dumps({"volumes": volumes})})
        await self.recovery_context(request, endpoint, identity)
        await self.authorize(request, endpoint, "admin", fresh=True)
        record = existing or {
            "id": identifier,
            "endpoint_id": str(endpoint),
            "identity_id": str(identity),
            "label": label,
            "kind": kind,
            "retired": False,
            "use_for_remote": False,
            "source_job": job_id,
            "source_action": job["action"],
            **extra,
            "path": f"{config['prefix']}/endpoints/{endpoint}/{identity}/{identifier}",
        }
        self.state.save_record(record)
        await self.provider_call(
            provider, "configure_metadata", record["path"], record["label"], kind
        )
        version = await self.provider_call(
            provider, "write", record["path"], fields, cas=0
        )
        await self.audit(principal, endpoint, "recovery_imported", job_id)
        return {
            "id": identifier,
            "version": version,
            "message": (
                "Completed recovery result imported into OpenBao; "
                "device access was not changed"
            ),
        }

    async def ui(self, request):
        await self.authorize(request, self.endpoint(request), "metadata")
        return web.Response(
            text=Path(__file__)
            .with_name("secrets_ui.html")
            .read_text(encoding="utf-8"),
            content_type="text/html",
            headers={
                **HEADERS,
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": (
                    "default-src 'none'; script-src 'self'; "
                    "style-src 'self'; connect-src 'self'; frame-ancestors 'self'; "
                    "base-uri 'none'; form-action 'self'"
                ),
            },
        )

    async def asset(self, request):
        await self.authorize(request, self.endpoint(request), "metadata")
        kind = request.match_info["asset"]
        if kind not in {"js", "css"}:
            raise web.HTTPNotFound()
        return web.Response(
            text=Path(__file__)
            .with_name("secrets_ui." + kind)
            .read_text(encoding="utf-8"),
            content_type="application/javascript" if kind == "js" else "text/css",
            headers=HEADERS,
        )

    def register(self, app):
        app.router.add_get("/remote/{endpoint}/secrets/ui", self.ui)
        app.router.add_get("/remote/{endpoint}/secrets/assets.{asset}", self.asset)
        app.router.add_get("/remote/{endpoint}/secrets/state", self.get_state)
        app.router.add_post("/remote/{endpoint}/secrets/action", self.action)
