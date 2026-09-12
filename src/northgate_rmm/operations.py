"""Authenticated cases, infrastructure, evidence and normalized Wazuh intake."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from aiohttp import web

from northgate_rmm.domain import Endpoint, EndpointIdentity, EndpointLifecycle
from northgate_rmm.errors import NotFoundError
from northgate_rmm.management_protocol import SECRET_ACTIONS, TERMINAL
from northgate_rmm.operations_models import (
    KINDS,
    MAX_CHUNK,
    STATES,
    TRANSITIONS,
    bounded_json,
    check_secrets,
    identifier,
    stamp,
    text,
    validate,
)
from northgate_rmm.operations_store import Conflict

BASE = "/remote/ops"
MEDIA_TYPES = {
    "application/json",
    "text/plain",
    "text/csv",
    "application/x-ndjson",
    "application/zip",
    "application/vnd.tcpdump.pcap",
    "application/octet-stream",
}


@dataclass(frozen=True)
class IntegrationActor:
    subject: str
    session_id: str
    entry: dict[str, Any]


class RetriableIntake(Conflict):
    """A safe-to-retry intake failure already recorded for operators."""

    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category


class Operations:
    def __init__(
        self,
        management: Any,
        fleet: Any,
        store: Any,
        inspection: Any = None,
        capture: Any = None,
        wazuh_registry: Any = None,
    ) -> None:
        self.m, self.fleet, self.store = management, fleet, store
        self.inspection, self.capture = inspection, capture
        self.gateway = management.gateway
        self.wazuh_registry = Path(wazuh_registry) if wazuh_registry else None
        self.slots = asyncio.Semaphore(4)
        store.verify()

    def register(self, app: web.Application) -> None:
        app.router.add_get(BASE + "/api/state", self.state)
        app.router.add_get(BASE + "/api/record/{kind}/{id}", self.record)
        app.router.add_get(BASE + "/api/upload/{id}", self.upload_status)
        app.router.add_get(
            BASE + "/api/evidence/{id}/chunks/{index}", self.download_chunk
        )
        app.router.add_post(BASE + "/api/{operation}", self.mutate)
        app.router.add_post(BASE + "/intake/wazuh", self.wazuh)
        app.cleanup_ctx.append(self.maintenance)

    async def maintenance(self, app: web.Application) -> Any:
        stop = asyncio.Event()

        async def run() -> None:
            while not stop.is_set():
                try:
                    await asyncio.to_thread(self.store.cleanup_partials)
                except Exception:
                    logging.getLogger(__name__).error("Partial upload cleanup failed")
                try:
                    await asyncio.wait_for(stop.wait(), timeout=900)
                except TimeoutError:
                    continue

        task = asyncio.create_task(run())
        try:
            yield
        finally:
            stop.set()
            await task

    def csrf(self, p: Any) -> str:
        return hmac.digest(
            self.gateway.key,
            ("operations-form-v1/" + p.subject + "/" + p.session_id).encode(),
            "sha256",
        ).hex()

    @staticmethod
    def headers() -> dict[str, str]:
        return {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        }

    def permission(self, p: Any, endpoints: Any, permission: str) -> bool:
        if isinstance(p, IntegrationActor):
            native = self.m.integration
            if native is None:
                return False
            try:
                entry = native.auth.current(p.entry)
                if permission not in entry["actions"] or not endpoints:
                    return False
                for endpoint in endpoints:
                    _, target = native.endpoint(entry, endpoint, permission=permission)
                    if str(target.identity_id) != entry["endpoints"].get(endpoint):
                        return False
                return True
            except (ValueError, KeyError, web.HTTPException):
                return False
        policy = self.gateway.operation._policy
        if not endpoints:
            return bool(self.fleet.admin(p))
        return all(
            policy.permits(p.subject, endpoint, permission) for endpoint in endpoints
        )

    def require(self, p: Any, value: Any, permission: str = "ops.view") -> None:
        endpoints = value.get("endpoints", [])
        if not self.permission(p, endpoints, permission) or (
            permission != "ops.view" and not self.permission(p, endpoints, "ops.view")
        ):
            raise web.HTTPForbidden(
                text="Record is outside your operations permissions"
            )

    def active_enrollment(self, endpoint: str, identity: str) -> bool:
        """Resolve lifecycle from the identity, preserving both enrollment bindings."""
        devices = self.gateway.operation._store
        endpoint_id, identity_id = UUID(endpoint), UUID(identity)
        try:
            current: Endpoint = devices.get_endpoint(endpoint_id)
            enrolled: EndpointIdentity = devices.get_identity(current.identity_id)
        except NotFoundError:
            return False
        return bool(
            current.endpoint_id == endpoint_id
            and current.identity_id == identity_id
            and enrolled.identity_id == identity_id
            and enrolled.endpoint_id == endpoint_id
            and enrolled.lifecycle is EndpointLifecycle.ACTIVE
        )

    def authorized_record(
        self, p: Any, kind: str, key: Any, permission: str = "ops.view", db: Any = None
    ) -> Any:
        value = self.store.get(kind, key, db)
        self.require(p, value["value"], permission)
        # Linked scope may grow after this record was created. Always resolve the
        # current references before revealing a case or document containing them.
        expanded = self.expand_scope(p, kind, value["value"], db, permission)
        self.require(p, expanded, permission)
        # Consumers perform action-specific checks and retain historical scope.
        # Return the same expanded scope we authorized, not the stale snapshot.
        # expand_scope changes only the validated endpoints field.
        return {**value, "value": expanded}

    def expand_scope(
        self,
        p: Any,
        kind: str,
        value: Any,
        db: Any = None,
        permission: str = "ops.view",
        recursive: bool = True,
        visited: Any = None,
    ) -> Any:
        visited = set() if visited is None else visited
        endpoints = set(value.get("endpoints", []))
        references = [
            (name[:-1], key)
            for name in ("assets", "services", "networks")
            for key in value.get(name, [])
        ]
        if kind == "relationship":
            references += [
                (value[name]["kind"], value[name]["id"])
                for name in ("source", "target")
            ]
        if value.get("case_id"):
            references.append(("case", value["case_id"]))
        for target_kind, key in references:
            marker = (target_kind, key)
            if marker in visited:
                continue
            if len(visited) >= 128:
                raise ValueError(
                    "Related-record graph exceeds the bounded lookup limit"
                )
            visited.add(marker)
            record = self.store.get(target_kind, key, db)
            self.require(p, record["value"], "ops.view")
            endpoints.update(record["value"].get("endpoints", []))
            expanded = self.expand_scope(
                p, target_kind, record["value"], db, "ops.view", True, visited
            )
            endpoints.update(expanded["endpoints"])
        result = {**value, "endpoints": sorted(endpoints)}
        self.require(p, result, permission)
        return result

    def assignee(self, p: Any, value: Any, subject: str) -> None:
        if not subject:
            return
        policy = self.gateway.operation._policy
        if not policy.admits(subject) or not all(
            policy.permits(subject, e, "case.manage")
            and policy.permits(subject, e, "ops.view")
            for e in value["endpoints"]
        ):
            raise ValueError("Assignee must have access to every case device")
        if not value["endpoints"] and subject != policy.subject:
            raise ValueError("Unscoped cases require an owner assignee")

    async def authenticated(self, request: web.Request, write: bool = False) -> Any:
        p = await self.fleet.principal(request)
        if write and (not p.mfa or "remote_operator" not in p.roles):
            raise web.HTTPForbidden(
                text="An authenticated MFA operator session is required"
            )
        return p

    async def state(self, request: web.Request) -> Any:
        p = await self.authenticated(request)
        result = await asyncio.to_thread(self.snapshot, p)
        result["csrf"] = self.csrf(p)
        return web.json_response(result, headers=self.headers())

    def snapshot(self, p: Any) -> Any:
        result: dict[str, Any] = {}
        plural = {
            "case": "cases",
            "asset": "assets",
            "service": "services",
            "network": "networks",
            "relationship": "relationships",
            "document": "documents",
            "change": "changes",
            "exercise": "exercises",
            "alert": "alerts",
        }
        for kind, label in plural.items():
            rows = []
            for record in self.store.records(kind):
                try:
                    record = self.authorized_record(p, kind, record["id"])
                except (web.HTTPForbidden, KeyError):
                    continue
                rows.append(record)
            result[label] = rows
        cases = result["cases"]
        now = time.time()

        def due(record: Any, field: Any) -> Any:
            return (
                bool(record["value"].get(field))
                and datetime.fromisoformat(record["value"][field]).timestamp() < now
            )

        active = [
            r for r in cases if r["value"]["status"] not in {"resolved", "closed"}
        ]
        workload: dict[str, int] = {}
        for r in active:
            owner = r["value"].get("assignee") or "unassigned"
            workload[owner] = workload.get(owner, 0) + 1
        result["metrics"] = {
            "open": len(active),
            "unassigned": workload.get("unassigned", 0),
            "overdue_response": sum(
                due(r, "response_due") and not r["value"].get("responded_at")
                for r in active
            ),
            "overdue_resolution": sum(due(r, "resolve_due") for r in active),
            "by_assignee": workload,
            "by_status": {
                s: sum(r["value"]["status"] == s for r in cases) for s in sorted(STATES)
            },
            "oldest_open_seconds": max((now - r["created"] for r in active), default=0),
            "verified_closed": sum(
                r["value"]["status"] == "closed"
                and bool(r["value"].get("verification"))
                for r in cases
            ),
        }
        scopes = sorted(
            {e for r in result["assets"] + cases for e in r["value"]["endpoints"]}
        )
        scopes = sorted(
            set(scopes)
            | {str(e) for e in getattr(self.gateway, "targets", {})}
            | {
                str(e)
                for grant in getattr(self.gateway.operation._policy, "grants", ())
                if grant.subject == p.subject
                for e in grant.endpoints
                if e != "*"
            }
        )
        if isinstance(p, IntegrationActor):
            scopes = sorted(set(scopes) | set(p.entry["endpoints"]))
        result["capabilities"] = {
            name: self.permission(p, [], name)
            or any(
                self.permission(p, [endpoint], name)
                and self.permission(p, [endpoint], "ops.view")
                for endpoint in scopes
            )
            for name in (
                "ops.view",
                "case.manage",
                "infrastructure.manage",
                "evidence.manage",
            )
        }
        result["endpoint_capabilities"] = {
            endpoint: [
                name
                for name in (
                    "ops.view",
                    "case.manage",
                    "infrastructure.manage",
                    "evidence.manage",
                )
                if self.permission(p, [endpoint], name)
            ]
            for endpoint in scopes
            if self.permission(p, [endpoint], "ops.view")
        }
        result["capabilities"].update(
            wazuh_intake_configured=self.wazuh_registry is not None,
            upload_chunk_bytes=MAX_CHUNK,
            retained_evidence=True,
        )
        result["limits"] = {
            "records_per_kind": 2000,
            "record_history_page": 200,
            "versions_returned": 100,
        }
        return result

    async def record(self, request: web.Request) -> Any:
        p = await self.authenticated(request)
        kind = request.match_info["kind"]
        if kind not in KINDS:
            raise web.HTTPNotFound()
        try:
            key = identifier(request.match_info["id"])
            result = await asyncio.to_thread(
                self.record_detail, p, kind, key, request.query.get("before")
            )
        except KeyError:
            raise web.HTTPNotFound() from None
        except ValueError:
            raise web.HTTPBadRequest(
                text="Invalid record identifier or cursor"
            ) from None
        return web.json_response(result, headers=self.headers())

    def record_detail(self, p: Any, kind: str, key: Any, before: Any = None) -> Any:
        record = self.authorized_record(p, kind, key)
        history = self.store.history(kind, key, before)
        versions = self.store.versions(kind, key)
        # Previous versions may reference a device removed from today's scope.
        versions = [
            v
            for v in versions
            if self.permission(p, v["value"].get("endpoints", []), "ops.view")
        ]
        enrollments = []
        if kind == "asset":
            with self.store.connection() as db:
                enrollments = [
                    dict(r)
                    for r in db.execute(
                        "SELECT endpoint,identity,created,subject,reason "
                        "FROM ops_enrollments WHERE asset=? ORDER BY created DESC",
                        (key,),
                    ).fetchall()
                ]
        return {
            "record": record,
            "timeline": history,
            "versions": versions,
            "evidence": self.store.artifacts(key) if kind == "case" else [],
            "enrollments": enrollments,
            "next_before": history[-1]["created"] if len(history) == 200 else None,
        }

    async def body(self, request: web.Request) -> Any:
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        raw = bytearray()
        async with asyncio.timeout(20):
            async for part in request.content.iter_chunked(65536):
                raw.extend(part)
                if len(raw) > 2 * MAX_CHUNK:
                    raise web.HTTPRequestEntityTooLarge(
                        max_size=2 * MAX_CHUNK, actual_size=len(raw)
                    )
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("Expected a JSON object")
        return result

    async def mutate(self, request: web.Request) -> Any:
        p = await self.authenticated(request, True)
        try:
            value = await self.body(request)
            token = request.headers.get("X-CSRF-Token", value.pop("csrf", ""))
            if (
                request.headers.get("Origin") != self.gateway.origin
                or not isinstance(token, str)
                or not hmac.compare_digest(token, self.csrf(p))
            ):
                raise web.HTTPForbidden(text="Refresh the workspace before submitting")
            operation = request.match_info["operation"]
            async with self.slots:
                result = await asyncio.to_thread(self.dispatch, p, operation, value)
            return web.json_response(result, headers=self.headers())
        except Conflict as error:
            raise web.HTTPConflict(text=str(error)) from None
        except KeyError:
            raise web.HTTPNotFound(text="Record not found") from None
        except (ValueError, TypeError) as error:
            raise web.HTTPBadRequest(text=str(error)) from None

    def dispatch(self, p: Any, operation: str, args: Any) -> Any:
        value = dict(args)
        request_id = identifier(value.pop("request_id", None))
        # Resolve authorization before replaying an idempotent response: revoked
        # grants must not retrieve a response accepted under previous access.
        self.preflight(p, operation, value)

        def apply_authorized(db: Any) -> Any:
            self.preflight(p, operation, value, db)
            return self.apply(db, p, operation, value)

        return self.store.transaction(
            p.subject,
            request_id,
            {"operation": operation, "arguments": value},
            apply_authorized,
        )

    def preflight(self, p: Any, operation: str, v: Any, db: Any = None) -> Any:
        if operation == "save":
            kind = v["kind"]
            record = validate(kind, v["value"])
            permission = "case.manage" if kind == "case" else "infrastructure.manage"
            self.expand_scope(p, kind, record, db=db, permission=permission)
            if v.get("id"):
                try:
                    self.authorized_record(p, kind, identifier(v["id"]), permission, db)
                except KeyError:
                    if v.get("revision", 0) != 0:
                        raise
        elif operation in {"case_transition", "case_task", "link_alert"}:
            self.authorized_record(p, "case", identifier(v["id"]), "case.manage", db)
            if operation == "link_alert":
                self.authorized_record(
                    p, "alert", identifier(v["alert"]), "ops.view", db
                )
        elif operation == "note":
            kind = v["kind"]
            self.authorized_record(
                p,
                kind,
                identifier(v["id"]),
                "case.manage" if kind == "case" else "infrastructure.manage",
                db,
            )
        elif operation == "reconcile":
            self.authorized_record(
                p, "asset", identifier(v["asset"]), "infrastructure.manage", db
            )
            self.require(
                p, {"endpoints": [identifier(v["endpoint"])]}, "infrastructure.manage"
            )
        elif operation in {"upload_begin", "pin_job"}:
            case = self.authorized_record(
                p, "case", identifier(v["case"]), "case.manage", db
            )
            self.require(p, case["value"], "evidence.manage")
        elif operation in {"upload_chunk", "upload_finish", "upload_cancel"}:
            item = self.store.artifact(identifier(v["upload"]), db)
            case = self.authorized_record(p, "case", item["case_id"], "case.manage", db)
            self.require(p, case["value"], "evidence.manage")
            if item["subject"] != p.subject:
                raise web.HTTPForbidden(
                    text="Only the initiating collector may resume this upload"
                )
        else:
            raise ValueError("Unsupported operations action")

    def apply(self, db: Any, p: Any, operation: str, v: Any) -> Any:
        # Recheck scope inside the serialized mutation transaction to close races
        # with infrastructure reconciliation and case edits.
        if operation == "save":
            kind, key = v["kind"], identifier(v["id"]) if v.get("id") else str(uuid4())
            permission = "case.manage" if kind == "case" else "infrastructure.manage"
            value = self.expand_scope(
                p, kind, validate(kind, v["value"]), db, permission
            )
            if kind == "case":
                if v.get("revision", 0):
                    old = self.authorized_record(p, kind, key, permission, db)["value"]
                    for name in (
                        "status",
                        "tasks",
                        "outcome",
                        "verification",
                        "responded_at",
                        "resolved_at",
                        "closed_at",
                        "alerts",
                        "automation",
                    ):
                        if name in old:
                            value[name] = old[name]
                    # Historical case scope cannot be removed to reveal its old
                    # timeline/evidence to a narrower user.
                    value["endpoints"] = sorted(
                        set(value["endpoints"]) | set(old["endpoints"])
                    )
                    self.require(p, value, permission)
                else:
                    value.update(status="new", tasks=[], alerts=[])
                self.assignee(p, value, value.get("assignee", ""))
            elif v.get("revision", 0):
                old = self.authorized_record(p, kind, key, permission, db)["value"]
                value["endpoints"] = sorted(
                    set(value["endpoints"]) | set(old["endpoints"])
                )
            return {
                "record": self.store.put(
                    db, kind, key, value, p.subject, v.get("revision", 0)
                )
            }
        if operation == "note":
            kind, key = v["kind"], identifier(v["id"])
            self.authorized_record(
                p,
                kind,
                key,
                "case.manage" if kind == "case" else "infrastructure.manage",
                db,
            )
            return {
                "event": self.store.event(
                    db,
                    kind,
                    key,
                    p.subject,
                    "note.added",
                    {"text": text(v["text"], 16384)},
                )
            }
        if operation in {"case_transition", "case_task", "link_alert"}:
            key = identifier(v["id"])
            record = self.authorized_record(p, "case", key, "case.manage", db)
            value = record["value"]
            if operation == "case_transition":
                status = v["status"]
                if status not in TRANSITIONS[value["status"]]:
                    raise ValueError("That case status transition is not allowed")
                if status in {"resolved", "closed"}:
                    value["outcome"] = text(
                        v.get("outcome", value.get("outcome", "")), 8192
                    )
                    value["verification"] = text(
                        v.get("verification", value.get("verification", "")), 8192
                    )
                    if any(
                        t["status"] not in {"done", "cancelled"}
                        for t in value.get("tasks", [])
                    ):
                        raise ValueError(
                            "Complete or cancel outstanding tasks before resolution"
                        )
                    if db.execute(
                        "SELECT id FROM ops_artifacts WHERE case_id=? "
                        "AND state='uploading' LIMIT 1",
                        (key,),
                    ).fetchone():
                        raise ValueError("Finish or cancel incomplete evidence uploads")
                    value["resolved_at" if status == "resolved" else "closed_at"] = (
                        time.time()
                    )
                if status != "new" and not value.get("responded_at"):
                    value["responded_at"] = time.time()
                value["status"] = status
            elif operation == "case_task":
                if value["status"] in {"closed", "resolved"}:
                    raise ValueError("Reopen the case before changing tasks")
                task = v["task"]
                task_id = identifier(task["id"]) if task.get("id") else str(uuid4())
                status = task.get("status", "todo")
                if status not in {"todo", "in_progress", "done", "cancelled"}:
                    raise ValueError("Invalid task status")
                item = {
                    "id": task_id,
                    "title": text(task["title"], 1024),
                    "assignee": text(task.get("assignee", ""), 256, True),
                    "status": status,
                    "verification": text(
                        task.get("verification", ""), 4096, status != "done"
                    ),
                }
                self.assignee(p, value, item["assignee"])
                tasks = [t for t in value.get("tasks", []) if t["id"] != task_id]
                if len(tasks) >= 100:
                    raise ValueError("Case task limit reached")
                value["tasks"] = [*tasks, item]
            else:
                alert = self.authorized_record(
                    p, "alert", identifier(v["alert"]), "ops.view", db
                )
                value["endpoints"] = sorted(
                    set(value["endpoints"]) | set(alert["value"]["endpoints"])
                )
                self.require(p, value, "case.manage")
                value["alerts"] = sorted(set(value.get("alerts", [])) | {alert["id"]})
            return {
                "record": self.store.put(
                    db, "case", key, value, p.subject, v["revision"], operation
                )
            }
        if operation == "reconcile":
            asset, endpoint, identity = (
                identifier(v["asset"]),
                identifier(v["endpoint"]),
                identifier(v["identity"]),
            )
            record = self.authorized_record(
                p, "asset", asset, "infrastructure.manage", db
            )
            self.require(p, {"endpoints": [endpoint]}, "infrastructure.manage")
            if not self.active_enrollment(endpoint, identity):
                raise Conflict("Enrollment is no longer current and active")
            reason = text(v["reason"], 2048)
            old = db.execute(
                "SELECT asset FROM ops_enrollments WHERE endpoint=? AND identity=?",
                (endpoint, identity),
            ).fetchone()
            if old and old["asset"] != asset:
                raise Conflict("Enrollment is already attached to another stable asset")
            if old is None:
                db.execute(
                    "INSERT INTO ops_enrollments VALUES(?,?,?,?,?,?)",
                    (endpoint, identity, asset, time.time(), p.subject, reason),
                )
            value = record["value"]
            value["endpoints"] = sorted(set(value["endpoints"]) | {endpoint})
            result = self.store.put(
                db,
                "asset",
                asset,
                value,
                p.subject,
                record["revision"],
                "enrollment.reconciled",
            )
            self.store.event(
                db,
                "asset",
                asset,
                p.subject,
                "enrollment.evidence",
                {"endpoint": endpoint, "identity": identity, "reason": reason},
            )
            return {"record": result, "endpoint": endpoint, "identity": identity}
        if operation == "upload_begin":
            return {"upload": self.start_upload(db, p, v)}
        if operation == "upload_chunk":
            index = v["index"]
            if type(index) is not int or not 0 <= index < 128:
                raise ValueError("Invalid chunk index")
            data = base64.b64decode(v["data"], validate=True)
            return {
                "upload": self.store.write_chunk(
                    db, identifier(v["upload"]), index, data, self.digest(v["sha256"])
                )
            }
        if operation == "upload_finish":
            return {
                "upload": self.store.finish_artifact(
                    db, identifier(v["upload"]), p.subject
                )
            }
        if operation == "upload_cancel":
            return {
                "upload": self.store.cancel_artifact(
                    db, identifier(v["upload"]), p.subject
                )
            }
        if operation == "pin_job":
            return {
                "evidence": self.pin_job(
                    db, p, identifier(v["case"]), identifier(v["job"])
                )
            }
        raise ValueError("Unsupported operation")

    @staticmethod
    def digest(value: Any) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("A lowercase SHA-256 digest is required")
        return value

    def start_upload(self, db: Any, p: Any, v: Any, provenance: Any = None) -> Any:
        case = self.authorized_record(
            p, "case", identifier(v["case"]), "case.manage", db
        )
        self.require(p, case["value"], "evidence.manage")
        if case["value"]["status"] == "closed":
            raise ValueError("Reopen the case before adding evidence")
        if v.get("redacted") is not True:
            raise ValueError(
                "Confirm evidence excludes passwords, private keys and recovery secrets"
            )
        name = text(v["name"], 120)
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._ -]{0,119}", name
        ) or name.endswith((".", " ")):
            raise ValueError("Use a simple filename without directories")
        media = v.get("media_type", "application/octet-stream")
        if media not in MEDIA_TYPES:
            raise ValueError("Unsupported evidence media type")
        metadata = {
            "collector": p.subject,
            "ingested_at": datetime.now(UTC).isoformat(),
            "redaction_asserted": True,
            "source": "operator-upload",
            **(provenance or {}),
        }
        if v.get("provenance"):
            supplied = v["provenance"]
            allowed = {
                "endpoint_id",
                "identity_id",
                "source_job",
                "collector_version",
                "collected_at",
                "tool_id",
                "tool_version",
            }
            if not isinstance(supplied, dict) or set(supplied) - allowed:
                raise ValueError("Unsupported evidence provenance")
            metadata.update({k: text(val, 256) for k, val in supplied.items()})
            if metadata.get("endpoint_id") not in case["value"]["endpoints"]:
                raise web.HTTPForbidden(
                    text="Evidence source device is outside the case"
                )
            metadata["source_claim"] = (
                "collector-supplied; verify against signed receipt"
            )
        return self.store.begin_artifact(
            db,
            case["id"],
            p.subject,
            {
                "name": name,
                "size": v["size"],
                "sha256": self.digest(v["sha256"]),
                "media_type": media,
            },
            metadata,
        )

    def pin_job(self, db: Any, actor: Any, case_id: str, job_id: str) -> Any:
        """Internal custody helper; requires a verified actor and caller transaction."""
        case = self.authorized_record(actor, "case", case_id, "case.manage", db)
        self.require(actor, case["value"], "evidence.manage")
        job = self.m.store.job(job_id)
        if (
            job["endpoint"] not in case["value"]["endpoints"]
            or job["action"] in SECRET_ACTIONS
            or job["action"] in {"files.read", "shell.start"}
        ):
            raise web.HTTPForbidden(
                text="This job cannot be retained as ordinary case evidence"
            )
        if job["state"] not in TERMINAL or not job.get("receipt"):
            raise ValueError("Wait for the final job receipt")
        payload = {
            k: job[k]
            for k in (
                "id",
                "endpoint",
                "identity",
                "action",
                "state",
                "created",
                "receipt",
            )
        }
        check_secrets(payload)
        data = bounded_json(payload, 2 * MAX_CHUNK).encode()
        item = self.start_upload(
            db,
            actor,
            {
                "case": case_id,
                "name": "job-" + job_id + ".json",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "media_type": "application/json",
                "redacted": True,
            },
            {
                "source": "authenticated-management-receipt",
                "endpoint_id": job["endpoint"],
                "identity_id": job["identity"],
                "source_job": job_id,
            },
        )
        for index in range((len(data) + MAX_CHUNK - 1) // MAX_CHUNK):
            part = data[index * MAX_CHUNK : (index + 1) * MAX_CHUNK]
            self.store.write_chunk(
                db, item["id"], index, part, hashlib.sha256(part).hexdigest()
            )
        return self.store.finish_artifact(db, item["id"], actor.subject)

    async def upload_status(self, request: web.Request) -> Any:
        p = await self.authenticated(request)
        try:
            item = await asyncio.to_thread(
                self.store.artifact, identifier(request.match_info["id"])
            )
            self.authorized_record(p, "case", item["case_id"])
        except KeyError:
            raise web.HTTPNotFound() from None
        except ValueError:
            raise web.HTTPBadRequest(text="Invalid upload identifier") from None
        return web.json_response({"upload": item}, headers=self.headers())

    async def download_chunk(self, request: web.Request) -> Any:
        p = await self.authenticated(request)
        try:
            key, index = (
                identifier(request.match_info["id"]),
                int(request.match_info["index"]),
            )
            item = self.store.artifact(key)
            case = self.authorized_record(p, "case", item["case_id"])
            self.require(p, case["value"], "evidence.manage")
            if item["state"] != "complete":
                raise web.HTTPNotFound()
            chunk = next((r for r in item["chunks"] if r["chunk_index"] == index), None)
            if chunk is None:
                raise web.HTTPNotFound()
            data = await asyncio.to_thread(self.store.read_chunk, key, index)
            if hashlib.sha256(data).hexdigest() != chunk["sha256"]:
                raise ValueError("Evidence integrity verification failed")
            with self.store.connection(write=True) as db:
                self.store.event(
                    db,
                    "case",
                    item["case_id"],
                    p.subject,
                    "evidence.chunk.read",
                    {"artifact": key, "index": index},
                )
            return web.json_response(
                {
                    "index": index,
                    "size": len(data),
                    "sha256": chunk["sha256"],
                    "data": base64.b64encode(data).decode(),
                },
                headers=self.headers(),
            )
        except (KeyError, ValueError):
            raise web.HTTPNotFound() from None

    async def native_call(self, entry: Any, operation: str, args: Any) -> Any:
        """Called only after NativeAPI authenticates its real service identity."""
        p = IntegrationActor("integration:" + entry["id"], "operations-native", entry)
        if operation not in {"state", "record"} and entry.get("read_only") is True:
            raise web.HTTPForbidden(
                text="Integration is configured for read-only access"
            )
        async with self.slots:
            if operation == "state":
                return await asyncio.to_thread(self.snapshot, p)
            if operation == "record":
                return await asyncio.to_thread(
                    self.record_detail,
                    p,
                    args["kind"],
                    identifier(args["id"]),
                    args.get("before"),
                )
            return await asyncio.to_thread(self.dispatch, p, operation, args)

    async def wazuh(self, request: web.Request) -> Any:
        if (
            not self.wazuh_registry
            or request.headers.get("Origin")
            or request.remote not in {"127.0.0.1", "::1"}
        ):
            raise web.HTTPForbidden()
        from northgate_rmm.secure_files import regular_file_reference

        try:
            with regular_file_reference(
                self.wazuh_registry,
                label="Wazuh intake identities",
                maximum_bytes=65536,
                private=True,
            ) as held:
                config = json.loads(held.read_text())
            authorization = request.headers.get("Authorization", "")
            if not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43,128}", authorization):
                raise ValueError("Invalid intake identity")
            digest = hashlib.sha256(authorization[7:].encode()).hexdigest()
            source = next(
                (
                    s
                    for s in config["sources"]
                    if s.get("enabled") is True
                    and hmac.compare_digest(s["token_sha256"], digest)
                ),
                None,
            )
            if source is None:
                raise ValueError("Unknown intake identity")
        except (ValueError, KeyError, OSError, TypeError):
            raise web.HTTPUnauthorized() from None
        try:
            payload = await self.body(request)
            async with self.slots:
                result = await asyncio.to_thread(self.ingest_wazuh, source, payload)
            return web.json_response(result, headers=self.headers(), status=202)
        except RetriableIntake as error:
            self.intake_failure(
                text(source["id"], 64),
                text(str(payload.get("id", "unknown")), 256),
                error.category,
                str(error),
            )
            raise web.HTTPServiceUnavailable(
                text=str(error), headers={"Retry-After": "30"}
            ) from None
        except Conflict as error:
            raise web.HTTPConflict(text=str(error)) from None
        except (ValueError, KeyError, TypeError) as error:
            raise web.HTTPBadRequest(text=str(error)) from None

    def intake_failure(
        self, source: str, external: str, category: str, message: str
    ) -> None:
        """Publish bounded owner-visible intake health without raw source data."""
        key = str(uuid5(NAMESPACE_URL, f"northgate/wazuh-failure/{source}/{external}"))
        value = {
            "name": "Security alert intake failure",
            "source": source,
            "external_id": external,
            "intake_status": "failed",
            "failure_category": category,
            "failure_message": text(message, 512),
            "observed_at": datetime.now(UTC).isoformat(),
            "endpoints": [],
            "assets": [],
            "services": [],
            "networks": [],
        }
        with self.store.lock, self.store.connection(write=True) as db:
            try:
                old = self.store.get("alert", key, db)
                revision = old["revision"]
            except KeyError:
                revision = 0
            self.store.put(
                db, "alert", key, value, "intake:" + source, revision,
                "alert.intake_failed",
            )

    @staticmethod
    def detection(source: Any, rule_id: str) -> dict[str, Any]:
        item = source.get("detections", {}).get(rule_id)
        if not isinstance(item, dict):
            if "detections" not in source:
                return {
                    "id": "WAZUH-" + rule_id,
                    "version": "0.0.0",
                    "severity": "normal",
                    "attack": [],
                    "checklist": [],
                    "context_fields": [],
                }
            raise ValueError("Wazuh rule is not an approved detection")
        detection_id = text(item["id"], 64)
        version = text(item["version"], 32)
        if not re.fullmatch(r"[A-Z0-9_-]{3,64}", detection_id) or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+", version
        ):
            raise ValueError("Invalid detection identity")
        attack = item.get("attack", [])
        checklist = item.get("checklist", [])
        fields = item.get("context_fields", [])
        if (
            not isinstance(attack, list)
            or not isinstance(checklist, list)
            or not isinstance(fields, list)
            or len(attack) > 16
            or len(checklist) > 32
            or len(fields) > 32
        ):
            raise ValueError("Invalid detection metadata")
        return {
            "id": detection_id,
            "version": version,
            "severity": text(item.get("severity", "normal"), 16),
            "attack": [text(v, 32) for v in attack],
            "checklist": [text(v, 1024) for v in checklist],
            "context_fields": [text(v, 128) for v in fields],
        }

    @staticmethod
    def case_policy(source: Any, rule_id: str, level: int) -> dict[str, Any] | None:
        policies = source.get("case_policies", [])
        if not isinstance(policies, list) or len(policies) > 100:
            raise ValueError("Invalid case policy collection")
        matches = [
            p for p in policies
            if isinstance(p, dict)
            and p.get("enabled") is True
            and rule_id in p.get("rule_ids", [])
            and level >= p.get("minimum_level", 0)
        ]
        if len(matches) > 1:
            raise ValueError("Multiple case policies match one detection")
        if not matches:
            return None
        policy = matches[0]
        window = policy.get("window_seconds")
        group_by = policy.get("group_by")
        if (
            type(window) is not int
            or not 300 <= window <= 86400
            or not isinstance(group_by, list)
            or not group_by
            or len(group_by) > 3
            or not set(group_by) <= {"endpoint", "detection_id", "severity"}
            or policy.get("closed_behavior", "new_case") != "new_case"
        ):
            raise ValueError("Invalid case grouping policy")
        return policy

    def device_name(self, endpoint: str) -> str:
        try:
            return self.gateway.operation._store.get_endpoint(
                UUID(endpoint)
            ).display_name
        except (KeyError, NotFoundError, ValueError):
            return endpoint

    def auto_case(
        self, db: Any, source_name: str, alert_id: str, value: dict[str, Any],
        detection: dict[str, Any], policy: dict[str, Any] | None,
    ) -> str:
        if policy is None:
            return ""
        endpoint = value["endpoints"][0]
        parts = {
            "endpoint": endpoint,
            "detection_id": detection["id"],
            "severity": value["severity"],
        }
        group = bounded_json([parts[name] for name in policy["group_by"]], 4096)
        observed = datetime.fromisoformat(value["observed_at"]).timestamp()
        window = policy["window_seconds"]
        window_start = int(observed // window) * window
        policy_id = text(policy["id"], 64)
        existing = None
        rows = db.execute(
            "SELECT * FROM ops_records WHERE kind='case' "
            "ORDER BY updated DESC LIMIT 2000"
        ).fetchall()
        for row in rows:
            item = self.store.decode(row)
            automation = item["value"].get("automation", {})
            if (
                automation.get("policy_id") == policy_id
                and automation.get("group_key") == group
                and automation.get("window_started") == window_start
                and item["value"].get("status") not in {"resolved", "closed"}
            ):
                existing = item
                break
        subject = "intake:" + source_name
        if existing:
            case = existing["value"]
            case["alerts"] = sorted(set(case.get("alerts", [])) | {alert_id})
            case["endpoints"] = sorted(set(case["endpoints"]) | {endpoint})
            case["automation"]["alert_count"] = len(case["alerts"])
            case["automation"]["last_observed_at"] = value["observed_at"]
            self.store.put(
                db, "case", existing["id"], case, subject, existing["revision"],
                "case.auto_updated",
            )
            return existing["id"]
        case_id = str(uuid4())
        device = self.device_name(endpoint)
        context = bounded_json(value.get("context", {}), 8192)
        description = (
            f"Automatically created from Project_Mati detection {detection['id']} "
            f"v{detection['version']}.\nDevice: {device} ({endpoint})\n"
            f"Source alert: {source_name}/{value['external_id']}\n"
            f"Severity: {value['severity']} (Wazuh level {value['level']})\n"
            f"Observed: {value['observed_at']}\nReceived: {value['received_at']}\n"
            f"ATT&CK: {', '.join(detection['attack'])}\nContext: {context}"
        )
        tasks = [
            {
                "id": str(uuid5(NAMESPACE_URL, f"{case_id}/check/{index}")),
                "title": title,
                "assignee": "",
                "status": "todo",
                "verification": "",
            }
            for index, title in enumerate(detection["checklist"])
        ]
        case = {
            "name": f"[{detection['id']}] {value['name']} — {device}",
            "description": text(description, 8192),
            "type": "soc",
            "priority": value["severity"],
            "assignee": text(policy.get("assignee", ""), 256, True),
            "owner": text(policy.get("owner", "SOC"), 256, True),
            "team": text(policy.get("team", "SOC"), 128, True),
            "tags": sorted(
                {
                    "project-mati",
                    detection["id"],
                    *[text(v, 64) for v in policy.get("tags", [])],
                }
            ),
            "endpoints": [endpoint],
            "assets": [],
            "services": [],
            "networks": [],
            "status": "new",
            "tasks": tasks,
            "alerts": [alert_id],
            "automation": {
                "policy_id": policy_id, "group_key": group,
                "group_by": policy["group_by"], "window_started": window_start,
                "window_seconds": window, "closed_behavior": "new_case",
                "alert_count": 1, "last_observed_at": value["observed_at"],
            },
        }
        self.store.put(db, "case", case_id, case, subject, 0, "case.auto_created")
        return case_id

    def resolve_intake_failure(
        self, db: Any, source: str, external: str, alert_id: str
    ) -> None:
        key = str(uuid5(NAMESPACE_URL, f"northgate/wazuh-failure/{source}/{external}"))
        try:
            old = self.store.get("alert", key, db)
        except KeyError:
            return
        value = old["value"]
        value["intake_status"] = "resolved"
        value["resolved_alert"] = alert_id
        value["resolved_at"] = datetime.now(UTC).isoformat()
        self.store.put(
            db, "alert", key, value, "intake:" + source, old["revision"],
            "alert.intake_recovered",
        )

    def ingest_wazuh(self, source: Any, payload: Any) -> Any:
        """Preserve normalized metadata and create/update a policy-qualified case."""
        name, external = text(source["id"], 64), text(str(payload["id"]), 256)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
            raise ValueError("Invalid Wazuh source identifier")
        agent = str(payload.get("agent", {}).get("id", ""))
        mapping = source["agents"].get(agent)
        if not isinstance(mapping, dict):
            raise RetriableIntake(
                "unmapped_device", "Alert retained for retry: device mapping required"
            )
        endpoint, identity = (
            identifier(mapping["endpoint"]),
            identifier(mapping["identity"]),
        )
        if not self.active_enrollment(endpoint, identity):
            raise RetriableIntake(
                "unmapped_device",
                "Alert retained for retry: enrollment reconciliation required",
            )
        rule = payload["rule"]
        level = rule["level"]
        if type(level) is not int or not 0 <= level <= 16:
            raise ValueError("Invalid Wazuh alert level")
        groups = rule.get("groups", [])
        if not isinstance(groups, list) or len(groups) > 32:
            raise ValueError("Invalid Wazuh rule groups")
        rule_id = text(str(rule["id"]), 64)
        try:
            detection = self.detection(source, rule_id)
            policy = self.case_policy(source, rule_id, level)
        except ValueError as error:
            raise RetriableIntake(
                "case_creation_failure",
                "Alert retained for retry: detection or case policy "
                "configuration failed",
            ) from error
        if detection["severity"] not in {"low", "normal", "high", "critical"}:
            raise RetriableIntake(
                "case_creation_failure",
                "Alert retained for retry: detection severity is invalid",
            )
        severity = detection["severity"]
        if "detections" not in source:
            severity = (
                "critical" if level >= 12 else "high" if level >= 8
                else "normal" if level >= 4 else "low"
            )
        supplied_context = payload.get("context", {})
        if not isinstance(supplied_context, dict) or set(supplied_context) - set(
            detection["context_fields"]
        ):
            raise ValueError("Alert context is not allowlisted")
        context = {
            text(k, 128): text(str(v), 1024, True)
            for k, v in supplied_context.items()
        }
        observed_at = stamp(payload["timestamp"])
        received_at = datetime.now(UTC).isoformat()
        value = {
            "name": text(rule["description"], 1024),
            "source": name,
            "external_id": external,
            "agent_id": agent,
            "identity_id": identity,
            "rule_id": rule_id,
            "detection_id": detection["id"],
            "detection_version": detection["version"],
            "level": level,
            "severity": severity,
            "groups": [text(g, 128) for g in groups],
            "observed_at": observed_at,
            "received_at": received_at,
            "context": context,
            "endpoints": [endpoint],
            "assets": [],
            "services": [],
            "networks": [],
            "source_ref": text(source.get("source_ref", ""), 512, True),
        }
        digest_value = {k: v for k, v in value.items() if k != "received_at"}
        digest = hashlib.sha256(bounded_json(digest_value).encode()).hexdigest()
        key = str(
            uuid5(NAMESPACE_URL, "northgate/wazuh/" + bounded_json([name, external]))
        )
        with self.store.lock, self.store.connection(write=True) as db:
            old = db.execute(
                "SELECT * FROM ops_alert_sources WHERE source=? AND external_id=?",
                (name, external),
            ).fetchone()
            if old:
                if old["digest"] != digest:
                    raise Conflict(
                        "Source alert identifier already contains different content"
                    )
                db.execute(
                    "UPDATE ops_alert_sources SET repeats=repeats+1,received=? "
                    "WHERE source=? AND external_id=?",
                    (time.time(), name, external),
                )
                stored = self.store.get("alert", old["record_id"], db)
                result = {"alert": old["record_id"], "duplicate": True}
                if stored["value"].get("case_id"):
                    result["case"] = stored["value"]["case_id"]
                return result
            try:
                case_id = self.auto_case(db, name, key, value, detection, policy)
                value["case_id"] = case_id
                self.store.put(
                    db, "alert", key, value, "intake:" + name, 0, "alert.received"
                )
                db.execute(
                    "INSERT INTO ops_alert_sources VALUES(?,?,?,?,?,?)",
                    (name, external, digest, key, time.time(), 0),
                )
                self.resolve_intake_failure(db, name, external, key)
                result = {"alert": key, "duplicate": False}
                if case_id:
                    result["case"] = case_id
                return result
            except (ValueError, KeyError, Conflict) as error:
                raise RetriableIntake(
                    "case_creation_failure",
                    "Alert retained for retry: case creation failed",
                ) from error
