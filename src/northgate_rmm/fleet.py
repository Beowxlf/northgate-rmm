"""Authenticated fleet workspace, alert reconciliation and bounded rollout scheduler.

The scheduler uses the approving human's expiring session. It never fabricates
an operator or upgrades a browser session into a permanent service credential.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from aiohttp import web

from northgate_rmm.fleet_access import action_permission
from northgate_rmm.fleet_models import (
    EDITABLE,
    FLEET_ACTIONS,
    RUN_TERMINAL,
    identifier,
    integer,
    text,
    validate_record,
    window_open,
)
from northgate_rmm.fleet_store import Conflict, FleetStore
from northgate_rmm.management import Management
from northgate_rmm.management_protocol import (
    TERMINAL,
    canonical,
    unseal,
    validate_action,
)
from northgate_rmm.management_store import QueueFull
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.remote_policy import authorize_remote

LOGGER = logging.getLogger(__name__)
BASE = "/remote/fleet"
DEFAULT_RULES = (
    ("offline", "Device offline", "warning"),
    ("worker_missing", "Management worker unavailable", "warning"),
    ("capture_dependency", "Capture driver missing", "warning"),
    ("package_dependency", "Package manager unavailable", "info"),
    ("recovery_missing", "Recovery account not configured", "warning"),
    ("job_failed", "Management operation failed", "critical"),
    ("baseline_drift", "Baseline changed", "warning"),
)


class Fleet:
    def __init__(self, management: Management) -> None:
        self.m = management
        self.gateway = management.gateway
        self.store = FleetStore(management.store)
        self.lock = asyncio.Lock()
        self.last_tick: float | None = None
        self.last_error: str | None = None
        self.alert_seen: dict[str, float] = {}
        for condition, name, severity in DEFAULT_RULES:
            key = str(uuid5(NAMESPACE_URL, "northgate/fleet/rule/" + condition))
            try:
                self.store.get("rule", key)
            except KeyError:
                self.store.put(
                    "rule",
                    key,
                    validate_record(
                        "rule",
                        {"name": name, "condition": condition, "severity": severity},
                    ),
                    "system",
                )

    def register(self, app: web.Application) -> None:
        app.router.add_get(BASE + "/ui", self.page)
        app.router.add_get(BASE + "/assets/{name}", self.asset)
        app.router.add_get(BASE + "/api/state", self.state)
        app.router.add_post(BASE + "/api/{operation}", self.mutate)
        app.cleanup_ctx.append(self.lifecycle)

    def headers(self) -> dict[str, str]:
        return {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "same-origin",
            "Content-Security-Policy": (
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; frame-src 'self'; "
                "frame-ancestors 'self'; base-uri 'none'; form-action 'self'"
            ),
        }

    async def principal(self, request: web.Request) -> OperatorPrincipal:
        if request.remote not in {"127.0.0.1", "::1"}:
            raise web.HTTPForbidden()
        try:
            p = await self.authenticate(request.headers.get("Authorization"))
            if self.gateway.operation._authorization_denial(p, now=datetime.now(UTC)):
                raise ValueError("Scope denied")
            return p
        except Exception:
            raise web.HTTPForbidden(text="Sign in again to continue") from None

    async def authenticate(self, authorization: str | None) -> OperatorPrincipal:
        async with asyncio.timeout(10):
            await self.gateway._verification_slots.acquire()
        task = asyncio.create_task(
            asyncio.to_thread(
                self.gateway.operation._authenticate,
                authorization,
                now=datetime.now(UTC),
                correlation_id=uuid4(),
            )
        )

        def completed(result: asyncio.Task[OperatorPrincipal]) -> None:
            self.gateway._verification_slots.release()
            if not result.cancelled():
                result.exception()

        task.add_done_callback(completed)
        # HTTP cancellation must not release a still-running identity check slot.
        return await asyncio.shield(task)

    def csrf(self, p: OperatorPrincipal) -> str:
        return hmac.new(
            self.gateway.key,
            canonical(["fleet-form-v1", p.subject, p.session_id]),
            hashlib.sha256,
        ).hexdigest()

    def admin(self, p: OperatorPrincipal) -> bool:
        return self.gateway.operation._policy.permits(p.subject, "*", "fleet_admin")

    def allowed(
        self, p: OperatorPrincipal, endpoint: str, permission: str = "view"
    ) -> bool:
        return self.gateway.operation._policy.permits(p.subject, endpoint, permission)

    async def audit(
        self,
        p: OperatorPrincipal,
        action: str,
        target: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        await asyncio.to_thread(
            self.gateway.operation._audit,
            p,
            subject="fleet:" + target[:128],
            action="fleet." + action,
            decision="accepted",
            reason="authenticated fleet operation",
            correlation_id=uuid4(),
            now=datetime.now(UTC),
        )
        self.m.store.event(
            "", target, "fleet." + action, {"subject": p.subject, **(detail or {})}
        )

    async def page(self, request: web.Request) -> web.Response:
        p = await self.principal(request)
        await self.audit(p, "workspace.read", "workspace")
        return web.Response(
            text=Path(__file__).with_name("fleet.html").read_text(encoding="utf-8"),
            content_type="text/html",
            headers=self.headers(),
        )

    async def asset(self, request: web.Request) -> web.Response:
        await self.principal(request)
        name = request.match_info["name"]
        if name not in {"fleet.js", "fleet.css"}:
            raise web.HTTPNotFound()
        return web.Response(
            body=Path(__file__).with_name(name).read_bytes(),
            content_type="text/javascript" if name.endswith(".js") else "text/css",
            headers=self.headers(),
        )

    def inventory(self) -> list[dict[str, Any]]:
        asset_records = {r["id"]: r for r in self.store.list("asset")}
        metadata = {key: r["value"] for key, r in asset_records.items()}
        baselines = {r["id"]: r["value"] for r in self.store.list("baseline")}
        rows = []
        after = None
        now = datetime.now(UTC)
        source = self.gateway.operation._store
        snapshot_reader = getattr(source, "fleet_snapshot", None)
        if callable(snapshot_reader):
            snapshot = snapshot_reader(now=now)
        else:
            snapshot = []
            for _ in range(100):
                page = source.list_endpoint_page(after=after, limit=100)
                snapshot.extend(
                    (endpoint, source.endpoint_status(endpoint.endpoint_id, now=now))
                    for endpoint in page
                )
                if len(page) < 100:
                    break
                after = page[-1].endpoint_id
        with self.m.store.connect() as db:
            workers = {
                r["endpoint"]: dict(r) for r in db.execute("SELECT * FROM workers")
            }
            latest_jobs = {
                r["endpoint"]: dict(r)
                for r in db.execute("""
                SELECT id,endpoint,action,state,updated FROM (
                    SELECT id,endpoint,action,state,updated,
                           ROW_NUMBER() OVER(
                               PARTITION BY endpoint ORDER BY created DESC,id DESC
                           ) AS position
                    FROM jobs) WHERE position=1
            """)
            }
            escrow_by_endpoint: dict[str, list[dict[str, Any]]] = {}
            for r in db.execute(
                "SELECT endpoint,kind,max(created) AS collected "
                "FROM escrow GROUP BY endpoint,kind"
            ):
                escrow_by_endpoint.setdefault(r["endpoint"], []).append(
                    {"kind": r["kind"], "collected": r["collected"]}
                )
        for endpoint, status in snapshot:
            key = str(endpoint.endpoint_id)
            stored = workers.get(key)
            worker: dict[str, Any] = (
                {"ready": False}
                if stored is None
                else {
                    "ready": time.time() - stored["seen"] < 20,
                    "identity": stored["identity"],
                    "last_seen": stored["seen"],
                    "capabilities": unseal(
                        self.gateway.key, stored["capabilities"], key + "/worker"
                    ),
                }
            )
            bound = worker.get("identity") == str(endpoint.identity_id)
            capabilities = worker.get("capabilities", {}) if bound else {}
            meta = metadata.get(key, {})
            snapshot = {
                "platform": endpoint.platform.value,
                "architecture": endpoint.architecture,
                "versions": capabilities.get("versions", {}),
                "features": capabilities.get("features", {}),
            }
            base = baselines.get(key)
            changes = []
            if base and bound and worker.get("ready"):
                for field, old in base["snapshot"].items():
                    if old != snapshot.get(field):
                        changes.append(
                            {
                                "field": field,
                                "before": old,
                                "after": snapshot.get(field),
                            }
                        )
            latest = latest_jobs.get(key)
            escrow = escrow_by_endpoint.get(key, [])
            rows.append(
                {
                    "id": key,
                    "identity": str(endpoint.identity_id),
                    "name": meta.get("name") or endpoint.display_name,
                    "platform": endpoint.platform.value,
                    "architecture": endpoint.architecture,
                    "lifecycle": status.lifecycle.value,
                    "health": status.health.value,
                    "last_seen": status.last_heartbeat_at.timestamp()
                    if status.last_heartbeat_at
                    else None,
                    "worker_ready": bool(bound and worker.get("ready")),
                    "worker_seen": worker.get("last_seen"),
                    "managed": endpoint.endpoint_id in self.gateway.targets,
                    "capabilities": capabilities,
                    "metadata": meta,
                    "metadata_revision": asset_records.get(key, {}).get("revision", 0),
                    "baseline": base.get("created") if base else None,
                    "changes": changes,
                    "last_job": dict(latest) if latest else None,
                    "recovery_receipts": [dict(r) for r in escrow],
                    "snapshot": snapshot,
                }
            )
        return rows

    def members(self, group: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not group:
            return rows
        parents = {
            r["id"]: r["value"].get("parent", "") for r in self.store.list("group")
        }
        if group not in parents:
            raise ValueError("Device group no longer exists")

        def belongs(key: str) -> bool:
            seen: set[str] = set()
            while key and key not in seen:
                if key == group:
                    return True
                seen.add(key)
                key = parents.get(key, "")
            return False

        return [r for r in rows if belongs(r["metadata"].get("group", ""))]

    async def state(self, request: web.Request) -> web.Response:
        p = await self.principal(request)
        rows = await asyncio.to_thread(self.inventory)
        rows = [r for r in rows if self.allowed(p, r["id"])]
        visible = {r["id"] for r in rows}
        for row in rows:
            row["permissions"] = [
                name
                for name in ("remote", "manage", "patch", "recovery")
                if self.allowed(p, row["id"], name)
            ]
            if (
                not self.allowed(p, row["id"], "recovery")
                or "recovery_operator" not in p.roles
            ):
                row.pop("recovery_receipts", None)
                row["capabilities"] = {
                    k: v
                    for k, v in row["capabilities"].items()
                    if k != "recovery_account"
                }
        records: dict[str, Any] = {}
        for kind in (
            "group",
            "policy",
            "automation",
            "rule",
            "exercise",
            "view",
            "rollout",
            "alert",
        ):
            entries = self.store.list(kind, 500)
            if kind in {"policy", "automation", "rule", "exercise"} and not self.admin(
                p
            ):
                entries = [e for e in entries if e["subject"] == p.subject]
            if kind == "view":
                entries = [e for e in entries if e["subject"] == p.subject]
            if kind == "group" and not self.admin(p):
                parents = {e["id"]: e["value"].get("parent", "") for e in entries}
                permitted_groups: set[str] = set()
                for row in rows:
                    group = row["metadata"].get("group", "")
                    while group and group not in permitted_groups:
                        permitted_groups.add(group)
                        group = parents.get(group, "")
                entries = [e for e in entries if e["id"] in permitted_groups]
            if kind == "rollout":
                entries = [
                    e for e in entries if e["subject"] == p.subject or self.admin(p)
                ]
                for entry in entries:
                    value = entry["value"]
                    entry["value"] = {
                        k: value[k]
                        for k in (
                            "name",
                            "state",
                            "action",
                            "created",
                            "expires",
                            "targets",
                            "jobs",
                            "errors",
                            "canary_approved",
                            "exercise",
                            "policy",
                            "progress",
                            "next_due",
                        )
                        if k in value
                    }
                    entry["value"]["targets"] = [
                        r for r in value["targets"] if r["id"] in visible
                    ]
                    entry["value"]["jobs"] = {
                        k: v for k, v in value.get("jobs", {}).items() if k in visible
                    }
                    entry["value"]["errors"] = {
                        k: v for k, v in value.get("errors", {}).items() if k in visible
                    }
            if kind == "alert":
                entries = [e for e in entries if e["value"]["endpoint"] in visible]
            records[kind] = entries
        await self.audit(p, "state.read", "workspace")
        return web.json_response(
            {
                "devices": rows,
                "records": records,
                "csrf": self.csrf(p),
                "subject": p.subject,
                "roles": list(p.roles),
                "admin": self.admin(p),
                "actions": FLEET_ACTIONS,
                "server_time": time.time(),
                "session_expires": p.expires_at.timestamp(),
                "scheduler": {"last_tick": self.last_tick, "error": self.last_error},
                "limits": {
                    "preview_devices": 500,
                    "concurrency": 16,
                    "run_seconds": 3600,
                },
            },
            headers=self.headers(),
        )

    async def mutate(self, request: web.Request) -> web.Response:
        p = await self.principal(request)
        if request.headers.get(
            "Origin"
        ) != self.gateway.origin or not hmac.compare_digest(
            request.headers.get("X-CSRF-Token", ""), self.csrf(p)
        ):
            raise web.HTTPForbidden(text="Refresh the workspace before submitting")
        try:
            if (
                request.content_type != "application/json"
                or (request.content_length or 0) > 262144
            ):
                raise ValueError("A bounded JSON request is required")
            raw = bytearray()
            async for chunk in request.content.iter_chunked(32768):
                raw.extend(chunk)
                if len(raw) > 262144:
                    raise ValueError("Request too large")
            if len(raw) > 262144:
                raise ValueError("Request too large")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("Invalid request")
            async with self.lock:
                result = await self.perform(
                    request.match_info["operation"],
                    value,
                    p,
                    request.headers["Authorization"],
                )
            return web.json_response(result, headers=self.headers())
        except Conflict as error:
            return web.json_response(
                {"error": str(error)}, status=409, headers=self.headers()
            )
        except (ValueError, KeyError, TypeError) as error:
            return web.json_response(
                {"error": str(error)}, status=400, headers=self.headers()
            )

    async def perform(
        self,
        operation: str,
        value: dict[str, Any],
        p: OperatorPrincipal,
        authorization: str,
    ) -> dict[str, Any]:
        if operation == "save":
            kind = value.get("kind")
            if kind not in EDITABLE or (kind != "view" and not self.admin(p)):
                raise web.HTTPForbidden(text="Fleet administrator access required")
            key = identifier(value["id"]) if value.get("id") else str(uuid4())
            revision = integer(value.get("revision", 0), 0, 100000000)
            record = validate_record(kind, value.get("value"))
            if (
                kind == "view"
                and revision
                and self.store.get(kind, key)["subject"] != p.subject
            ):
                raise web.HTTPForbidden()
            if kind == "asset":
                endpoint = self.gateway.operation._store.get_endpoint(UUID(key))
                if not self.allowed(p, str(endpoint.endpoint_id)):
                    raise web.HTTPForbidden()
            if record.get("group"):
                self.store.get("group", record["group"])
            if kind == "automation":
                self.store.get("policy", record["policy"])
            if kind == "group":
                parent, seen = record["parent"], {key}
                while parent:
                    if parent in seen:
                        raise ValueError("Groups cannot contain themselves")
                    seen.add(parent)
                    parent = self.store.get("group", parent)["value"]["parent"]
            await self.audit(p, kind + ".saved", key)
            return self.store.put(kind, key, record, p.subject, revision)
        if operation == "delete":
            kind, key = value["kind"], identifier(value["id"])
            if kind not in EDITABLE or (kind != "view" and not self.admin(p)):
                raise web.HTTPForbidden()
            record = self.store.get(kind, key)
            if kind == "view" and record["subject"] != p.subject:
                raise web.HTTPForbidden()
            if kind in {"group", "policy"}:
                for other in ("group", "asset", "policy", "automation", "rule", "view"):
                    if any(
                        key
                        in (
                            r["value"].get("group"),
                            r["value"].get("parent"),
                            r["value"].get("policy"),
                        )
                        for r in self.store.list(other)
                    ):
                        raise ValueError(
                            "Move dependent records before deleting this item"
                        )
            await self.audit(p, kind + ".deleted", key)
            self.store.delete(kind, key, integer(value["revision"], 1, 100000000))
            return {"deleted": key}
        if operation == "preview":
            return await self.preview(value, p)
        if operation == "start":
            return await self.start(value, p, authorization)
        if operation == "run-control":
            return await self.control(value, p)
        if operation == "alert":
            key = identifier(value["id"])
            entry = self.store.get("alert", key)
            alert = entry["value"]
            if (
                not self.allowed(p, alert["endpoint"], "manage")
                or "remote_operator" not in p.roles
            ):
                raise web.HTTPForbidden()
            state = value.get("state")
            if state not in {"acknowledged", "resolved", "snoozed", "open"}:
                raise ValueError("Invalid alert transition")
            alert.update(
                state=state,
                note=text(value.get("note", ""), 1024, empty=True),
                actor=p.subject,
                snooze_until=time.time()
                + integer(value.get("seconds", 3600), 60, 86400)
                if state == "snoozed"
                else 0,
            )
            await self.audit(p, "alert." + state, key)
            return self.store.put(
                "alert", key, alert, p.subject, integer(value["revision"], 1, 100000000)
            )
        if operation == "baseline":
            key = identifier(value["endpoint"])
            if not self.allowed(p, key, "manage") or "remote_operator" not in p.roles:
                raise web.HTTPForbidden()
            rows = await asyncio.to_thread(self.inventory)
            row = next((r for r in rows if r["id"] == key), None)
            if row is None or not row["worker_ready"]:
                raise ValueError(
                    "Wait for a current authenticated worker before saving a baseline"
                )
            try:
                existing = self.store.get("baseline", key)
            except KeyError:
                existing = {"revision": 0}
            await self.audit(p, "baseline.saved", key)
            return self.store.put(
                "baseline",
                key,
                {"created": time.time(), "snapshot": row["snapshot"]},
                p.subject,
                existing["revision"],
            )
        if operation == "export":
            return await self.export(value, p)
        raise ValueError("Unknown workspace operation")

    async def preview(
        self, value: dict[str, Any], p: OperatorPrincipal
    ) -> dict[str, Any]:
        if "remote_operator" not in p.roles:
            raise web.HTTPForbidden(text="Remote operator role required")
        policy_record = (
            self.store.get("policy", identifier(value["policy"]))
            if value.get("policy")
            else None
        )
        if (
            policy_record
            and policy_record["subject"] != p.subject
            and not self.admin(p)
        ):
            raise web.HTTPForbidden()
        policy = (
            policy_record["value"]
            if policy_record
            else validate_record("policy", value.get("operation"))
        )
        rows = await asyncio.to_thread(self.inventory)
        group = value.get("group") or policy.get("group", "")
        rows = self.members(group, rows)
        requested = value.get("endpoints", [])
        if not isinstance(requested, list) or len(requested) > 500:
            raise ValueError("Select at most 500 devices")
        selected = {identifier(key) for key in requested}
        if selected:
            rows = [r for r in rows if r["id"] in selected]
            if {r["id"] for r in rows} != selected:
                raise ValueError("Selection contains unavailable devices")
        rows = [
            r for r in rows if self.allowed(p, r["id"]) and r["lifecycle"] == "active"
        ]
        if not rows or len(rows) > 500:
            raise ValueError("Choose between 1 and 500 active devices")
        eligible, excluded = [], []
        action = policy["action"]
        for row in rows:
            reason = None
            if policy["platform"] not in {"all", row["platform"]}:
                reason = "Platform does not match the policy"
            elif not row["managed"]:
                reason = "Management enrollment configuration required"
            elif not self.allowed(
                p, row["id"], action_permission(action)
            ) or not self.allowed(p, row["id"], "manage"):
                reason = "Operation is outside your device permissions"
            elif not row["worker_ready"] or row["health"] != "online":
                reason = "Device or management worker is offline"
            elif (
                action.startswith("package.")
                or (action.startswith("patches.") and row["platform"] == "linux")
            ) and not row["capabilities"].get("features", {}).get("packages"):
                reason = "Package manager is unavailable under the worker identity"
            if reason:
                excluded.append(
                    {"id": row["id"], "name": row["name"], "reason": reason}
                )
            else:
                validate_action(action, policy["params"], row["platform"])
                eligible.append(
                    {
                        "id": row["id"],
                        "identity": row["identity"],
                        "name": row["name"],
                        "platform": row["platform"],
                    }
                )
        eligible.sort(key=lambda r: (r["name"].casefold(), r["id"]))
        self.store.prune_previews()
        key = str(uuid4())
        preview: dict[str, Any] = {
            "policy": policy,
            "policy_id": policy_record["id"] if policy_record else "",
            "policy_revision": policy_record["revision"] if policy_record else 0,
            "targets": eligible,
            "excluded": excluded,
            "created": time.time(),
            "expires": time.time() + 600,
            "session": p.session_id,
            "exercise": text(value.get("exercise", ""), 64, empty=True),
            "automation": identifier(value["automation"])
            if value.get("automation")
            else "",
        }
        if preview["automation"]:
            if not self.admin(p):
                raise web.HTTPForbidden()
            automation = self.store.get("automation", preview["automation"])
            if (
                not automation["value"]["enabled"]
                or automation["value"]["policy"] != preview["policy_id"]
            ):
                raise ValueError("Automation changed or is disabled")
            preview["automation_revision"] = automation["revision"]
            preview["interval"] = automation["value"]["interval"]
        await self.audit(
            p,
            "rollout.previewed",
            key,
            {"eligible": len(eligible), "excluded": len(excluded)},
        )
        record = self.store.put("preview", key, preview, p.subject)
        return {
            "id": key,
            "revision": record["revision"],
            "targets": eligible,
            "excluded": excluded,
            "policy": policy,
            "expires": preview["expires"],
            "window_open": window_open(policy["window"], time.time()),
        }

    async def start(
        self, value: dict[str, Any], p: OperatorPrincipal, authorization: str
    ) -> dict[str, Any]:
        key = identifier(value["preview"])
        entry = self.store.get("preview", key)
        preview = entry["value"]
        if (
            entry["subject"] != p.subject
            or preview["session"] != p.session_id
            or preview["expires"] < time.time()
        ):
            raise ValueError("Preview expired. Preview the targets again.")
        if not preview["targets"]:
            raise ValueError("No eligible targets")
        if (
            preview["policy_id"]
            and self.store.get("policy", preview["policy_id"])["revision"]
            != preview["policy_revision"]
        ):
            raise Conflict("Policy changed after preview")
        if (
            preview["automation"]
            and self.store.get("automation", preview["automation"])["revision"]
            != preview["automation_revision"]
        ):
            raise Conflict("Automation changed after preview")
        # A preview ID is also the run ID: retries never create another rollout.
        try:
            existing = self.store.get("rollout", key)
            return {"id": existing["id"], "state": existing["value"]["state"]}
        except KeyError:
            pass
        expires = min(
            p.expires_at.timestamp(),
            time.time() + integer(value.get("seconds", 3600), 60, 3600),
        )
        run = {
            **preview,
            "name": preview["policy"]["name"],
            "state": "scheduled",
            "action": preview["policy"]["action"],
            "authorization": authorization,
            "subject": p.subject,
            "session": p.session_id,
            "expires": expires,
            "jobs": {},
            "errors": {},
            "canary_approved": False,
            "progress": {"completed": 0, "failed": 0, "total": len(preview["targets"])},
            "cycle": 0,
            "next_due": time.time(),
        }
        await self.audit(
            p,
            "rollout.approved",
            key,
            {"targets": len(run["targets"]), "action": run["action"]},
        )
        self.store.put("rollout", key, run, p.subject)
        return {"id": key, "state": run["state"]}

    async def control(
        self, value: dict[str, Any], p: OperatorPrincipal
    ) -> dict[str, Any]:
        entry = self.store.get("rollout", identifier(value["id"]))
        run = entry["value"]
        if entry["subject"] != p.subject and not self.admin(p):
            raise web.HTTPForbidden()
        if integer(value["revision"], 1, 100000000) != entry["revision"]:
            raise Conflict("Run changed; refresh before controlling it")
        action = value.get("action")
        if run["state"] in RUN_TERMINAL:
            raise ValueError("Run has finished; create a fresh preview")
        if action == "cancel":
            run["state"] = "cancelled"
            run.pop("authorization", None)
            for job in run["jobs"].values():
                with suppress(KeyError):
                    self.m.store.cancel(job)
        elif action == "pause":
            run["state"] = "paused"
        elif action == "resume":
            if run["state"] not in {"paused", "awaiting_review"}:
                raise ValueError("Only a paused run can resume")
            if run["session"] != p.session_id or run["subject"] != p.subject:
                raise ValueError(
                    "Resume using the approving session or create a new preview"
                )
            if run["state"] == "awaiting_review":
                run["canary_approved"] = True
            run["state"] = "scheduled"
        else:
            raise ValueError("Invalid run control")
        await self.audit(p, "rollout." + action, entry["id"])
        self.store.put(
            "rollout",
            entry["id"],
            run,
            entry["subject"],
            integer(value["revision"], 1, 100000000),
        )
        return {"id": entry["id"], "state": run["state"]}

    async def export(
        self, value: dict[str, Any], p: OperatorPrincipal
    ) -> dict[str, Any]:
        exercise = identifier(value["exercise"]) if value.get("exercise") else ""
        visible = {
            r["id"]
            for r in await asyncio.to_thread(self.inventory)
            if self.allowed(p, r["id"])
        }
        if exercise:
            record = self.store.get("exercise", exercise)
            if record["subject"] != p.subject and not self.admin(p):
                raise web.HTTPForbidden()
        else:
            record = None
        runs = []
        for entry in self.store.list("rollout"):
            run = entry["value"]
            if (exercise and run.get("exercise") != exercise) or (
                entry["subject"] != p.subject and not self.admin(p)
            ):
                continue
            jobs = []
            all_jobs = [*run.get("history", []), run["jobs"]]
            for endpoint, key in (item for cycle in all_jobs for item in cycle.items()):
                if endpoint not in visible:
                    continue
                with suppress(KeyError):
                    job = self.m.store.job(key)
                    # Export provenance and outcomes without arbitrary command output.
                    jobs.append(
                        {
                            k: job[k]
                            for k in (
                                "id",
                                "endpoint",
                                "identity",
                                "action",
                                "state",
                                "created",
                                "updated",
                            )
                        }
                    )
            runs.append(
                {
                    "id": entry["id"],
                    "name": run["name"],
                    "state": run["state"],
                    "jobs": jobs,
                }
            )
        payload = {
            "schema": "northgate.fleet.evidence.v1",
            "generated": time.time(),
            "exercise": record,
            "runs": runs,
            "alerts": [
                r for r in self.store.list("alert") if r["value"]["endpoint"] in visible
            ],
        }
        await self.audit(p, "evidence.exported", exercise or "fleet")
        return {
            "data": payload,
            "sha256": hashlib.sha256(canonical(payload)).hexdigest(),
        }

    async def lifecycle(self, app: web.Application) -> AsyncIterator[None]:
        task = asyncio.create_task(self.scheduler())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    async def scheduler(self) -> None:
        while True:
            try:
                async with self.lock:
                    rows = await asyncio.to_thread(self.inventory)
                    await self.reconcile_alerts(rows)
                    for entry in self.store.list("rollout"):
                        if entry["value"]["state"] not in RUN_TERMINAL:
                            await self.advance(entry)
                    self.last_tick = time.time()
                    self.last_error = None
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never log bearer tokens, command payloads or recovery material.
                LOGGER.error("Fleet reconciliation failed; inspect workspace readiness")
                self.last_error = (
                    "Fleet reconciliation failed. "
                    "Existing worker leases still expire independently."
                )
            await asyncio.sleep(10)

    async def advance(self, entry: dict[str, Any]) -> None:
        run = entry["value"]
        now = time.time()
        if run["expires"] <= now:
            run["state"] = "expired"
            for key in run["jobs"].values():
                with suppress(KeyError):
                    self.m.store.cancel(key)
        elif run["state"] == "paused":
            return
        else:
            try:
                p = await self.authenticate(run["authorization"])
                if (
                    p.subject != run["subject"]
                    or p.session_id != run["session"]
                    or self.gateway.operation._authorization_denial(
                        p, now=datetime.now(UTC)
                    )
                ):
                    raise ValueError("Approving session is no longer valid")
                await self.advance_authorized(entry["id"], run, p)
            except QueueFull:
                # Already dispatched jobs remain tracked; retry remaining targets.
                run["state"] = "waiting_capacity"
            except Exception:
                run["state"] = "failed"
                run["errors"]["authorization"] = (
                    "Run stopped: authorization, policy or dispatch validation failed. "
                    "Review before creating a new run."
                )
                for key in run["jobs"].values():
                    with suppress(KeyError):
                        self.m.store.cancel(key)
        if run["state"] in RUN_TERMINAL:
            run.pop("authorization", None)
            self.m.store.event(
                run.get("exercise", ""),
                "fleet",
                "fleet.rollout." + run["state"],
                {"run": entry["id"], "progress": run["progress"]},
            )
        self.store.put("rollout", entry["id"], run, entry["subject"], entry["revision"])

    async def advance_authorized(
        self, run_id: str, run: dict[str, Any], p: OperatorPrincipal
    ) -> None:
        policy = run["policy"]
        if run.get("automation"):
            current = self.store.get("automation", run["automation"])
            if (
                not current["value"]["enabled"]
                or current["revision"] != run["automation_revision"]
            ):
                raise ValueError("Automation has changed")
            if (
                self.store.get("policy", run["policy_id"])["revision"]
                != run["policy_revision"]
            ):
                raise ValueError("Automation policy has changed")
        done, failed, active = 0, len(run["errors"]), 0
        for job_id in run["jobs"].values():
            job = self.m.store.job(job_id)
            done += job["state"] == "completed"
            failed += job["state"] in TERMINAL and job["state"] != "completed"
            active += job["state"] not in TERMINAL
        run["progress"] = {
            "completed": done,
            "failed": failed,
            "active": active,
            "total": len(run["targets"]),
        }
        if failed >= policy["failure_limit"]:
            run["state"] = "failed"
            for job_id in run["jobs"].values():
                if self.m.store.job(job_id)["state"] not in TERMINAL:
                    self.m.store.cancel(job_id)
            return
        finished = (
            len(run["jobs"]) + len(run["errors"]) == len(run["targets"]) and active == 0
        )
        if finished:
            if (
                run.get("automation")
                and not failed
                and run["expires"] > time.time() + run["interval"]
            ):
                self.m.store.event(
                    run.get("exercise", ""),
                    "fleet",
                    "fleet.automation.cycle",
                    {"run": run_id, "cycle": run["cycle"], "jobs": run["jobs"]},
                )
                run.setdefault("history", []).append(dict(run["jobs"]))
                run.update(
                    cycle=run["cycle"] + 1,
                    jobs={},
                    errors={},
                    next_due=time.time() + run["interval"],
                    state="scheduled",
                    canary_approved=False,
                )
            else:
                run["state"] = "failed" if failed else "completed"
            return
        if time.time() < run["next_due"] or not window_open(
            policy["window"], time.time()
        ):
            run["state"] = "scheduled"
            return
        canary_count = min(policy["canary"], len(run["targets"]))
        if len(run["jobs"]) >= canary_count and not run["canary_approved"]:
            if active:
                run["state"] = "canary"
                return
            if policy["review_canary"]:
                run["state"] = "awaiting_review"
                return
            run["canary_approved"] = True
        limit = policy["concurrency"] - active
        if not run["canary_approved"]:
            limit = min(limit, canary_count - len(run["jobs"]))
        for target in run["targets"]:
            if limit <= 0:
                break
            if target["id"] in run["jobs"] or target["id"] in run["errors"]:
                continue
            endpoint = UUID(target["id"])
            e = await asyncio.to_thread(
                self.gateway.operation._store.get_endpoint, endpoint
            )
            status = await asyncio.to_thread(
                self.gateway.operation._store.endpoint_status,
                endpoint,
                now=datetime.now(UTC),
            )
            if str(e.identity_id) != target["identity"]:
                run["errors"][target["id"]] = "Enrollment changed after preview"
                break
            worker = self.m.store.worker(endpoint)
            if not worker.get("ready") or worker.get("identity") != target["identity"]:
                run["errors"][target["id"]] = "Worker unavailable; no action sent"
                break
            authorize_remote(
                p,
                self.gateway.operation._policy,
                self.gateway.targets[endpoint][0],
                status,
                e.identity_id,
                now=datetime.now(UTC),
                permission=action_permission(run["action"]),
            )
            params = dict(policy["params"])
            validate_action(run["action"], params, e.platform.value)
            if run["action"] == "script.run":
                with self.m.store.connect() as db:
                    row = db.execute(
                        "SELECT payload FROM scripts WHERE id=? AND version=?",
                        (params["script_id"], params["version"]),
                    ).fetchone()
                if row is None:
                    raise ValueError("Reviewed script is missing")
                script = unseal(
                    self.gateway.key,
                    row[0],
                    params["script_id"] + "/" + params["version"],
                )
                if (
                    hashlib.sha256(canonical(script)).hexdigest() != params["version"]
                    or script["platform"] != e.platform.value
                    or set(script["inputs"]) != set(params["inputs"])
                ):
                    raise ValueError("Reviewed script contract changed")
                params["content"] = script["content"]
            job_id = str(uuid5(UUID(run_id), target["id"] + "/" + str(run["cycle"])))
            await self.audit(
                p,
                "job.dispatched",
                target["id"],
                {"run": run_id, "job": job_id, "action": run["action"]},
            )
            self.m.store.add(
                endpoint,
                e.identity_id,
                p,
                run["action"],
                params,
                run["authorization"],
                run.get("exercise", ""),
                min(900, max(1, int(run["expires"] - time.time()))),
                identifier=job_id,
            )
            run["jobs"][target["id"]] = job_id
            limit -= 1
        run["state"] = "running" if run["canary_approved"] else "canary"

    async def reconcile_alerts(self, rows: list[dict[str, Any]]) -> None:
        now = time.time()
        existing = {r["id"]: r for r in self.store.list("alert")}
        observed: set[str] = set()
        for rule in self.store.list("rule"):
            config = rule["value"]
            if not config["enabled"]:
                continue
            for row in self.members(config.get("group", ""), rows):
                if row["lifecycle"] != "active":
                    continue
                features = row["capabilities"].get("features", {})
                conditions = {
                    "offline": row["health"] == "offline",
                    "worker_missing": row["managed"] and not row["worker_ready"],
                    "capture_dependency": row["worker_ready"]
                    and row["platform"] == "windows"
                    and not features.get("npcap_driver_installed", False),
                    "package_dependency": row["worker_ready"]
                    and not features.get("packages", False),
                    "recovery_missing": row["worker_ready"]
                    and not row["capabilities"]
                    .get("recovery_account", {})
                    .get("managed", False),
                    "job_failed": bool(
                        row["last_job"]
                        and row["last_job"]["state"]
                        in {"failed", "expired", "result_unknown"}
                    ),
                    "baseline_drift": bool(row["changes"]),
                }
                if not conditions[config["condition"]]:
                    continue
                key = str(uuid5(UUID(rule["id"]), row["id"]))
                observed.add(key)
                entry = existing.get(key)
                first = self.alert_seen.setdefault(key, now)
                if entry and entry["value"].get("condition_active"):
                    first = entry["value"].get("first_seen", first)
                if now - first < config["delay"]:
                    continue
                alert = (
                    dict(entry["value"])
                    if entry
                    else {
                        "endpoint": row["id"],
                        "rule": rule["id"],
                        "state": "open",
                        "first_seen": first,
                        "count": 1,
                        "note": "",
                    }
                )
                fingerprint = hashlib.sha256(
                    canonical(
                        [
                            config["condition"],
                            row["last_job"]
                            if config["condition"] == "job_failed"
                            else row["changes"]
                            if config["condition"] == "baseline_drift"
                            else True,
                        ]
                    )
                ).hexdigest()
                if (
                    alert.get("state") == "resolved"
                    and alert.get("fingerprint") == fingerprint
                    and alert.get("condition_active")
                ):
                    continue
                if (
                    alert.get("state") == "snoozed"
                    and alert.get("snooze_until", 0) > now
                ):
                    continue
                if alert.get("state") in {"resolved", "snoozed"}:
                    alert["state"] = "open"
                    alert["count"] += 1
                    alert["first_seen"] = now
                alert.update(
                    name=config["name"],
                    device=row["name"],
                    condition=config["condition"],
                    fingerprint=fingerprint,
                    severity="critical"
                    if config["severity"] == "warning"
                    and now - first >= config["escalate"]
                    else config["severity"],
                    last_seen=now,
                    condition_active=True,
                )
                # Avoid revising an operator's open editor every ten seconds.
                if (
                    not entry
                    or any(
                        alert.get(k) != entry["value"].get(k)
                        for k in (
                            "state",
                            "severity",
                            "fingerprint",
                            "condition_active",
                        )
                    )
                    or now - entry["updated"] > 300
                ):
                    changed = not entry or any(
                        alert.get(k) != entry["value"].get(k)
                        for k in (
                            "state",
                            "severity",
                            "fingerprint",
                            "condition_active",
                        )
                    )
                    self.store.put(
                        "alert", key, alert, "system", entry["revision"] if entry else 0
                    )
                    if changed:
                        self.m.store.event(
                            "",
                            row["id"],
                            "fleet.alert." + alert["state"],
                            {
                                "alert": key,
                                "severity": alert["severity"],
                                "condition": alert["condition"],
                            },
                        )
        self.alert_seen = {
            key: value for key, value in self.alert_seen.items() if key in observed
        }
        for key, entry in existing.items():
            if key not in observed and entry["value"].get("condition_active"):
                alert = {
                    **entry["value"],
                    "state": "resolved",
                    "condition_active": False,
                    "resolved_at": now,
                }
                self.store.put("alert", key, alert, "system", entry["revision"])
                self.m.store.event(
                    "",
                    alert["endpoint"],
                    "fleet.alert.resolved",
                    {
                        "alert": key,
                        "severity": alert["severity"],
                        "condition": alert["condition"],
                    },
                )
