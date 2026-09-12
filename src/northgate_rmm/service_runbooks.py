"""Deployment-approved recurring jobs under revocable machine authority.

No human bearer token is retained and the scheduler never fabricates MFA.
Plans are read from a private deployment file; the UI can run/pause approved
plans but cannot change their action, service identity or enrollment scope.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from contextlib import suppress
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from aiohttp import web

from northgate_rmm.fleet_models import READ_ACTIONS, window, window_open
from northgate_rmm.management_protocol import TERMINAL, canonical, seal, unseal
from northgate_rmm.secure_files import regular_file_reference

LOGGER = logging.getLogger(__name__)
ALLOWED = READ_ACTIONS | {
    "service.control",
    "package.install",
    "package.remove",
    "patches.install",
    "reboot",
    "tool.verify",
    "tool.run",
}


def load_plans(path: Path | None) -> dict:
    if path is None:
        return {}
    with regular_file_reference(
        path, label="service runbooks", maximum_bytes=131072, private=True
    ) as ref:
        data = json.loads(ref.read_text())
    if (
        not isinstance(data, dict)
        or set(data) != {"schema", "plans"}
        or data["schema"] != 1
    ):
        raise ValueError("Invalid service runbook configuration")
    if not isinstance(data["plans"], list) or len(data["plans"]) > 64:
        raise ValueError("Invalid runbook count")
    result = {}
    for plan in data["plans"]:
        if not isinstance(plan, dict) or set(plan) != {
            "id",
            "name",
            "client",
            "endpoints",
            "steps",
            "interval",
            "window",
            "enabled",
            "concurrency",
            "failure_limit",
            "case_id",
        }:
            raise ValueError("Runbook fields are not exact")
        identifier = str(UUID(plan["id"]))
        if identifier in result or identifier != plan["id"]:
            raise ValueError("Duplicate runbook")
        for field in ("name", "client"):
            if type(plan[field]) is not str or not 1 <= len(plan[field]) <= 128:
                raise ValueError("Invalid runbook name/client")
        if type(plan["enabled"]) is not bool:
            raise ValueError("Invalid enabled flag")
        for field, low, high in (
            ("interval", 300, 604800),
            ("concurrency", 1, 4),
            ("failure_limit", 1, 256),
        ):
            if type(plan[field]) is not int or not low <= plan[field] <= high:
                raise ValueError("Invalid runbook limits")
        endpoints = plan["endpoints"]
        if not isinstance(endpoints, dict) or not 1 <= len(endpoints) <= 256:
            raise ValueError("Runbook requires exact enrollment scope")
        for endpoint, identity in endpoints.items():
            if str(UUID(endpoint)) != endpoint or str(UUID(identity)) != identity:
                raise ValueError("Invalid runbook enrollment")
        if type(plan["case_id"]) is not str or (
            plan["case_id"] and str(UUID(plan["case_id"])) != plan["case_id"]
        ):
            raise ValueError("Invalid linked case")
        window(plan["window"])
        if not isinstance(plan["steps"], list) or not 1 <= len(plan["steps"]) <= 16:
            raise ValueError("Invalid runbook steps")
        for step in plan["steps"]:
            if not isinstance(step, dict) or set(step) != {"name", "action", "params"}:
                raise ValueError("Invalid step")
            if type(step["name"]) is not str or not 1 <= len(step["name"]) <= 128:
                raise ValueError("Invalid step name")
            if step["action"] not in ALLOWED or not isinstance(step["params"], dict):
                raise ValueError("Action not supported for unattended execution")
            if len(canonical(step["params"])) > 32768:
                raise ValueError("Oversized step parameters")
            if (
                step["action"] == "tool.run"
                and (step["params"].get("case_id") or "") != plan["case_id"]
            ):
                raise ValueError("Tool step case must match the runbook case")
        result[identifier] = {
            **plan,
            "digest": hashlib.sha256(canonical(plan)).hexdigest(),
        }
    return result


class ServiceRunbooks:
    def __init__(
        self,
        management,
        fleet,
        native,
        path=None,
        *,
        evidence_sink=None,
        case_authorizer=None,
    ):
        self.m, self.fleet, self.native = management, fleet, native
        self.path = Path(path) if path else None
        self.evidence_sink = evidence_sink
        self.case_authorizer = case_authorizer
        self.lock = asyncio.Lock()
        self.last_error = None
        self.last_tick = None
        with self.m.store.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS service_plan_state (
                    id TEXT PRIMARY KEY, paused INTEGER NOT NULL DEFAULT 0,
                    next_due REAL NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS service_plan_runs (
                    id TEXT PRIMARY KEY, plan TEXT NOT NULL, state TEXT NOT NULL,
                    created REAL NOT NULL, updated REAL NOT NULL,
                    payload BLOB NOT NULL);
                CREATE INDEX IF NOT EXISTS service_plan_recent
                    ON service_plan_runs(plan,created);
            """)

    def register(self, app):
        app.router.add_get("/remote/runbooks/state", self.state)
        app.router.add_post("/remote/runbooks/action", self.action)
        app.cleanup_ctx.append(self.lifecycle)

    def permitted(self, principal, plan):
        policy = self.m.gateway.operation._policy
        return all(
            policy.permits(principal.subject, e, "automation.manage")
            for e in plan["endpoints"]
        )

    def authority(self, plan):
        if self.native is None:
            raise ValueError("Native service authorization is not configured")
        entry = self.native.auth.entries().get(plan["client"])
        if not entry or not entry["enabled"]:
            raise ValueError("Runbook service identity unavailable or revoked")
        for endpoint, identity in plan["endpoints"].items():
            if entry["endpoints"].get(endpoint) != identity:
                raise ValueError("Runbook enrollment scope is no longer authorized")
        for step in plan["steps"]:
            if step["action"] not in entry["actions"]:
                raise ValueError("Runbook action is no longer authorized")
            if (
                step["action"] == "tool.run"
                and (step["params"].get("case_id") or "") != plan["case_id"]
            ):
                raise ValueError("Tool step case must match the runbook case")
        return entry

    async def authorize_case(self, entry, plan):
        if plan["case_id"]:
            if self.evidence_sink is None or self.case_authorizer is None:
                raise ValueError(
                    "Linked cases require case authorization and an evidence sink"
                )
            await self.case_authorizer(entry, plan)

    def settings(self, identifier):
        with self.m.store.connect() as db:
            row = db.execute(
                "SELECT paused,next_due FROM service_plan_state WHERE id=?",
                (identifier,),
            ).fetchone()
        return (
            {"paused": bool(row[0]), "next_due": row[1]}
            if row
            else {"paused": False, "next_due": 0}
        )

    def runs(self, plan=None, active=False):
        where, args = [], []
        if plan:
            where.append("plan=?")
            args.append(plan)
        if active:
            where.append("state='running'")
        clause = " WHERE " + " AND ".join(where) if where else ""
        with self.m.store.connect() as db:
            rows = db.execute(
                "SELECT * FROM service_plan_runs"  # noqa: S608 - fixed predicates only
                + clause
                + " ORDER BY created DESC LIMIT 200",
                args,
            ).fetchall()
        return [
            unseal(self.m.gateway.key, r["payload"], "service-run/" + r["id"])
            for r in rows
        ]

    def save_run(self, run):
        run["updated"] = time.time()
        with self.m.store.connect() as db:
            db.execute(
                "INSERT INTO service_plan_runs VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET state=excluded.state,"
                "updated=excluded.updated,payload=excluded.payload",
                (
                    run["id"],
                    run["plan"],
                    run["state"],
                    run["created"],
                    run["updated"],
                    seal(self.m.gateway.key, run, "service-run/" + run["id"]),
                ),
            )

    async def state(self, request):
        principal = await self.fleet.principal(request)
        try:
            plans = load_plans(self.path)
        except (ValueError, OSError):
            raise web.HTTPServiceUnavailable(
                text="Runbook configuration needs administrator attention"
            ) from None
        rows = []
        for plan in plans.values():
            if not self.permitted(principal, plan):
                continue
            try:
                entry = self.authority(plan)
                await self.authorize_case(entry, plan)
                ready, reason = True, ""
            except (ValueError, web.HTTPException) as exc:
                ready, reason = False, str(exc)
            rows.append(
                {
                    **{k: v for k, v in plan.items() if k not in {"digest", "steps"}},
                    "steps": [
                        {"name": s["name"], "action": s["action"]}
                        for s in plan["steps"]
                    ],
                    **self.settings(plan["id"]),
                    "ready": ready,
                    "reason": reason,
                    "runs": self.runs(plan["id"])[:10],
                }
            )
        return web.json_response(
            {
                "plans": rows,
                "csrf": self.fleet.csrf(principal),
                "configured": self.path is not None,
                "last_tick": self.last_tick,
                "error": self.last_error,
            },
            headers=self.fleet.headers(),
        )

    async def action(self, request):
        principal = await self.fleet.principal(request)
        if request.headers.get("Origin") != self.m.gateway.origin:
            raise web.HTTPForbidden()
        import hmac

        if not hmac.compare_digest(
            request.headers.get("X-CSRF-Token", ""), self.fleet.csrf(principal)
        ):
            raise web.HTTPForbidden()
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        try:
            value = await request.json()
            if not isinstance(value, dict) or set(value) != {
                "plan",
                "action",
                "request_id",
            }:
                raise ValueError("Expected plan, action and request_id")
            identifier = str(UUID(value["request_id"]))
            plan = load_plans(self.path)[str(UUID(value["plan"]))]
            if not self.permitted(principal, plan):
                raise web.HTTPForbidden()
            async with self.lock:
                if value["action"] == "run":
                    await self.fleet.audit(principal, "runbook.run", plan["id"])
                    run = await self.begin(plan, identifier)
                    return web.json_response({"run": run}, headers=self.fleet.headers())
                if value["action"] not in {"pause", "resume"}:
                    raise ValueError("Unsupported action")
                if value["action"] == "resume":
                    await self.authorize_case(self.authority(plan), plan)
                await self.fleet.audit(
                    principal, "runbook." + value["action"], plan["id"]
                )
                with self.m.store.connect() as db:
                    db.execute(
                        "INSERT INTO service_plan_state(id,paused,next_due) "
                        "VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET "
                        "paused=excluded.paused",
                        (
                            plan["id"],
                            int(value["action"] == "pause"),
                            time.time() + plan["interval"],
                        ),
                    )
                if value["action"] == "pause":
                    for run in self.runs(plan["id"], active=True):
                        self.stop(run, "Paused by operator")
            return web.json_response({"ok": True}, headers=self.fleet.headers())
        except (ValueError, KeyError, TypeError) as exc:
            raise web.HTTPBadRequest(text=str(exc)[:200]) from None

    async def begin(self, plan, identifier):
        with self.m.store.connect() as db:
            existing_row = db.execute(
                "SELECT plan,payload FROM service_plan_runs WHERE id=?", (identifier,)
            ).fetchone()
        if existing_row and existing_row["plan"] != plan["id"]:
            raise ValueError("Request identifier already belongs to another plan")
        existing = (
            unseal(
                self.m.gateway.key, existing_row["payload"], "service-run/" + identifier
            )
            if existing_row
            else None
        )
        if existing and existing["digest"] != plan["digest"]:
            raise ValueError(
                "Request identifier already belongs to a different plan version"
            )
        await self.authorize_case(self.authority(plan), plan)
        if existing:
            return existing
        if not plan["enabled"] or self.settings(plan["id"])["paused"]:
            raise ValueError("Runbook is disabled or paused")
        if not window_open(plan["window"], time.time()):
            raise ValueError("Outside the approved maintenance window")
        if self.runs(plan["id"], active=True):
            raise ValueError("This runbook already has an active run")
        now = time.time()
        run = {
            "id": identifier,
            "plan": plan["id"],
            "digest": plan["digest"],
            "state": "running",
            "created": now,
            "updated": now,
            "devices": {
                e: {"step": 0, "job": None, "state": "pending", "history": []}
                for e in plan["endpoints"]
            },
            "error": "",
            "case_id": plan["case_id"],
        }
        self.save_run(run)
        with self.m.store.connect() as db:
            db.execute(
                "INSERT INTO service_plan_state(id,paused,next_due) VALUES (?,0,?) "
                "ON CONFLICT(id) DO UPDATE SET next_due=excluded.next_due",
                (plan["id"], now + plan["interval"]),
            )
        self.m.store.event(
            "",
            "runbook:" + plan["id"],
            "service.runbook.started",
            {"run": identifier, "client": plan["client"], "case": plan["case_id"]},
        )
        return run

    def stop(self, run, reason):
        for device in run["devices"].values():
            if device["job"]:
                self.m.store.cancel(device["job"])
            if device["state"] not in {"completed", "failed"}:
                device["state"] = "cancel_requested" if device["job"] else "cancelled"
        run.update(state="stopped", error=reason)
        self.save_run(run)

    async def advance(self, run, plan):
        if (
            not plan
            or plan["digest"] != run["digest"]
            or not plan["enabled"]
            or self.settings(plan["id"])["paused"]
        ):
            self.stop(run, "Plan changed, removed, disabled or paused")
            return
        try:
            entry = self.authority(plan)
        except ValueError:
            self.stop(run, "Service authorization revoked")
            return
        try:
            await self.authorize_case(entry, plan)
        except (ValueError, web.HTTPException):
            self.stop(run, "Case authorization unavailable or revoked")
            return
        active = 0
        for row in run["devices"].values():
            if not row["job"]:
                continue
            job = self.m.store.job(row["job"])
            if job["state"] not in TERMINAL:
                active += 1
                continue
            row["history"].append(
                {"job": job["id"], "action": job["action"], "state": job["state"]}
            )
            if self.evidence_sink and plan["case_id"]:
                try:
                    await self.evidence_sink(entry, plan["case_id"], job["id"])
                except Exception:
                    row.update(
                        state="failed", error="Unable to retain case evidence", job=None
                    )
                    continue
            row["job"] = None
            if (
                job["state"] != "completed"
                or job.get("receipt", {}).get("exit_code", 0) != 0
            ):
                row.update(state="failed", error="Step did not complete successfully")
            else:
                row["step"] += 1
                row["state"] = (
                    "completed" if row["step"] == len(plan["steps"]) else "pending"
                )
        if (
            sum(r["state"] == "failed" for r in run["devices"].values())
            >= plan["failure_limit"]
        ):
            self.stop(run, "Failure limit reached; remaining jobs cancelled")
            return
        if all(r["state"] in {"completed", "failed"} for r in run["devices"].values()):
            run["state"] = (
                "failed"
                if any(r["state"] == "failed" for r in run["devices"].values())
                else "completed"
            )
        elif window_open(plan["window"], time.time()):
            for endpoint, row in run["devices"].items():
                if active >= plan["concurrency"]:
                    break
                if row["state"] != "pending" or row["job"]:
                    continue
                step = plan["steps"][row["step"]]
                identifier = str(
                    uuid5(
                        NAMESPACE_URL,
                        "northgate/runbook/"
                        + run["id"]
                        + "/"
                        + endpoint
                        + "/"
                        + str(row["step"]),
                    )
                )
                try:
                    entry = self.authority(plan)
                    await self.authorize_case(entry, plan)
                except (ValueError, web.HTTPException):
                    self.stop(
                        run, "Service or case authorization unavailable or revoked"
                    )
                    return
                try:
                    _, device = self.native.endpoint(
                        entry, endpoint, step["action"], online=True
                    )
                    result = await self.native.submit(
                        entry,
                        UUID(endpoint),
                        device,
                        step["action"],
                        step["params"],
                        identifier,
                    )
                    row.update(job=result["job"], state="running")
                    active += 1
                except (ValueError, web.HTTPException, KeyError):
                    row.update(
                        state="failed", error="Endpoint or operation no longer eligible"
                    )
                self.save_run(run)  # Persist each submission before another target.
        self.save_run(run)

    async def tick(self):
        async with self.lock:
            try:
                plans = load_plans(self.path)
            except (ValueError, OSError, KeyError, TypeError):
                for run in self.runs(active=True):
                    self.stop(run, "Runbook configuration unavailable or invalid")
                raise
            for run in self.runs(active=True):
                await self.advance(run, plans.get(run["plan"]))
            for plan in plans.values():
                settings = self.settings(plan["id"])
                if (
                    plan["enabled"]
                    and not settings["paused"]
                    and settings["next_due"] <= time.time()
                    and not self.runs(plan["id"], active=True)
                    and window_open(plan["window"], time.time())
                ):
                    try:
                        await self.begin(plan, str(uuid4()))
                    except (ValueError, web.HTTPException):
                        continue
            self.last_tick, self.last_error = time.time(), None

    async def lifecycle(self, app):
        async def loop():
            while True:
                try:
                    await self.tick()
                except Exception:
                    self.last_error = (
                        "Scheduler needs administrator attention; no new work started"
                    )
                    LOGGER.exception("Service runbook reconciliation failed")
                await asyncio.sleep(5)

        task = asyncio.create_task(loop())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
