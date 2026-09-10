"""Owner-authorized privileged jobs and a separate endpoint-mTLS polling surface."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from aiohttp import web

from northgate_rmm.domain import EndpointLifecycle
from northgate_rmm.fleet_access import action_permission
from northgate_rmm.listener import extract_verified_client_certificate
from northgate_rmm.management_protocol import (
    ACTIONS,
    MAX_RESULT,
    SECRET_ACTIONS,
    TERMINAL,
    canonical,
    open_worker_result,
    public_configuration,
    seal,
    sign,
    unseal,
    validate_action,
)
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import authorize_remote
from northgate_rmm.remote_workspace import frame_response

RECOVERY_ROLE = "recovery_operator"


class Management:
    def __init__(self, gateway: RemoteGateway, store: ManagementStore) -> None:
        self.gateway, self.store = gateway, store
        self.forms: dict[str, tuple[str, str, str, float]] = {}
        self.shell_leases: dict[str, float] = {}
        self.slots = asyncio.Semaphore(4)
        from northgate_rmm.management_extended import ExtendedManagement

        self.extended = ExtendedManagement(self)

    def register(self, app: web.Application) -> None:
        self.extended.register(app)
        app.router.add_get("/remote/{endpoint}/manage", self.page)
        app.router.add_get("/remote/{endpoint}/manage/state", self.state)
        app.router.add_post("/remote/{endpoint}/manage/action", self.action)
        app.router.add_post("/remote/{endpoint}/manage/io", self.terminal)
        app.router.add_post("/remote/{endpoint}/manage/reveal", self.reveal)
        app.router.add_post("/remote/{endpoint}/manage/download", self.download)
        app.router.add_get("/remote/{endpoint}/manage/config", self.configuration)
        app.router.add_post("/remote/{endpoint}/manage/scripts", self.script)
        app.router.add_get("/remote/{endpoint}/manage/evidence", self.evidence)

    async def context(
        self, request: web.Request, online: bool = False
    ) -> tuple[UUID, OperatorPrincipal, Any]:
        try:
            endpoint = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        p = await self.gateway.principal(
            request, endpoint, require_online=online, permission="manage"
        )
        e = await asyncio.to_thread(
            self.gateway.operation._store.get_endpoint, endpoint
        )
        return endpoint, p, e

    def csrf(
        self,
        request: web.Request,
        p: OperatorPrincipal,
        endpoint: UUID | str,
        token: Any,
    ) -> None:
        if not isinstance(token, str):
            raise web.HTTPForbidden(text="Invalid form token")
        if request.headers.get("Origin") != self.gateway.origin:
            raise web.HTTPForbidden(text="Refresh the endpoint page before submitting")
        form = self.forms.get(token)
        if (
            form is None
            or form[:3] != (p.subject, p.session_id, str(endpoint))
            or form[3] < time.time()
        ):
            raise web.HTTPForbidden(text="Form expired; refresh this page")

    async def body(self, request: web.Request) -> dict[str, Any]:
        if request.content_type != "application/json":
            raise web.HTTPUnsupportedMediaType()
        try:
            value = await request.json()
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise web.HTTPBadRequest(text="Invalid request") from None

    def headers(self) -> dict[str, str]:
        return {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

    async def state(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.context(request)
        jobs = self.store.list(endpoint)
        for j in jobs:
            if j["subject"] != p.subject:
                j.pop("receipt", None)
        worker = self.store.worker(endpoint)
        if worker.get("identity") != str(e.identity_id):
            worker = {
                "ready": False,
                "reason": "Worker enrollment is missing or has changed",
            }
        return web.json_response(
            {"worker": worker, "jobs": jobs}, headers=self.headers()
        )

    async def configuration(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.context(request)
        await self.gateway.audit(
            p, endpoint, "management.configuration.exported", uuid4()
        )
        return web.json_response(
            {
                "endpoint_id": str(endpoint),
                "identity_id": str(e.identity_id),
                **public_configuration(self.gateway.key),
            },
            headers=self.headers(),
        )

    async def action(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.context(request)
        value = await self.body(request)
        self.csrf(request, p, endpoint, value.get("csrf"))
        operation = value.get("action")
        if not isinstance(operation, str):
            raise web.HTTPBadRequest(text="Invalid operation")
        try:
            if operation == "cancel":
                j = self.store.job(str(UUID(value["job"])))
                if j["endpoint"] != str(endpoint) or j["subject"] != p.subject:
                    raise web.HTTPForbidden()
                await self.gateway.audit(
                    p, endpoint, "management.job.cancelled", UUID(j["id"])
                )
                self.store.cancel(j["id"])
                return web.json_response({"job": j["id"]}, headers=self.headers())
            params = value.get("params", {})
            validate_action(operation, params, e.platform.value)
            if not self.gateway.operation._policy.permits(
                p.subject, endpoint, action_permission(operation)
            ):
                raise web.HTTPForbidden(
                    text="Operation is outside your assigned permissions"
                )
            if operation in SECRET_ACTIONS and RECOVERY_ROLE not in p.roles:
                raise web.HTTPForbidden(text="Recovery operator role required")
            exercise = value.get("exercise", "")
            if (
                not isinstance(exercise, str)
                or len(exercise) > 64
                or any(ord(c) < 32 for c in exercise)
            ):
                raise ValueError("Invalid exercise identifier")
            if operation == "script.run":
                with self.store.connect() as db:
                    row = db.execute(
                        "SELECT payload FROM scripts WHERE id=? AND version=?",
                        (params["script_id"], params["version"]),
                    ).fetchone()
                if row is None:
                    raise ValueError("Reviewed script version not found")
                script = unseal(
                    self.gateway.key,
                    row[0],
                    params["script_id"] + "/" + params["version"],
                )
                if hashlib.sha256(canonical(script)).hexdigest() != params["version"]:
                    raise ValueError("Reviewed script integrity failed")
                if script["platform"] != e.platform.value:
                    raise ValueError("Script platform mismatch")
                if set(params["inputs"]) != set(script["inputs"]):
                    raise ValueError("Script inputs do not match its contract")
                if any(
                    not isinstance(v, str) or len(v) > 4096
                    for v in params["inputs"].values()
                ):
                    raise ValueError("Invalid script input")
                params = {**params, "content": script["content"]}
            await self.gateway.audit(
                p, endpoint, "management.job.requested." + operation, uuid4()
            )
            identifier = self.store.add(
                endpoint,
                e.identity_id,
                p,
                operation,
                params,
                request.headers["Authorization"],
                exercise,
                900
                if operation
                in {
                    "patches.install",
                    "package.install",
                    "package.remove",
                    "prerequisites.install",
                    "shell.start",
                }
                else 300,
            )
            if operation == "shell.start":
                self.shell_leases[identifier] = time.time() + 45
            self.store.event(
                exercise,
                str(endpoint),
                "job.requested",
                {"job": identifier, "operation": operation, "subject": p.subject},
            )
            return web.json_response(
                {"job": identifier}, headers=self.headers(), status=202
            )
        except (ValueError, KeyError, TypeError) as error:
            raise web.HTTPBadRequest(text=str(error)) from None

    async def terminal(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.context(request)
        v = await self.body(request)
        self.csrf(request, p, endpoint, v.get("csrf"))
        try:
            identifier = str(UUID(v["job"]))
            j = self.store.job(identifier)
            if (
                j["endpoint"],
                j["identity"],
                j["subject"],
                j["session"],
                j["action"],
            ) != (
                str(endpoint),
                str(e.identity_id),
                p.subject,
                p.session_id,
                "shell.start",
            ):
                raise web.HTTPForbidden()
            if j["state"] not in TERMINAL:
                self.shell_leases[identifier] = time.time() + 45
            after = v.get("after", 0)
            if type(after) is not int or after < 0:
                raise ValueError("Invalid output position")
            self.store.prune_frames(identifier, "out", after)
            if "input" in v and j["state"] not in TERMINAL:
                message = v["input"]
                if not isinstance(message, dict) or not set(message) <= {
                    "data",
                    "columns",
                    "rows",
                }:
                    raise ValueError("Invalid terminal input")
                if (
                    len(base64.b64decode(message.get("data", ""), validate=True))
                    > 16384
                ):
                    raise ValueError("Input too large")
                for name, low, high in [("columns", 20, 240), ("rows", 5, 100)]:
                    if name in message and (
                        type(message[name]) is not int
                        or not low <= message[name] <= high
                    ):
                        raise ValueError("Invalid terminal size")
                self.store.io(identifier, "in", v["sequence"], message)
            return web.json_response(
                {
                    "state": j["state"],
                    "frames": self.store.frames(identifier, "out", after),
                },
                headers=self.headers(),
            )
        except (ValueError, KeyError, TypeError):
            raise web.HTTPBadRequest(text="Invalid terminal request") from None

    async def reveal(self, request: web.Request) -> web.Response:
        endpoint, p, _e = await self.context(request)
        v = await self.body(request)
        self.csrf(request, p, endpoint, v.get("csrf"))
        if RECOVERY_ROLE not in p.roles:
            raise web.HTTPForbidden(text="Recovery operator role required")
        if not self.gateway.operation._policy.permits(p.subject, endpoint, "recovery"):
            raise web.HTTPForbidden(
                text="Recovery access is outside your assigned permissions"
            )
        try:
            j = self.store.job(str(UUID(v["job"])), private=True)
        except (ValueError, KeyError):
            raise web.HTTPNotFound() from None
        if (
            j["endpoint"] != str(endpoint)
            or j["action"] not in SECRET_ACTIONS
            or j["state"] != "completed"
        ):
            raise web.HTTPNotFound()
        await self.gateway.audit(
            p, endpoint, "management.escrow.revealed", UUID(j["id"])
        )
        self.store.event(
            j["exercise"],
            str(endpoint),
            "escrow.revealed",
            {"job": j["id"], "subject": p.subject},
        )
        return web.json_response(j["receipt"], headers=self.headers())

    async def download(self, request: web.Request) -> web.Response:
        endpoint, p, _e = await self.context(request)
        v = await self.body(request)
        self.csrf(request, p, endpoint, v.get("csrf"))
        try:
            j = self.store.job(str(UUID(v["job"])), private=True)
        except (ValueError, KeyError):
            raise web.HTTPNotFound() from None
        if (
            j["endpoint"] != str(endpoint)
            or j["subject"] != p.subject
            or j["action"] != "files.read"
            or j["state"] != "completed"
        ):
            raise web.HTTPNotFound()
        value = json.loads(j["receipt"]["output"])
        data = base64.b64decode(value["data"], validate=True)
        if (
            len(data) != value["size"]
            or hashlib.sha256(data).hexdigest() != value["sha256"]
        ):
            raise web.HTTPBadGateway(text="File result integrity failed")
        await self.gateway.audit(
            p, endpoint, "management.file.downloaded", UUID(j["id"])
        )
        return web.Response(
            body=data,
            content_type="application/octet-stream",
            headers={
                **self.headers(),
                "Content-Disposition": 'attachment; filename="NorthGateRMM-download"',
                "X-Content-SHA256": value["sha256"],
            },
        )

    async def script(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.context(request)
        v = await self.body(request)
        self.csrf(request, p, endpoint, v.get("csrf"))
        try:
            identifier = str(UUID(v.get("id", str(uuid4()))))
            content = v["content"]
            names = v.get("inputs", [])
            if (
                not isinstance(content, str)
                or len(content.encode()) > 32768
                or not isinstance(names, list)
                or len(names) > 16
            ):
                raise ValueError()
            import re

            if any(
                not isinstance(n, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", n)
                for n in names
            ) or len(set(names)) != len(names):
                raise ValueError()
            payload = {
                "content": content,
                "platform": e.platform.value,
                "inputs": names,
                "author": p.subject,
            }
            version = hashlib.sha256(canonical(payload)).hexdigest()
            await self.gateway.audit(
                p, endpoint, "management.script.published", UUID(identifier)
            )
            with self.store.connect() as db:
                db.execute(
                    "INSERT OR IGNORE INTO scripts VALUES (?,?,?,?)",
                    (
                        identifier,
                        version,
                        time.time(),
                        seal(self.gateway.key, payload, identifier + "/" + version),
                    ),
                )
            return web.json_response(
                {"script_id": identifier, "version": version}, headers=self.headers()
            )
        except (ValueError, KeyError, TypeError):
            raise web.HTTPBadRequest(text="Invalid script contract") from None

    async def evidence(self, request: web.Request) -> web.Response:
        endpoint, _p, _e = await self.context(request)
        with self.store.connect() as db:
            rows = db.execute(
                (
                    "SELECT * FROM evidence WHERE endpoint=? ORDER BY "
                    "created DESC LIMIT 1000"
                ),
                (str(endpoint),),
            ).fetchall()
        value = [
            {
                **{k: r[k] for k in dict(r) if k != "payload"},
                "detail": unseal(self.gateway.key, r["payload"], r["id"]),
            }
            for r in rows
        ]
        return web.json_response(
            {"endpoint": str(endpoint), "events": value}, headers=self.headers()
        )

    async def authorize_job(self, j: dict[str, Any]) -> None:
        def check() -> None:
            now = datetime.now(UTC)
            p = self.gateway.operation._authenticate(
                j["payload"]["authorization"], now=now, correlation_id=uuid4()
            )
            endpoint = UUID(j["endpoint"])
            if not self.gateway.operation._policy.permits(
                p.subject, endpoint, "manage"
            ):
                raise ValueError("Management permission revoked")
            e = self.gateway.operation._store.get_endpoint(endpoint)
            if (p.subject, p.session_id, str(e.identity_id)) != (
                j["subject"],
                j["session"],
                j["identity"],
            ):
                raise ValueError("Job identity changed")
            authorize_remote(
                p,
                self.gateway.operation._policy,
                self.gateway.targets[endpoint][0],
                self.gateway.operation._store.endpoint_status(endpoint, now=now),
                e.identity_id,
                now=now,
                require_online=False,
                permission=action_permission(j["action"]),
            )
            if j["action"] in SECRET_ACTIONS and RECOVERY_ROLE not in p.roles:
                raise ValueError("Recovery role revoked")

        async with self.gateway._verification_slots:
            await asyncio.to_thread(check)

    def worker_application(self) -> web.Application:
        app = web.Application(client_max_size=MAX_RESULT + 65536)
        app.router.add_post("/v1/management/poll", self.poll)
        app.router.add_get(
            "/v1/management/releases/{digest}", self.extended.download_release
        )
        return app

    async def worker_identity(self, request: web.Request) -> tuple[Any, Any]:
        try:
            if request.transport is None:
                raise ValueError("TLS transport required")
            peer = extract_verified_client_certificate(
                request.transport.get_extra_info("ssl_object")
            )
            # The operator database identity is intentionally read-only for
            # enrollment records. Validate the current identity without taking
            # the agent-ingress UPDATE lock or granting it mutation privileges.
            store = self.gateway.operation._store
            endpoint = await asyncio.to_thread(store.get_endpoint, peer.endpoint_id)
            identity = await asyncio.to_thread(store.get_identity, endpoint.identity_id)
            if (
                peer.endpoint_id not in self.gateway.targets
                or self.gateway.targets[peer.endpoint_id][0].identity_id
                != identity.identity_id
                or identity.endpoint_id != peer.endpoint_id
                or identity.status is not EndpointLifecycle.ACTIVE
                or identity.revoked_at is not None
                or not secrets.compare_digest(
                    identity.public_key_fingerprint, peer.public_key_fingerprint
                )
            ):
                raise ValueError("Endpoint not managed")
            return peer, identity
        except Exception:
            raise web.HTTPForbidden(
                text="Management endpoint authentication rejected"
            ) from None

    async def poll(self, request: web.Request) -> web.Response:
        async with self.slots:
            try:
                peer, identity = await self.worker_identity(request)
                v = await self.body(request)
                if (
                    not isinstance(v.get("nonce"), str)
                    or not 16 <= len(v["nonce"]) <= 64
                ):
                    raise ValueError("Invalid poll nonce")
                receipts = v.get("receipts", [])
                frames = v.get("frames", [])
                if (
                    not isinstance(receipts, list)
                    or len(receipts) > 4
                    or not isinstance(frames, list)
                    or len(frames) > 32
                ):
                    raise ValueError("Invalid worker batch")
                self.store.seen(
                    peer.endpoint_id, identity.identity_id, v.get("capabilities", {})
                )
                acks = []
                for item in receipts:
                    identifier = str(UUID(item["job"]))
                    receipt = open_worker_result(
                        self.gateway.key, item["sealed"], identifier
                    )
                    self.store.result(
                        peer.endpoint_id, identity.identity_id, identifier, receipt
                    )
                    acks.append(identifier)
                for item in frames:
                    j = self.store.job(str(UUID(item["job"])))
                    if (j["endpoint"], j["identity"], j["action"]) != (
                        str(peer.endpoint_id),
                        str(identity.identity_id),
                        "shell.start",
                    ):
                        raise ValueError("Wrong terminal binding")
                    data = base64.b64decode(item["data"], validate=True)
                    if len(data) > 16384:
                        raise ValueError("Output frame too large")
                    self.store.io(
                        j["id"], "out", item["sequence"], {"data": item["data"]}
                    )
                controls = []
                job = None
                active = v.get("active", "")
                for j in self.store.pending(peer.endpoint_id, identity.identity_id):
                    allowed = True
                    try:
                        await self.authorize_job(j)
                    except Exception:
                        allowed = False
                    if (
                        j["action"] == "shell.start"
                        and self.shell_leases.get(j["id"], 0) < time.time()
                    ):
                        allowed = False
                    if not allowed:
                        self.store.cancel(j["id"])
                    if (
                        j["state"] == "queued"
                        and allowed
                        and not j["cancel"]
                        and not active
                        and job is None
                    ):
                        if self.store.dispatch(j["id"]):
                            job = {
                                k: j[k]
                                for k in (
                                    "id",
                                    "endpoint",
                                    "identity",
                                    "subject",
                                    "session",
                                    "action",
                                    "expires",
                                    "exercise",
                                )
                            }
                            job["params"] = j["payload"]["params"]
                    elif j["id"] == active:
                        control = {
                            "job": j["id"],
                            "cancel": bool(j["cancel"]) or not allowed,
                            "lease": min(time.time() + 45, j["expires"]),
                        }
                        if j["action"] == "shell.start":
                            after = v.get("input_ack", 0)
                            if type(after) is not int or after < 0:
                                raise ValueError("Invalid input acknowledgement")
                            self.store.prune_frames(j["id"], "in", after)
                            control["input"] = self.store.frames(j["id"], "in", after)
                        controls.append(control)
                if active and not any(c["job"] == active for c in controls):
                    controls.append({"job": active, "cancel": True, "lease": 0})
                body = {
                    "schema": 1,
                    "endpoint": str(peer.endpoint_id),
                    "identity": str(identity.identity_id),
                    "nonce": v.get("nonce"),
                    "expires": int(time.time()) + 30,
                    "job": job,
                    "controls": controls,
                    "acks": acks,
                    "frame_ack": [(f["job"], f["sequence"]) for f in frames],
                }
                return web.json_response(
                    sign(self.gateway.key, body), headers=self.headers()
                )
            except web.HTTPException:
                raise
            except Exception:
                raise web.HTTPForbidden(
                    text="Management authentication or request rejected"
                ) from None

    async def page(self, request: web.Request) -> web.Response:
        endpoint, p, e = await self.context(request)
        now = time.time()
        self.forms = {k: v for k, v in self.forms.items() if v[3] > now}
        if len(self.forms) >= 128:
            raise web.HTTPServiceUnavailable(text="Too many management pages")
        token = secrets.token_urlsafe(32)
        self.forms[token] = (
            p.subject,
            p.session_id,
            str(endpoint),
            min(now + 1800, p.expires_at.timestamp()),
        )
        settings = {
            "base": f"/remote/{endpoint}/manage",
            "csrf": token,
            "actions": {
                name: fields
                for name, fields in ACTIONS.items()
                if self.gateway.operation._policy.permits(
                    p.subject, endpoint, action_permission(name)
                )
                and (name not in SECRET_ACTIONS or RECOVERY_ROLE in p.roles)
            },
            "platform": e.platform.value,
            "recovery": RECOVERY_ROLE in p.roles
            and self.gateway.operation._policy.permits(p.subject, endpoint, "recovery"),
        }
        script = (
            Path(__file__).with_name("management_xterm.js").read_text(encoding="utf-8")
            + "\n;const settings="
            + json.dumps(settings).replace("<", "\\u003c")
            + ";\n"
            + Path(__file__).with_name("management.js").read_text(encoding="utf-8")
        )
        terminal_css = Path(__file__).with_name("management_xterm.css").read_text()
        content = (
            Path(__file__).with_name("management.html").read_text(encoding="utf-8")
        )
        response = frame_response(
            content.replace("__BASE__", settings["base"])
            + "<style>"
            + terminal_css
            + "</style><script>"
            + script
            + "</script>"
        )
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        response.headers["Content-Security-Policy"] += (
            f"; script-src 'sha256-{digest}'; connect-src 'self'"
        )
        import re

        response.headers["Content-Security-Policy"] = re.sub(
            r"style-src [^;]+",
            "style-src 'self' 'unsafe-inline'",
            response.headers["Content-Security-Policy"],
        )
        return response
