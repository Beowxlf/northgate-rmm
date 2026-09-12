"""Optional tool catalog: approved recipes over the existing signed job channel."""

from __future__ import annotations

import base64
import json
import secrets
import time
from pathlib import Path
from uuid import UUID, uuid4

from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from northgate_rmm.management_protocol import validate_action
from northgate_rmm.secure_files import regular_file_reference
from northgate_rmm.tool_catalog_models import (
    ACTION_GUIDANCE,
    BUILTIN,
    PROFILE_GUIDANCE,
    PROFILES,
    TOOL_GUIDANCE,
    TOOLS,
    manifest_bytes,
    validate_manifest,
)


class ToolCatalog:
    def __init__(
        self,
        management,
        root: Path | None = None,
        *,
        case_authorizer=None,
        case_linker=None,
    ):
        self.m = management
        self.root = root or management.store.root / "tool-catalog"
        self.case_authorizer = case_authorizer
        self.case_linker = case_linker

    def register(self, app):
        app.router.add_get("/remote/{endpoint}/tool-catalog", self.state)
        app.router.add_post("/remote/{endpoint}/tool-catalog/action", self.action)

    def entries(self, platform, architecture=None):
        result = []
        for path in sorted(self.root.glob("*.json"))[:128]:
            with regular_file_reference(
                path, label="approved tool manifest", maximum_bytes=16384, private=True
            ) as ref:
                entry = json.loads(ref.read_text())
            if not isinstance(entry, dict) or set(entry) != {"manifest", "signature"}:
                raise ValueError("Invalid catalog entry")
            manifest = validate_manifest(entry["manifest"])
            if len(base64.b64decode(entry["signature"], validate=True)) != 64:
                raise ValueError("Invalid catalog signature")
            with regular_file_reference(
                self.root / "authority.pub",
                label="tool approval authority",
                maximum_bytes=256,
                private=True,
            ) as ref:
                authority = base64.b64decode(ref.read_text().strip(), validate=True)
            Ed25519PublicKey.from_public_bytes(authority).verify(
                base64.b64decode(entry["signature"]),
                b"NorthGate-Tool-v1\0" + manifest_bytes(manifest),
            )
            if manifest["platform"] == platform and (
                architecture is None or manifest["arch"] == architecture
            ):
                result.append(entry)
        return sorted(
            result, key=lambda entry: entry["manifest"]["revision"], reverse=True
        )

    async def state(self, request):
        endpoint, principal, device = await self.m.context(request)
        entries = self.entries(
            device.platform.value, getattr(device, "architecture", "amd64")
        )
        self.m.forms = {k: v for k, v in self.m.forms.items() if v[3] > time.time()}
        if len(self.m.forms) >= 128:
            raise web.HTTPTooManyRequests(text="Too many open operation forms")
        token = next(
            (
                key
                for key, form in self.m.forms.items()
                if form[:3] == (principal.subject, principal.session_id, str(endpoint))
                and form[3] > time.time() + 60
            ),
            None,
        )
        token = token or secrets.token_urlsafe(32)
        self.m.forms[token] = (
            principal.subject,
            principal.session_id,
            str(endpoint),
            min(time.time() + 1800, principal.expires_at.timestamp()),
        )
        tools = []
        for name, platforms in TOOLS.items():
            if device.platform.value not in platforms:
                continue
            releases = sorted(
                [e["manifest"] for e in entries if e["manifest"]["id"] == name],
                key=lambda item: item["revision"],
            )
            tools.append(
                {
                    "id": name,
                    "name": name.replace("-", " ").title(),
                    "builtin": name in BUILTIN,
                    "platforms": list(platforms),
                    "profiles": sorted(PROFILES[name]),
                    "releases": releases,
                    "release": releases[-1] if releases else None,
                    "guidance": {
                        "purpose": TOOL_GUIDANCE[name][0],
                        "use_when": TOOL_GUIDANCE[name][1],
                        "output": TOOL_GUIDANCE[name][2],
                        "impact": TOOL_GUIDANCE[name][3],
                    },
                    "profile_guidance": {
                        profile: PROFILE_GUIDANCE.get(
                            profile, "Approved bounded profile."
                        )
                        for profile in sorted(PROFILES[name])
                    },
                }
            )
        jobs = [
            j
            for j in self.m.store.list(endpoint)
            if j["subject"] == principal.subject and j["action"].startswith("tool.")
        ]
        worker = self.m.store.worker(endpoint)
        if worker.get("identity") != str(device.identity_id):
            worker = {"ready": False, "reason": "Worker enrollment changed"}
        await self.m.gateway.audit(principal, endpoint, "tools.catalog.viewed", uuid4())
        return web.json_response(
            {
                "csrf": token,
                "tools": tools,
                "worker": worker,
                "jobs": jobs,
                "action_guidance": {
                    action: {"label": value[0], "description": value[1]}
                    for action, value in ACTION_GUIDANCE.items()
                },
            },
            headers=self.m.headers(),
        )

    def validation_rejection(self, value, message):
        """Mark only requests rejected before queuing and without a prior job.

        An old request replayed after validation rules change may already exist.
        Retain the uncertain-result UI in that case rather than invite a new ID.
        """
        headers = self.m.headers()
        try:
            identifier = str(UUID(value["request_id"]))
        except (ValueError, TypeError, KeyError):
            no_prior_job = True
        else:
            try:
                self.m.store.job(identifier)
            except KeyError:
                no_prior_job = True
            else:
                no_prior_job = False
        if no_prior_job:
            headers["X-NorthGate-Request-Outcome"] = "rejected-before-queue"
        return web.HTTPBadRequest(text=message, headers=headers)

    async def action(self, request):
        endpoint, principal, device = await self.m.context(request, online=True)
        value = await self.m.body(request)
        self.m.csrf(request, principal, endpoint, value.get("csrf"))
        action = value.get("action")
        if action == "cancel":
            job = self.m.store.job(str(UUID(value["job"])))
            if (
                job["endpoint"] != str(endpoint)
                or job["identity"] != str(device.identity_id)
                or job["subject"] != principal.subject
                or not job["action"].startswith("tool.")
            ):
                raise web.HTTPForbidden()
            await self.m.gateway.audit(
                principal, endpoint, "tools.job.cancelled", UUID(job["id"])
            )
            self.m.store.cancel(job["id"])
            return web.json_response({"job": job["id"]}, headers=self.m.headers())
        if action not in {
            "tool.list",
            "tool.verify",
            "tool.run",
            "tool.install",
            "tool.update",
            "tool.remove",
            "tool.artifact.read",
        }:
            raise web.HTTPBadRequest(text="Unsupported tool operation")
        permission = (
            "patch"
            if action in {"tool.install", "tool.update", "tool.remove"}
            else "manage"
        )
        if not self.m.gateway.operation._policy.permits(
            principal.subject, endpoint, permission
        ):
            raise web.HTTPForbidden(text="Tool operation is outside your permissions")
        try:
            if action in {"tool.install", "tool.update"}:
                entry = next(
                    (
                        e
                        for e in self.entries(
                            device.platform.value,
                            getattr(device, "architecture", "amd64"),
                        )
                        if e["manifest"]["id"] == value.get("tool_id")
                        and e["manifest"]["version"] == value.get("version")
                    ),
                    None,
                )
                if entry is None:
                    raise ValueError("Choose an approved tool version")
                params = {
                    "manifest": base64.b64encode(
                        manifest_bytes(entry["manifest"])
                    ).decode(),
                    "signature": entry["signature"],
                }
            elif action == "tool.run":
                params = {k: value.get(k) for k in ("tool_id", "profile", "inputs")}
                params["case_id"] = value.get("case_id", "")
            elif action == "tool.artifact.read":
                params = {k: value.get(k) for k in ("artifact_id", "offset", "size")}
                params["case_id"] = value.get("case_id", "")
            else:
                params = (
                    {"tool_id": value.get("tool_id")} if action != "tool.list" else {}
                )
            validate_action(action, params, device.platform.value)
        except (ValueError, TypeError, KeyError) as exc:
            raise self.validation_rejection(value, str(exc)) from None
        try:
            identifier = str(UUID(value["request_id"]))
        except (ValueError, TypeError, KeyError):
            raise self.validation_rejection(
                value, "A UUID request_id is required for safe retries"
            ) from None
        case_id = params.get("case_id", "")
        if case_id:
            if self.case_authorizer is None:
                raise web.HTTPConflict(text="Case authorization is not configured")
            await self.case_authorizer(principal, endpoint, case_id)
        await self.m.gateway.audit(
            principal, endpoint, "tools.job.requested." + action, UUID(identifier)
        )
        job = self.m.store.add(
            endpoint,
            device.identity_id,
            principal,
            action,
            params,
            request.headers["Authorization"],
            exercise="",
            seconds=900,
            identifier=identifier,
        )
        if case_id and self.case_linker:
            await self.case_linker(principal, endpoint, case_id, job)
        return web.json_response({"job": job}, status=202, headers=self.m.headers())
