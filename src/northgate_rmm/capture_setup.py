"""Session-authorized capture installation through the existing signed-job worker."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from uuid import UUID, uuid4

from aiohttp import web
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from northgate_rmm.capture_ui import signing_key
from northgate_rmm.management_protocol import TERMINAL, validate_action
from northgate_rmm.secure_files import regular_file_reference


class CaptureSetup:
    def __init__(self, management):
        self.m = management
        self.busy = set()
        self.tokens = {}

    def register(self, app):
        app.router.add_get("/remote/{endpoint}/capture/setup", self.status)
        app.router.add_post("/remote/{endpoint}/capture/setup", self.start)

    def release(self, platform, component="wxlfgar", installed=None):
        entries = []
        for path in sorted(self.m.extended.catalog.glob("*.json"))[:100]:
            with regular_file_reference(
                path, label="capture release", maximum_bytes=4096, private=True
            ) as ref:
                try:
                    entry = json.loads(ref.read_text())
                except (ValueError, UnicodeError):
                    continue
            if not isinstance(entry, dict):
                continue
            manifest = entry.get("manifest", {})
            if not isinstance(manifest, dict):
                continue
            if (
                manifest.get("component") != component
                or manifest.get("platform") != platform
            ):
                continue
            version = manifest.get("version", "")
            if not isinstance(version, str):
                continue
            match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-lab\.(\d+))?", version)
            if not match or (installed and version != installed):
                continue
            if not isinstance(manifest.get("sha256"), str) or not re.fullmatch(
                r"[a-f0-9]{64}", manifest["sha256"]
            ):
                continue
            if not all(isinstance(entry.get(k), str) for k in ("url", "signature")):
                continue
            entries.append(
                (
                    tuple(
                        int(x) if x is not None else 2147483647 for x in match.groups()
                    ),
                    entry,
                )
            )
        return max(entries, key=lambda item: item[0])[1] if entries else None

    def current(self, endpoint, identity, subject):
        return next(
            (
                j
                for j in self.m.store.list(endpoint)
                if (
                    j["action"] == "capture.install"
                    or j.get("exercise") == "capture-setup-worker"
                )
                and j["identity"] == str(identity)
                and j["subject"] == subject
            ),
            None,
        )

    async def status(self, request):
        endpoint, p, e = await self.m.context(request)
        permitted = self.m.gateway.operation._policy.permits(
            p.subject, endpoint, "patch"
        )
        worker = self.m.store.worker(endpoint)
        ready = worker.get("ready", False) and worker.get("identity") == str(
            e.identity_id
        )
        capable = self.worker_release(e.platform.value, worker) is None and (
            worker.get("capabilities", {})
            .get("features", {})
            .get("capture_installer", False)
        )
        installed = worker.get("capabilities", {}).get("versions", {}).get("wxlfgar")
        release = (
            self.release(
                e.platform.value,
                installed=installed
                if worker.get("capabilities", {}).get("capture_installed")
                else None,
            )
            if capable
            else self.worker_release(e.platform.value, worker)
        )
        job = self.current(endpoint, e.identity_id, p.subject)
        active = job is not None and job["state"] not in TERMINAL
        now = time.time()
        self.m.forms = {k: v for k, v in self.m.forms.items() if v[3] > now}
        self.tokens = {k: v for k, v in self.tokens.items() if v in self.m.forms}
        token = self.tokens.get((p.subject, p.session_id, str(endpoint)))
        if token and self.m.forms[token][3] <= now + 30:
            self.m.forms.pop(token, None)
            token = None
        if token is None:
            if len(self.m.forms) >= 128:
                raise web.HTTPTooManyRequests(text="Too many open management pages")
            token = secrets.token_urlsafe(32)
            self.m.forms[token] = (
                p.subject,
                p.session_id,
                str(endpoint),
                min(now + 1800, p.expires_at.timestamp()),
            )
            self.tokens[(p.subject, p.session_id, str(endpoint))] = token
        reason = (
            "Installation permission is required."
            if not permitted
            else "The management worker is offline."
            if not ready
            else "No approved worker upgrade is available in the package catalog."
            if not capable and not release
            else "No approved Wxlfgar package is available for this platform."
            if not release
            else "Installation is running."
            if active
            else "Ready to install or check dependencies."
            if capable
            else "Update the management worker first, then install the capture tools."
        )
        return web.json_response(
            dict(
                csrf=token,
                available=bool(permitted and ready and release and not active),
                reason=reason,
                job=job,
                version=release["manifest"]["version"] if release else None,
                mode="install" if capable else "worker",
            ),
            headers=self.m.headers(),
        )

    async def start(self, request):
        endpoint, p, e = await self.m.context(request, online=True)
        value = await self.m.body(request)
        self.m.csrf(request, p, endpoint, value.get("csrf"))
        if not self.m.gateway.operation._policy.permits(p.subject, endpoint, "patch"):
            raise web.HTTPForbidden(text="Installation permission is required")
        worker = self.m.store.worker(endpoint)
        if not worker.get("ready") or worker.get("identity") != str(e.identity_id):
            raise web.HTTPConflict(
                text="An online worker with capture installation support is required"
            )
        old = self.current(endpoint, e.identity_id, p.subject)
        if old and old["state"] not in TERMINAL:
            return web.json_response({"job": old["id"]}, headers=self.m.headers())
        if endpoint in self.busy or any(
            (
                j["action"] == "capture.install"
                or j.get("exercise") == "capture-setup-worker"
            )
            and j["identity"] == str(e.identity_id)
            and j["state"] not in TERMINAL
            for j in self.m.store.list(endpoint)
        ):
            raise web.HTTPConflict(text="Capture installation is already running")
        capable = self.worker_release(e.platform.value, worker) is None and (
            worker.get("capabilities", {}).get("features", {}).get("capture_installer")
        )
        installed = worker.get("capabilities", {}).get("versions", {}).get("wxlfgar")
        entry = (
            self.release(
                e.platform.value,
                installed=installed
                if worker.get("capabilities", {}).get("capture_installed")
                else None,
            )
            if capable
            else self.worker_release(e.platform.value, worker)
        )
        if entry is None:
            raise web.HTTPConflict(text="No approved capture package is available")
        params = {k: entry["manifest"][k] for k in ("sha256", "version")}
        params.update(
            url=entry["url"],
            signature=entry["signature"],
            public_key=base64.b64encode(
                signing_key(self.m.gateway.key)
                .public_key()
                .public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
        )
        operation = "capture.install"
        if not capable:
            operation = "update.install"
            params.pop("public_key")
            params["component"] = "worker"
        validate_action(operation, params, e.platform.value)
        # Consume before yielding so duplicate submissions cannot dispatch twice.
        self.m.forms.pop(value["csrf"])
        identifier = str(uuid4())
        self.busy.add(endpoint)
        try:
            await self.m.gateway.audit(
                p,
                endpoint,
                "management.job.requested." + operation,
                UUID(identifier),
            )
            job = self.m.store.add(
                endpoint,
                e.identity_id,
                p,
                operation,
                params,
                request.headers["Authorization"],
                exercise="capture-setup-worker" if not capable else "",
                seconds=900,
                identifier=identifier,
            )
        finally:
            self.busy.discard(endpoint)
        return web.json_response({"job": job}, status=202, headers=self.m.headers())

    def worker_release(self, platform, worker):
        entry = self.release(platform, "worker")
        if entry is None:
            return None
        current = worker.get("capabilities", {}).get("version", "")

        def parts(value):
            match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-lab\.(\d+))?", value)
            return (
                tuple(int(x) if x is not None else 2147483647 for x in match.groups())
                if match
                else ()
            )

        return (
            entry
            if parts(current)
            and parts(entry["manifest"]["version"]) > parts(current)
            and parts(entry["manifest"]["version"]) >= (1, 1, 0, 4)
            else None
        )
