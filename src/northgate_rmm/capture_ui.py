"""RMM network capture: signed jobs, human-session leases and verified artifacts."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from uuid import UUID, uuid4

from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from northgate_rmm.capture_store import CaptureStore
from northgate_rmm.capture_transport import ARTIFACTS, request_tool
from northgate_rmm.remote_workspace import frame_response

PRESETS = {
    "all": "All traffic",
    "dns": "DNS",
    "dhcp": "DHCP",
    "web": "Web ports (80/443)",
    "smb": "SMB",
    "icmp": "ICMP / ICMPv6",
}
TERMINAL = {"completed", "stopped", "expired", "failed", "interrupted"}
STATES = TERMINAL | {"capturing", "analyzing", "stopping"}


def signing_key(key: bytes):
    return Ed25519PrivateKey.from_private_bytes(
        hmac.digest(key, b"northgate-wxlfgar-signing-v1", "sha256")
    )


def validate_job(value, job_id, endpoint, identity):
    if (
        not isinstance(value, dict)
        or value.get("id") != str(job_id)
        or value.get("endpoint_id") != str(endpoint)
        or value.get("identity_id") != str(identity)
        or not isinstance(value.get("state"), str)
        or value.get("state") not in STATES
    ):
        raise ValueError("Invalid capture job response")
    if len(json.dumps(value, allow_nan=False)) > 2 * 1024 * 1024:
        raise ValueError("Capture response exceeds limit")
    artifacts = value.get("artifacts", [])
    if not isinstance(artifacts, list) or len(artifacts) > 4:
        raise ValueError("Invalid capture artifacts")
    names = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or not isinstance(artifact.get("name"), str)
            or artifact["name"] not in ARTIFACTS
            or artifact["name"] in names
            or type(artifact.get("size")) is not int
            or not 0 <= artifact["size"] <= 33 * 1024 * 1024
            or not isinstance(artifact.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"])
        ):
            raise ValueError("Invalid capture artifact manifest")
        names.add(artifact["name"])
    report = value.get("report")
    if report is not None:
        if not isinstance(report, dict):
            raise ValueError("Invalid capture report")
        for field, limit in (("flows", 512), ("findings", 256), ("assets", 256)):
            rows = report.get(field, [])
            if (
                not isinstance(rows, list)
                or len(rows) > limit
                or any(not isinstance(row, dict) for row in rows)
            ):
                raise ValueError("Invalid capture report entries")
        warnings = report.get("warnings", [])
        if (
            not isinstance(warnings, list)
            or len(warnings) > 32
            or any(not isinstance(w, str) for w in warnings)
        ):
            raise ValueError("Invalid capture warnings")
        for asset in report.get("assets", []):
            if any(
                not isinstance(asset.get(field, []), list)
                for field in ("roles", "macs", "vlans")
            ):
                raise ValueError("Invalid infrastructure asset")
            if len(asset.get("roles", [])) > 17 or any(
                not isinstance(role, dict) for role in asset.get("roles", [])
            ):
                raise ValueError("Invalid infrastructure roles")
    return value


class CaptureUI:
    def __init__(self, gateway, store: CaptureStore, runner=request_tool):
        self.gateway, self.store, self.runner = gateway, store, runner
        self.key = signing_key(gateway.key)
        self.forms = {}
        self.leases = {}
        self.busy = set()
        self.downloads = asyncio.Semaphore(2)
        self.slots = asyncio.Semaphore(4)

    def register(self, app):
        app.router.add_get("/remote/{endpoint}/capture", self.page)
        app.router.add_post("/remote/{endpoint}/capture", self.action)
        app.router.add_get("/remote/{endpoint}/capture/state", self.state)
        app.router.add_post("/remote/{endpoint}/capture/lease", self.lease)
        app.router.add_get("/remote/{endpoint}/capture/config", self.configuration)
        app.router.add_get(
            "/remote/{endpoint}/capture/file/{job}/{artifact}", self.download
        )

    async def context(self, request, online=False):
        try:
            endpoint = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        principal = await self.gateway.principal(
            request, endpoint, require_online=online
        )
        target, parameters = self.gateway.targets[endpoint]
        device = await asyncio.to_thread(
            self.gateway.operation._store.get_endpoint, endpoint
        )
        return endpoint, principal, target, parameters, device.platform.value

    def envelope(self, target, principal, action, job_id=None, **fields):
        now = int(time.time())
        claims = {
            "schema": 1,
            "endpoint_id": str(target.endpoint_id),
            "identity_id": str(target.identity_id),
            "subject": principal.subject,
            "session_id": principal.session_id,
            "nonce": str(uuid4()),
            "action": action,
            "job_id": str(job_id or UUID(int=0)),
            "issued": now,
            "expires": now + 45,
            **fields,
        }
        payload = json.dumps(claims, separators=(",", ":")).encode()
        return {
            "payload": base64.b64encode(payload).decode(),
            "signature": base64.b64encode(
                self.key.sign(b"NorthGate-Wxlfgar-v1\0" + payload)
            ).decode(),
        }

    async def rpc(
        self,
        target,
        parameters,
        platform,
        principal,
        action,
        job_id=None,
        destination=None,
        request=None,
        **fields,
    ):
        async with asyncio.timeout(185):
            async with self.slots:
                if request is None:
                    raise ValueError("Authenticated request required")
                current = await self.gateway.principal(request, target.endpoint_id)
                if (current.subject, current.session_id) != (
                    principal.subject,
                    principal.session_id,
                ):
                    raise web.HTTPForbidden()
                envelope = self.envelope(target, principal, action, job_id, **fields)
                return await self.runner(
                    target, parameters, platform, envelope, destination
                )

    def nonce(self, principal, endpoint):
        now = time.time()
        self.forms = {k: v for k, v in self.forms.items() if v[3] > now}
        self.leases = {k: v for k, v in self.leases.items() if v[4] > now}
        if len(self.forms) >= 256 or len(self.leases) >= 256:
            raise web.HTTPTooManyRequests()
        token = secrets.token_urlsafe(32)
        self.forms[token] = (
            principal.subject,
            principal.session_id,
            endpoint,
            now + 600,
        )
        return token

    def origin(self, request):
        if request.headers.get("Origin") != self.gateway.origin:
            raise web.HTTPForbidden()
        if request.content_length is not None and request.content_length > 8192:
            raise web.HTTPRequestEntityTooLarge(
                max_size=8192, actual_size=request.content_length
            )

    def row(self, endpoint, target, principal, job_id):
        try:
            job_id = str(UUID(str(job_id)))
        except ValueError:
            raise web.HTTPNotFound() from None
        row = self.store.get(endpoint, target.identity_id, principal.subject, job_id)
        if not row:
            raise web.HTTPNotFound()
        return row

    async def configuration(self, request):
        endpoint, principal, target, _params, platform = await self.context(request)
        value = {
            "endpoint_id": str(endpoint),
            "identity_id": str(target.identity_id),
            "public_key": base64.b64encode(
                self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
            "dumpcap": r"C:\Program Files\Wireshark\dumpcap.exe"
            if platform == "windows"
            else "/usr/bin/dumpcap",
            "root": r"C:\ProgramData\NorthGateWxlfgar\state"
            if platform == "windows"
            else "/var/lib/northgate-wxlfgar",
        }
        await self.gateway.audit(
            principal, endpoint, "capture.configuration.exported", uuid4()
        )
        return web.json_response(
            value,
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": 'attachment; filename="wxlfgar-config.json"',
            },
        )

    async def action(self, request):
        endpoint, principal, target, params, platform = await self.context(
            request, online=True
        )
        self.origin(request)
        fields = await request.post()
        token = self.forms.pop(str(fields.get("nonce", "")), None)
        if (
            not token
            or token[:3] != (principal.subject, principal.session_id, endpoint)
            or token[3] <= time.time()
        ):
            raise web.HTTPForbidden(text="Form expired; refresh the capture page")
        if endpoint in self.busy:
            raise web.HTTPConflict(text="Another capture operation is in progress")
        self.busy.add(endpoint)
        try:
            action = str(fields.get("action", ""))
            if action == "start":
                job_id = uuid4()
                try:
                    seconds, size, snaplen = (
                        int(fields["seconds"]),
                        int(fields["size"]) * 1024 * 1024,
                        int(fields["snaplen"]),
                    )
                    interface = str(int(fields["interface"]))
                    preset = str(fields["preset"])
                    host = str(fields.get("host", "")).strip()
                    if host:
                        host = str(ipaddress.ip_address(host))
                    port = int(fields.get("port") or 0)
                    if not 0 <= port <= 65535:
                        raise ValueError("Invalid port")
                except (KeyError, ValueError):
                    raise web.HTTPBadRequest(text="Invalid capture options") from None
                if (
                    not 5 <= seconds <= 300
                    or not 1 <= int(interface) <= 256
                    or not 1024 * 1024 <= size <= 32 * 1024 * 1024
                    or not 96 <= snaplen <= 65535
                    or preset not in PRESETS
                ):
                    raise web.HTTPBadRequest(text="Capture options exceed limits")
                if (
                    len(
                        self.store.history(
                            endpoint, target.identity_id, principal.subject
                        )
                    )
                    >= 20
                ):
                    raise web.HTTPConflict(
                        text="Delete an older capture before starting another"
                    )
                await self.gateway.audit(
                    principal, endpoint, "capture.start.requested", job_id
                )
                # Reserve history before dispatch: a lost reply must not orphan
                # an accepted endpoint job or bypass the server storage limit.
                self.store.add(
                    endpoint,
                    target.identity_id,
                    principal,
                    {
                        "id": str(job_id),
                        "endpoint_id": str(endpoint),
                        "identity_id": str(target.identity_id),
                        "state": "starting",
                        "reason": (
                            "Start pending; capture stops unless authorization renews."
                        ),
                        "started": datetime.now(UTC).isoformat(),
                        "preset": preset,
                        "max_bytes": size,
                        "artifacts": [],
                    },
                )
                job = await self.rpc(
                    target,
                    params,
                    platform,
                    principal,
                    "start",
                    job_id,
                    interface=interface,
                    preset=preset,
                    seconds=seconds,
                    max_bytes=size,
                    request=request,
                    snaplen=snaplen,
                    host=host,
                    port=port,
                )
                validate_job(job, job_id, endpoint, target.identity_id)
                self.store.update(job)
            elif action in {"stop", "delete"}:
                row = self.row(endpoint, target, principal, fields.get("job", ""))
                job_id = UUID(row["id"])
                await self.gateway.audit(
                    principal, endpoint, "capture." + action + ".requested", job_id
                )
                job = await self.rpc(
                    target, params, platform, principal, action, job_id, request=request
                )
                if action == "delete":
                    if job.get("deleted") is not True:
                        raise ValueError("Deletion was not confirmed")
                    self.store.delete(str(job_id))
                else:
                    self.store.update(
                        validate_job(job, job_id, endpoint, target.identity_id)
                    )
            else:
                raise web.HTTPBadRequest(text="Unknown action")
            await self.gateway.audit(
                principal, endpoint, "capture." + action + ".completed", job_id
            )
            location = f"/remote/{endpoint}/capture"
            if action != "delete":
                location += "?job=" + str(job_id)
            raise web.HTTPSeeOther(location=location)
        except (ValueError, OSError, TimeoutError):
            raise web.HTTPBadGateway(
                text="Capture operation could not be confirmed. Refresh history before retrying; unrenewed captures stop automatically."  # noqa: E501 - HTML and user-facing literals
            ) from None
        finally:
            self.busy.discard(endpoint)

    async def state(self, request):
        endpoint, principal, target, params, platform = await self.context(
            request, online=True
        )
        row = self.row(endpoint, target, principal, request.query.get("job", ""))
        try:
            value = await self.rpc(
                target,
                params,
                platform,
                principal,
                "status",
                row["id"],
                request=request,
            )
            self.store.update(
                validate_job(value, row["id"], endpoint, target.identity_id)
            )
        except (ValueError, OSError, TimeoutError):
            raise web.HTTPServiceUnavailable(
                text="Capture status unavailable"
            ) from None
        return web.json_response(value, headers={"Cache-Control": "no-store"})

    async def lease(self, request):
        endpoint, principal, target, params, platform = await self.context(
            request, online=True
        )
        self.origin(request)
        data = await request.post()
        value = self.leases.get(str(data.get("token", "")))
        if (
            not value
            or value[:3] != (principal.subject, principal.session_id, endpoint)
            or value[4] <= time.time()
        ):
            raise web.HTTPForbidden()
        row = self.row(endpoint, target, principal, value[3])
        if row["session"] != principal.session_id:
            raise web.HTTPForbidden()
        try:
            result = await self.rpc(
                target,
                params,
                platform,
                principal,
                "keepalive",
                value[3],
                request=request,
            )
            self.store.update(
                validate_job(result, value[3], endpoint, target.identity_id)
            )
        except (ValueError, OSError, TimeoutError):
            raise web.HTTPConflict(text="Capture lease ended") from None
        return web.json_response(
            {"renewed": True}, headers={"Cache-Control": "no-store"}
        )

    async def download(self, request):
        endpoint, principal, target, params, platform = await self.context(request)
        row = self.row(endpoint, target, principal, request.match_info["job"])
        name = request.match_info["artifact"]
        if name not in ARTIFACTS:
            raise web.HTTPNotFound()
        expected = next(
            (
                a
                for a in json.loads(row["payload"]).get("artifacts", [])
                if a.get("name") == name
            ),
            None,
        )
        if expected is None:
            raise web.HTTPNotFound()
        async with self.downloads:
            path = self.store.root / (str(uuid4()) + ".download")
            try:
                await self.gateway.principal(request, endpoint)
                await self.gateway.audit(
                    principal, endpoint, "capture.artifact.requested", UUID(row["id"])
                )
                actual = await self.rpc(
                    target,
                    params,
                    platform,
                    principal,
                    "artifact",
                    row["id"],
                    destination=path,
                    request=request,
                    artifact=name,
                )
                if actual != expected:
                    raise ValueError("Artifact differs from recorded manifest")
                # Revalidate before releasing the verified bytes to the browser.
                await self.gateway.principal(request, endpoint)
                await self.gateway.audit(
                    principal, endpoint, "capture.artifact.verified", UUID(row["id"])
                )
                response = web.StreamResponse(
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Content-Disposition": (
                            f'attachment; filename="{row["id"]}-{name}"'
                        ),
                        "Cache-Control": "no-store",
                        "X-Content-Type-Options": "nosniff",
                        "Content-Length": str(actual["size"]),
                    }
                )
                await response.prepare(request)
                with path.open("rb") as source:
                    while chunk := source.read(65536):
                        await response.write(chunk)
                await response.write_eof()
                return response
            except (ValueError, OSError, TimeoutError):
                raise web.HTTPBadGateway(
                    text="Artifact could not be verified or retrieved"
                ) from None
            finally:
                path.unlink(missing_ok=True)

    async def page(self, request):
        endpoint, principal, target, params, platform = await self.context(request)
        base = f"/remote/{endpoint}/capture"
        token = self.nonce(principal, endpoint)
        capability = None
        try:
            await self.gateway.principal(request, endpoint)
            capability = await self.rpc(
                target, params, platform, principal, "capabilities", request=request
            )
            if not isinstance(capability, dict):
                raise ValueError("Invalid capability response")
            interfaces = capability.get("interfaces", [])
            if (
                not isinstance(interfaces, list)
                or len(interfaces) > 256
                or any(not isinstance(item, dict) for item in interfaces)
            ):
                raise ValueError("Invalid interface response")
        except (web.HTTPException, ValueError, OSError, TimeoutError):
            capability = None
        ready = isinstance(capability, dict) and capability.get("state") == "ready"
        interface_options = ""
        if ready:
            for item in capability.get("interfaces", [])[:256]:
                capture_name = str(item.get("CaptureName", ""))
                if capture_name.isdigit() and 1 <= int(capture_name) <= 256:
                    interface_options += f'<option value="{capture_name}">{escape(str(item.get("Name", capture_name)))}</option>'  # noqa: E501 - HTML and user-facing literals
        content = f'<a href="/endpoints/{endpoint}">← Device profile</a><h1>Network capture</h1><p>Wxlfgar · {escape(platform)} · Capture is off until you start a job.</p>'  # noqa: E501 - HTML and user-facing literals
        content += (
            f'<p><a href="{base}/config">Download enrollment tool configuration</a></p>'
        )
        if ready and interface_options:
            content += f'<form method="post"><input type="hidden" name="nonce" value="{token}"><input type="hidden" name="action" value="start"><label>Interface <select name="interface">{interface_options}</select></label> <label>Preset <select name="preset">'  # noqa: E501 - HTML and user-facing literals
            content += "".join(
                f'<option value="{k}">{v}</option>' for k, v in PRESETS.items()
            )
            content += '</select></label> <label>Seconds <input name="seconds" type="number" value="60" min="5" max="300" required></label> <label>Maximum MiB <input name="size" type="number" value="16" min="1" max="32" required></label> <label>Packet bytes <select name="snaplen"><option value="1536">1536 (standard packets)</option><option value="256">256 (reduced analysis)</option><option value="65535">Full packet</option></select></label> <label>Host IP (optional) <input name="host" maxlength="45"></label> <label>Port (optional) <input name="port" type="number" min="1" max="65535"></label> <button>Start capture</button></form>'  # noqa: E501 - HTML and user-facing literals
        else:
            content += "<p>Capture is unavailable. Install the approved Wxlfgar package and capture dependency, verify permissions and confirm the endpoint is online.</p>"  # noqa: E501 - HTML and user-facing literals
        content += "<p>Keep this page open to renew capture authorization. Stop, session expiry or a lost connection ends capture after at most 45 seconds without renewal. Maximum duration is five minutes. Files expire on the endpoint after seven days.</p>"  # noqa: E501 - HTML and user-facing literals
        history = self.store.history(endpoint, target.identity_id, principal.subject)
        current = None
        if request.query.get("job"):
            current = self.row(endpoint, target, principal, request.query["job"])
        elif history:
            current = history[0]
        lease_token = ""
        if current:
            job = json.loads(current["payload"])
            job_id = current["id"]
            content += f'<h2>Capture {escape(job_id)}</h2><p id="capture-status">{escape(str(job.get("state", "unknown")))}</p><p id="capture-counters"></p><p id="capture-message"></p><div id="capture-results"></div><div id="capture-files"></div>'  # noqa: E501 - HTML and user-facing literals
            action_token = self.nonce(principal, endpoint)
            content += f'<form method="post"><input type="hidden" name="nonce" value="{action_token}"><input type="hidden" name="job" value="{job_id}"><button name="action" value="stop">Stop capture</button> <button name="action" value="delete">Delete capture and artifacts</button></form>'  # noqa: E501 - HTML and user-facing literals
            if (
                current["session"] == principal.session_id
                and job.get("state") not in TERMINAL
            ):
                lease_token = secrets.token_urlsafe(32)
                self.leases[lease_token] = (
                    principal.subject,
                    principal.session_id,
                    endpoint,
                    job_id,
                    time.time() + 600,
                )
        content += "<h2>History</h2><table><thead><tr><th>Capture</th><th>State</th><th>Preset</th><th>Bytes</th></tr></thead><tbody>"  # noqa: E501 - HTML and user-facing literals
        for row in history:
            value = json.loads(row["payload"])
            content += f'<tr><td><a href="{base}?job={row["id"]}">{row["id"][:8]}</a></td><td>{escape(str(value.get("state", "unknown")))}</td><td>{escape(str(value.get("preset", "")))}</td><td>{escape(str(value.get("bytes", 0)))}</td></tr>'  # noqa: E501 - HTML and user-facing literals
        content += "</tbody></table><p>Traffic shown belongs to the selected interface. Encrypted payloads are not decrypted.</p>"  # noqa: E501 - HTML and user-facing literals
        response = frame_response(content)
        if current:
            script = (
                SCRIPT.replace("__BASE__", json.dumps(base))
                .replace("__JOB__", json.dumps(current["id"]))
                .replace("__TOKEN__", json.dumps(lease_token))
                .replace("__INITIAL__", script_json(json.loads(current["payload"])))
            )
            response.text = response.text.replace(
                "</body>", f"<script>{script}</script></body>"
            )
            digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
            response.headers["Content-Security-Policy"] += (
                f"; script-src 'sha256-{digest}'; connect-src 'self'"
            )
        return response


def script_json(value):
    # HTML parses script end tags before JavaScript parses JSON string literals.
    return json.dumps(value, ensure_ascii=True, allow_nan=False).replace("<", r"\u003c")


SCRIPT = Path(__file__).with_name("capture.js").read_text(encoding="utf-8")
