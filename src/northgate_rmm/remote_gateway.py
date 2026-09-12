"""Private Guacamole adapter with endpoint-bound, revalidated remote leases.

The established Guacamole web application handles desktop protocols. This
adapter owns RMM authorization and never accepts browser-selected destinations.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import re
import secrets
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape
from urllib.parse import urlencode
from uuid import UUID, uuid4

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from northgate_rmm.errors import AuthorizationError
from northgate_rmm.operator_api import OperatorApplication, OperatorPrincipal
from northgate_rmm.remote_policy import RemoteLease, RemoteTarget, authorize_remote
from northgate_rmm.remote_sessions import RemoteSessionStore
from northgate_rmm.remote_workspace import UPLOAD_REQUEST_LIMIT, frame_response

COOKIE = "__Secure-rmm-remote"
RECHECK_SECONDS = 30
MAX_LEASES = 64
MAX_BODY = 65536
UPSTREAM = "http://127.0.0.1:8088"


def encrypt_connection(key: bytes, value: dict[str, object]) -> str:
    """Encode Apache Guacamole's documented encrypted JSON auth format."""
    if len(key) != 16:
        raise ValueError("Guacamole JSON key must be 128 bits")
    plaintext = json.dumps(value, separators=(",", ":")).encode()
    signed = hmac.digest(key, plaintext, "sha256") + plaintext
    padder = padding.PKCS7(128).padder()
    padded = padder.update(signed) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()


@dataclass
class LeaseState:
    lease: RemoteLease
    websocket: web.WebSocketResponse | None = None
    auth_data: str = ""
    auth_token: str = ""
    authorization: str = ""
    method: str = ""
    case_id: str = ""
    outcome: str = "transport_closed"
    secret_id: str = ""


class RemoteGateway:
    def __init__(
        self,
        operation: OperatorApplication,
        targets: dict[UUID, tuple[RemoteTarget, dict[str, str]]],
        key: bytes,
        origin: str,
        *,
        receipt_store: RemoteSessionStore | None = None,
    ) -> None:
        if not origin.startswith("https://") or origin.endswith("/"):
            raise ValueError("remote origin must be an exact HTTPS origin")
        self.operation = operation
        self.targets = targets
        self.methods = getattr(
            targets,
            "methods",
            {
                endpoint: {target.protocol: (target, params)}
                for endpoint, (target, params) in targets.items()
            },
        )
        self.receipt_store = receipt_store or RemoteSessionStore()
        self.secret_resolver = None
        self.secret_authorizer = None
        self.legacy_credential_guard = None
        self.case_authorizer = None
        self.key = key
        self.origin = origin
        self.leases: dict[str, LeaseState] = {}
        self.forms: dict[str, tuple] = {}
        self.client: ClientSession | None = None
        # The verifier admits four connections per workload identity. Leave room
        # for the operator service while browser assets arrive concurrently.
        self._verification_slots = asyncio.Semaphore(2)
        self._start_lock = asyncio.Lock()

    async def principal(
        self,
        request: web.Request,
        endpoint_id: UUID,
        authorization: str | None = None,
        *,
        require_online: bool = True,
        permission: str = "remote",
    ) -> OperatorPrincipal:
        if request.remote not in {"127.0.0.1", "::1"}:
            raise web.HTTPForbidden()
        if endpoint_id not in self.targets:
            raise web.HTTPNotFound()
        authorization = authorization or request.headers.get("Authorization")

        def verify() -> OperatorPrincipal:
            now = datetime.now(UTC)
            principal = self.operation._authenticate(
                authorization, now=now, correlation_id=uuid4()
            )
            endpoint = self.operation._store.get_endpoint(endpoint_id)
            status = self.operation._store.endpoint_status(endpoint_id, now=now)
            authorize_remote(
                principal,
                self.operation._policy,
                self.targets[endpoint_id][0],
                status,
                endpoint.identity_id,
                now=now,
                require_online=require_online,
                permission=permission,
            )
            return principal

        try:
            async with asyncio.timeout(10):
                await self._verification_slots.acquire()
            task = asyncio.create_task(asyncio.to_thread(verify))

            def completed(result) -> None:
                self._verification_slots.release()
                if not result.cancelled():
                    result.exception()

            task.add_done_callback(completed)
            # A cancelled HTTP request must not free a still-running TLS slot.
            return await asyncio.shield(task)
        except TimeoutError:
            raise web.HTTPServiceUnavailable(text="Remote verification busy") from None
        except Exception:
            raise web.HTTPForbidden(
                text="Remote access unavailable or unauthorized"
            ) from None

    async def audit(
        self,
        principal: OperatorPrincipal,
        endpoint_id: UUID,
        action: str,
        correlation: UUID,
    ) -> None:
        await asyncio.to_thread(
            self.operation._audit,
            principal,
            subject=f"endpoint:{endpoint_id}",
            action=action,
            decision="accepted",
            reason="authorized lab remote access",
            correlation_id=correlation,
            now=datetime.now(UTC),
        )

    def purge(self) -> None:
        now = datetime.now(UTC)
        self.forms = {k: v for k, v in self.forms.items() if v[3] > now}
        for key, state in tuple(self.leases.items()):
            if state.lease.expires_at <= now and state.websocket is None:
                self.receipt_store.update(
                    state.lease.session_id,
                    status="expired",
                    outcome="authorization_expired",
                )
                self.leases.pop(key, None)

    def method_target(self, endpoint, method):
        try:
            return self.methods[endpoint][method]
        except KeyError:
            raise web.HTTPNotFound(
                text="This remote method is not configured for this enrollment"
            ) from None

    async def sessions(self, request):
        try:
            endpoint = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        await self.principal(request, endpoint, require_online=False)
        self.purge()
        target = self.targets[endpoint][0]
        return web.json_response(
            {
                "methods": sorted(self.methods[endpoint]),
                "sessions": self.receipt_store.list(endpoint, target.identity_id),
            },
            headers={"Cache-Control": "no-store"},
        )

    async def desktop_file(self, request: web.Request) -> web.Response:
        try:
            endpoint_id = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        principal = await self.principal(request, endpoint_id)
        # Keep the existing native file on SSH-only Windows configurations.
        target, parameters = self.methods[endpoint_id].get(
            "rdp", self.targets[endpoint_id]
        )
        username = parameters.get("username", "")
        domain = parameters.get("domain", "")
        if domain:
            username = domain + "\\" + username
        if not re.fullmatch(r"[A-Za-z0-9_.\\@-]{1,128}", username):
            raise web.HTTPServiceUnavailable()
        await self.audit(
            principal, endpoint_id, "remote.native_rdp.file_issued", uuid4()
        )
        content = "\r\n".join(
            [
                f"full address:s:{target.address}:3389",
                f"username:s:{username}",
                "prompt for credentials:i:0",
                "authentication level:i:2",
                "enablecredsspsupport:i:1",
                "redirectclipboard:i:0",
                "redirectprinters:i:0",
                "drivestoredirect:s:",
                "",
            ]
        )
        return web.Response(
            body=content.encode("utf-16"),
            headers={
                "Content-Type": "application/x-rdp",
                "Content-Disposition": f'attachment; filename="rmm-{endpoint_id}.rdp"',
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def landing(self, request: web.Request) -> web.Response:
        if request.method == "POST":
            async with self._start_lock:
                return await self._landing(request)
        return await self._landing(request)

    async def _landing(self, request: web.Request) -> web.Response:
        try:
            endpoint_id = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        principal = await self.principal(request, endpoint_id)
        method = (
            "rdp"
            if request.path.endswith("/desktop")
            else self.targets[endpoint_id][0].protocol
        )
        target, parameters = self.method_target(endpoint_id, method)
        label = (
            "Browser desktop" if request.path.endswith("/desktop") else "SSH terminal"
        )
        case_id = request.query.get("case_id", "")
        if case_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", case_id):
            raise web.HTTPBadRequest(text="Invalid case reference")
        if case_id:
            if self.case_authorizer is None:
                raise web.HTTPForbidden(
                    text="Case session authorization is unavailable"
                )
            await self.case_authorizer(principal, endpoint_id, case_id)
        self.purge()
        if request.method == "GET":
            if len(self.forms) >= 32:
                raise web.HTTPTooManyRequests()
            nonce = secrets.token_urlsafe(32)
            self.forms[nonce] = (
                principal.subject,
                principal.session_id,
                endpoint_id,
                datetime.now(UTC) + timedelta(minutes=5),
                method,
                case_id,
            )
            endpoint = await asyncio.to_thread(
                self.operation._store.get_endpoint, endpoint_id
            )
            content = (
                f'<a target="_top" href="/endpoints/{endpoint_id}">← Device profile</a>'
                f"<h1>Connect to {escape(endpoint.display_name)}</h1>"
                '<section class="panel"><div class="panel-heading"><div>'
                f"<h2>{label}</h2><p>Start a connection in your browser. "
                "Sessions end after one hour; "
                "device and sign-in access are checked throughout.</p>"
                "<p>Use Send a file in the remote workspace "
                "to upload into NorthGateRMM-Ops.</p>"
                f'<form method="post" action="{escape(request.path)}">'
                f'<input type="hidden" name="nonce" value="{nonce}">'
                f'<button class="button" type="submit">Connect {label}'
                "</button></form>"
                '<form method="post" action="/remote/end">'
                '<button class="button" type="submit">End current session</button>'
                "</form>"
                "</div></div></section>"
            )
            return frame_response(content)
        if request.headers.get("Origin") != self.origin:
            raise web.HTTPForbidden()
        form = await request.post()
        claim = self.forms.pop(str(form.get("nonce", "")), None)
        if claim is None or claim[:3] != (
            principal.subject,
            principal.session_id,
            endpoint_id,
        ):
            raise web.HTTPForbidden()
        if claim[3] <= datetime.now(UTC):
            raise web.HTTPForbidden()
        if claim[4] != method:
            raise web.HTTPForbidden()
        case_id = claim[5]
        if case_id:
            if self.case_authorizer is None:
                raise web.HTTPForbidden(
                    text="Case session authorization is unavailable"
                )
            await self.case_authorizer(principal, endpoint_id, case_id)
        if request.cookies.get(COOKIE, "") in self.leases:
            raise web.HTTPConflict(
                text="End the current browser remote session before starting another"
            )
        if len(self.leases) >= MAX_LEASES or any(
            state.lease.endpoint_id == endpoint_id for state in self.leases.values()
        ):
            raise web.HTTPConflict(
                text="A remote session already exists; close it or wait for expiry"
            )
        parameters = dict(parameters)
        secret_id = ""
        if self.secret_resolver:
            resolved = await self.secret_resolver(request, principal, target, method)
            secret_id = resolved.pop("__rmm_secret_id", "")
            if secret_id:
                for field in (
                    "username",
                    "password",
                    "domain",
                    "private-key",
                    "passphrase",
                ):
                    parameters.pop(field, None)
            parameters.update(resolved)
        principal = await self.principal(request, endpoint_id)
        if secret_id and self.secret_authorizer:
            await self.secret_authorizer(
                request, endpoint_id, secret_id, principal=principal
            )
        now = datetime.now(UTC)
        lease = RemoteLease(
            uuid4(),
            endpoint_id,
            target.identity_id,
            principal.subject,
            principal.session_id,
            now,
            now + timedelta(hours=1),
        )
        await self.audit(
            principal, endpoint_id, "remote.session.authorized", lease.session_id
        )
        # Credentials are encrypted for Guacamole, never placed in plaintext HTML.
        options = {
            **parameters,
            "hostname": target.address,
            "port": str(target.port),
            "disable-copy": "true",
            "disable-paste": "true",
            "enable-drive": "false",
            "enable-printing": "false",
            "enable-audio-input": "false",
            "disable-audio": "true",
            "enable-sftp": "false",
        }
        if method == "rdp":
            options.update(
                {
                    "security": parameters.get("security", "nla"),
                    "ignore-cert": "false",
                    "cert-tofu": "false",
                    "disable-auth": "false",
                }
            )
            if options["security"] not in {"nla", "nla-ext"}:
                raise web.HTTPServiceUnavailable(text="Browser RDP requires NLA")
        data = encrypt_connection(
            self.key,
            {
                "username": str(lease.session_id),
                "expires": int((now + timedelta(seconds=60)).timestamp() * 1000),
                "connections": {
                    (
                        "Browser Desktop"
                        if request.path.endswith("/desktop")
                        else "SSH Terminal"
                    ): {"protocol": target.protocol, "parameters": options}
                },
            },
        )
        cookie = secrets.token_urlsafe(32)
        self.receipt_store.create(lease, method, case_id)
        self.leases[cookie] = LeaseState(
            lease,
            auth_data=data,
            authorization=request.headers.get("Authorization", ""),
            method=method,
            case_id=case_id,
            secret_id=secret_id,
        )
        response = web.HTTPFound("/guacamole/?" + urlencode({"data": data}))
        response.set_cookie(
            COOKIE,
            cookie,
            secure=True,
            httponly=True,
            samesite="Strict",
            max_age=3600,
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "strict-origin"
        raise response

    async def checked_lease(
        self, request: web.Request, *, authorization: str | None = None
    ) -> tuple[LeaseState, OperatorPrincipal]:
        self.purge()
        state = self.leases.get(request.cookies.get(COOKIE, ""))
        if state is None:
            raise web.HTTPForbidden(text="Start remote access from the device profile")
        principal = await self.principal(
            request, state.lease.endpoint_id, authorization
        )
        try:
            state.lease.check(
                principal,
                self.method_target(state.lease.endpoint_id, state.method)[0]
                if state.method
                else self.targets[state.lease.endpoint_id][0],
                now=datetime.now(UTC),
            )
        except AuthorizationError:
            raise web.HTTPForbidden() from None
        state.authorization = authorization or request.headers.get("Authorization", "")
        if state.case_id:
            if self.case_authorizer is None:
                raise web.HTTPForbidden()
            await self.case_authorizer(
                principal, state.lease.endpoint_id, state.case_id
            )
        if state.secret_id:
            if self.secret_authorizer is None:
                raise web.HTTPForbidden()
            await self.secret_authorizer(
                request, state.lease.endpoint_id, state.secret_id, principal=principal
            )
        return state, principal

    async def keepalive(self, request: web.Request) -> web.Response:
        await self.checked_lease(request)
        return web.Response(status=204, headers={"Cache-Control": "no-store"})

    async def session_script(self, request: web.Request) -> web.Response:
        await self.checked_lease(request)
        script = (
            "setInterval(async()=>{try{const r=await fetch('/remote/keepalive',"
            "{credentials:'same-origin',cache:'no-store'});"
            "if(!r.ok)location.assign('/endpoints');}"
            "catch(e){location.assign('/endpoints');}},20000);"
        )
        return web.Response(
            text=script,
            content_type="application/javascript",
            headers={"Cache-Control": "no-store"},
        )

    async def proxy(self, request: web.Request) -> web.StreamResponse:
        state, principal = await self.checked_lease(request)
        if request.content_length and request.content_length > MAX_BODY:
            raise web.HTTPRequestEntityTooLarge(
                max_size=MAX_BODY, actual_size=request.content_length
            )
        if request.method not in {"GET", "POST", "DELETE"}:
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "POST", "DELETE"])
        if request.method != "GET" and request.headers.get("Origin") != self.origin:
            raise web.HTTPForbidden()
        if self.client is None:
            raise web.HTTPServiceUnavailable()
        if request.path.rstrip("/").endswith("/parameters"):
            raise web.HTTPForbidden(text="Connection credentials are managed by RMM")
        # HTTP polling tunnels have no owned stream to close on lease revocation.
        # Require the guarded WebSocket transport for both SSH and RDP.
        if request.path.rstrip("/").endswith("/tunnel"):
            raise web.HTTPForbidden(
                text="This gateway requires WebSocket remote transport"
            )
        if len(request.query.getall("token", [])) > 1:
            raise web.HTTPForbidden()
        tokens = [
            item
            for item in (
                request.query.get("token"),
                request.headers.get("Guacamole-Token"),
            )
            if item
        ]
        if len(set(tokens)) > 1:
            raise web.HTTPForbidden()
        token = tokens[0] if tokens else None
        if token and (
            not state.auth_token or not hmac.compare_digest(token, state.auth_token)
        ):
            raise web.HTTPForbidden()
        forwarded_body = None
        if request.path.endswith("/api/tokens") and request.method == "POST":
            fields = await request.post()
            if any(len(fields.getall(name)) != 1 for name in fields):
                raise web.HTTPForbidden()
            data = str(fields.get("data", ""))
            body_token = str(fields.get("token", ""))
            if state.auth_token:
                # Guacamole revalidates its token when Angular changes routes.
                # Forward only this lease's token, never replay the JSON ticket.
                if not body_token or not hmac.compare_digest(
                    body_token, state.auth_token
                ):
                    raise web.HTTPForbidden()
                forwarded_body = urlencode({"token": body_token}).encode()
            else:
                if (
                    not data
                    or not state.auth_data
                    or not hmac.compare_digest(data, state.auth_data)
                ):
                    raise web.HTTPForbidden()
                state.auth_data = ""
                # Ignore a stale token retained by Guacamole from an older lease.
                forwarded_body = urlencode({"data": data}).encode()
        if request.headers.get("Upgrade", "").lower() == "websocket":
            if (
                request.headers.get("Origin") != self.origin
                or state.websocket is not None
            ):
                raise web.HTTPForbidden()
            return await self.websocket(request, state, principal)
        # No arbitrary forward proxy: raw_path always starts at this fixed route.
        async with self.client.request(
            request.method,
            UPSTREAM + request.raw_path,
            data=(
                forwarded_body
                if forwarded_body is not None
                else (await request.read() or None)
            ),
            headers={
                **(
                    {"Content-Type": request.headers["Content-Type"]}
                    if "Content-Type" in request.headers
                    else {}
                ),
                **({"Guacamole-Token": token} if token else {}),
            },
            allow_redirects=False,
        ) as upstream:
            chunks = bytearray()
            async for chunk in upstream.content.iter_chunked(65536):
                chunks.extend(chunk)
                if len(chunks) > 8 * 1024 * 1024:
                    raise web.HTTPBadGateway()
            data = bytes(chunks)
            if request.path == "/guacamole/" and upstream.status == 200:
                data = data.replace(
                    b"</body>", b'<script src="/remote/session.js"></script></body>'
                )
            if (
                request.path.endswith("/api/tokens")
                and request.method == "POST"
                and upstream.status == 200
            ):
                state.auth_token = json.loads(data)["authToken"]
            headers = {
                "Cache-Control": "no-store",
                "Referrer-Policy": "strict-origin",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
            }
            for name in ("Content-Type",):
                if name in upstream.headers:
                    headers[name] = upstream.headers[name]
            return web.Response(body=data, status=upstream.status, headers=headers)

    async def end(self, request: web.Request) -> web.Response:
        if request.headers.get("Origin") != self.origin:
            raise web.HTTPForbidden()
        state, principal = await self.checked_lease(request)
        await self.audit(
            principal,
            state.lease.endpoint_id,
            "remote.session.end_requested",
            state.lease.session_id,
        )
        self.leases.pop(request.cookies.get(COOKIE, ""), None)
        state.outcome = "operator_disconnected"
        self.receipt_store.update(
            state.lease.session_id, status="closed", outcome=state.outcome
        )
        if state.websocket is not None:
            await state.websocket.close()
        response = web.HTTPFound(
            f"/remote/{state.lease.endpoint_id}"
            + ("/desktop" if state.method == "rdp" else "")
        )
        response.del_cookie(COOKIE, path="/")
        raise response

    async def websocket(
        self, request: web.Request, state: LeaseState, principal: OperatorPrincipal
    ) -> web.WebSocketResponse:
        if self.client is None:
            raise web.HTTPServiceUnavailable()
        browser = web.WebSocketResponse(
            protocols=("guacamole",), max_msg_size=MAX_BODY, heartbeat=20
        )
        # Reserve before awaiting to prevent two simultaneous desktop streams.
        state.websocket = browser
        state.outcome = "connection_failed"
        tasks: list[asyncio.Task[None]] = []
        try:
            async with self.client.ws_connect(
                UPSTREAM + request.raw_path,
                protocols=("guacamole",),
                max_msg_size=2 * 1024 * 1024,
            ) as upstream:
                await self.audit(
                    principal,
                    state.lease.endpoint_id,
                    "remote.session.started",
                    state.lease.session_id,
                )
                await browser.prepare(request)
                state.outcome = "transport_closed"
                self.receipt_store.update(
                    state.lease.session_id,
                    status="connected",
                    outcome="transport_connected",
                )

                async def forward(source, destination) -> None:
                    async for message in source:
                        if message.type == WSMsgType.TEXT:
                            await destination.send_str(message.data)
                        elif message.type == WSMsgType.BINARY:
                            await destination.send_bytes(message.data)
                        else:
                            break

                async def guard() -> None:
                    while True:
                        await asyncio.sleep(RECHECK_SECONDS)
                        try:
                            await self.checked_lease(
                                request, authorization=state.authorization
                            )
                        except Exception:
                            state.outcome = "authorization_expired"
                            raise

                tasks = [
                    asyncio.create_task(forward(browser, upstream)),
                    asyncio.create_task(forward(upstream, browser)),
                    asyncio.create_task(guard()),
                ]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await browser.close()
            self.receipt_store.update(
                state.lease.session_id, status="closed", outcome=state.outcome
            )
            self.leases.pop(request.cookies.get(COOKIE, ""), None)
            with suppress(Exception):
                await self.audit(
                    principal,
                    state.lease.endpoint_id,
                    "remote.session.closed",
                    state.lease.session_id,
                )
        return browser

    def application(self) -> web.Application:
        app = web.Application(
            client_max_size=max(UPLOAD_REQUEST_LIMIT, 32 * 1024 * 1024)
        )
        app.router.add_post("/remote/end", self.end)
        app.router.add_get("/remote/keepalive", self.keepalive)
        app.router.add_get("/remote/session.js", self.session_script)
        app.router.add_get("/remote/{endpoint}/desktop.rdp", self.desktop_file)
        app.router.add_get("/remote/{endpoint}/desktop", self.landing)
        app.router.add_post("/remote/{endpoint}/desktop", self.landing)
        app.router.add_get("/remote/{endpoint}/sessions", self.sessions)
        app.router.add_get("/remote/{endpoint}", self.landing)
        app.router.add_post("/remote/{endpoint}", self.landing)
        app.router.add_route("*", "/guacamole/{tail:.*}", self.proxy)

        async def start(app: web.Application) -> None:
            self.client = ClientSession(
                timeout=ClientTimeout(total=30), auto_decompress=True
            )

        async def stop(app: web.Application) -> None:
            for state in tuple(self.leases.values()):
                self.receipt_store.update(
                    state.lease.session_id, status="closed", outcome="gateway_stopped"
                )
                if state.websocket is not None:
                    await state.websocket.close()
            if self.client is not None:
                await self.client.close()

        app.on_startup.append(start)
        app.on_shutdown.append(stop)
        return app
