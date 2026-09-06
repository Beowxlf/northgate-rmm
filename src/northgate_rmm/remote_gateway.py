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
from northgate_rmm.presentation import STYLE_SOURCE, document
from northgate_rmm.remote_policy import RemoteLease, RemoteTarget, authorize_remote

COOKIE = "__Secure-rmm-remote"
RECHECK_SECONDS = 30
MAX_LEASES = 8
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


class RemoteGateway:
    def __init__(
        self,
        operation: OperatorApplication,
        targets: dict[UUID, tuple[RemoteTarget, dict[str, str]]],
        key: bytes,
        origin: str,
    ) -> None:
        if not origin.startswith("https://") or origin.endswith("/"):
            raise ValueError("remote origin must be an exact HTTPS origin")
        self.operation = operation
        self.targets = targets
        self.key = key
        self.origin = origin
        self.leases: dict[str, LeaseState] = {}
        self.forms: dict[str, tuple[str, str, UUID, datetime]] = {}
        self.client: ClientSession | None = None

    async def principal(
        self,
        request: web.Request,
        endpoint_id: UUID,
        authorization: str | None = None,
        *,
        require_online: bool = True,
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
            )
            return principal

        try:
            return await asyncio.to_thread(verify)
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
        self.leases = {
            k: v
            for k, v in self.leases.items()
            if v.lease.expires_at > now or v.websocket is not None
        }

    async def desktop_file(self, request: web.Request) -> web.Response:
        try:
            endpoint_id = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        principal = await self.principal(request, endpoint_id)
        target, parameters = self.targets[endpoint_id]
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
                "prompt for credentials:i:1",
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
        try:
            endpoint_id = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        principal = await self.principal(request, endpoint_id)
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
            )
            endpoint = await asyncio.to_thread(
                self.operation._store.get_endpoint, endpoint_id
            )
            content = (
                f'<a href="/endpoints/{endpoint_id}">← Device profile</a>'
                f"<h1>Connect to {escape(endpoint.display_name)}</h1>"
                '<section class="panel"><div class="panel-heading"><div>'
                "<h2>SSH terminal</h2><p>Start a terminal in your browser. "
                "Sessions end after one hour; "
                "device and sign-in access are checked throughout.</p>"
                "<p>Clipboard and file transfer are disabled.</p>"
                f'<form method="post" action="/remote/{endpoint_id}">'
                f'<input type="hidden" name="nonce" value="{nonce}">'
                '<button class="button" type="submit">Connect SSH Terminal'
                "</button></form>"
                '<form method="post" action="/remote/end">'
                '<button class="button" type="submit">End current session</button>'
                "</form>"
                "</div></div></section>"
            )
            return web.Response(
                text=document("SSH terminal", content, updated=""),
                content_type="text/html",
                headers={
                    "Cache-Control": "no-store",
                    "Referrer-Policy": "strict-origin",
                    "Content-Security-Policy": (
                        "default-src 'none'; frame-ancestors 'none'; "
                        f"base-uri 'none'; form-action 'self'; style-src {STYLE_SOURCE}"
                    ),
                },
            )
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
        if len(self.leases) >= MAX_LEASES or any(
            state.lease.endpoint_id == endpoint_id for state in self.leases.values()
        ):
            raise web.HTTPConflict(
                text="A remote session already exists; close it or wait for expiry"
            )
        target, parameters = self.targets[endpoint_id]
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
        data = encrypt_connection(
            self.key,
            {
                "username": str(lease.session_id),
                "expires": int((now + timedelta(seconds=60)).timestamp() * 1000),
                "connections": {
                    "SSH Terminal": {"protocol": target.protocol, "parameters": options}
                },
            },
        )
        cookie = secrets.token_urlsafe(32)
        self.leases[cookie] = LeaseState(
            lease,
            auth_data=data,
            authorization=request.headers.get("Authorization", ""),
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
        return response

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
                self.targets[state.lease.endpoint_id][0],
                now=datetime.now(UTC),
            )
        except AuthorizationError:
            raise web.HTTPForbidden() from None
        state.authorization = authorization or request.headers.get("Authorization", "")
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
        if request.method not in {"GET", "POST", "DELETE"}:
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "POST", "DELETE"])
        if request.method != "GET" and request.headers.get("Origin") != self.origin:
            raise web.HTTPForbidden()
        if self.client is None:
            raise web.HTTPServiceUnavailable()
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
        if request.path.endswith("/api/tokens") and request.method == "POST":
            fields = await request.post()
            data = str(fields.get("data", ""))
            if (
                not data
                or not state.auth_data
                or not hmac.compare_digest(data, state.auth_data)
            ):
                raise web.HTTPForbidden()
            state.auth_data = ""
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
            data=await request.read(),
            headers={
                "Content-Type": request.headers.get(
                    "Content-Type", "application/octet-stream"
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
                "X-Frame-Options": "DENY",
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
        if state.websocket is not None:
            await state.websocket.close()
        response = web.HTTPFound(f"/endpoints/{state.lease.endpoint_id}")
        response.del_cookie(COOKIE, path="/")
        return response

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
                        await self.checked_lease(
                            request, authorization=state.authorization
                        )

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
        app = web.Application(client_max_size=MAX_BODY)
        app.router.add_post("/remote/end", self.end)
        app.router.add_get("/remote/keepalive", self.keepalive)
        app.router.add_get("/remote/session.js", self.session_script)
        app.router.add_get("/remote/{endpoint}/desktop.rdp", self.desktop_file)
        app.router.add_get("/remote/{endpoint}", self.landing)
        app.router.add_post("/remote/{endpoint}", self.landing)
        app.router.add_route("*", "/guacamole/{tail:.*}", self.proxy)

        async def start(app: web.Application) -> None:
            self.client = ClientSession(
                timeout=ClientTimeout(total=30), auto_decompress=True
            )

        async def stop(app: web.Application) -> None:
            for state in tuple(self.leases.values()):
                if state.websocket is not None:
                    await state.websocket.close()
            if self.client is not None:
                await self.client.close()

        app.on_startup.append(start)
        app.on_shutdown.append(stop)
        return app
