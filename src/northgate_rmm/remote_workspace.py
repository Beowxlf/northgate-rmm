"""Embedded remote workspace, encrypted credential reveal, and bounded uploads."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import tempfile
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path
from uuid import UUID, uuid4

from aiohttp import web
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_UPLOAD = 20 * 1024 * 1024
UPLOAD_REQUEST_LIMIT = MAX_UPLOAD + 65536
CSS = Path(__file__).with_name("remote_tools.css").read_text(encoding="utf-8")
STYLE_HASH = (
    "'sha256-" + base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode() + "'"
)


def frame_document(content: str, title: str = "Remote workspace") -> str:
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title><style>{CSS}</style></head>"
        f"<body>{content}</body></html>"
    )


def frame_response(content: str) -> web.Response:
    return web.Response(
        text=frame_document(content),
        content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "strict-origin",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; frame-src 'self'; frame-ancestors 'self'; "  # noqa: E501 - HTML and fixed command literals
            f"base-uri 'none'; form-action 'self'; style-src {STYLE_HASH}",
        },
    )


def credential_key(key: bytes) -> bytes:
    return hmac.digest(key, b"northgate-rmm-remote-credentials-v1", "sha256")


def seal_credentials(key: bytes, values: list[dict]) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(credential_key(key)).encrypt(
        nonce, json.dumps(values).encode(), b"rmm-credentials-v1"
    )


def open_credentials(key: bytes, blob: bytes) -> dict:
    if not 28 <= len(blob) <= 16 * 1024 * 1024:
        raise ValueError("Invalid credential envelope")
    values = json.loads(
        AESGCM(credential_key(key)).decrypt(blob[:12], blob[12:], b"rmm-credentials-v1")
    )
    result = {}
    if not isinstance(values, list) or len(values) > 4096:
        raise ValueError("Invalid credentials")
    for value in values:
        endpoint, identity = UUID(value["endpoint_id"]), UUID(value["identity_id"])
        if any(
            not isinstance(value.get(k), str) or not 1 <= len(value[k]) <= 1024
            for k in ["username", "password"]
        ):
            raise ValueError("Invalid credential fields")
        if endpoint in result:
            raise ValueError("Duplicate credentials")
        result[endpoint] = (identity, value["username"], value["password"])
    return result


def safe_filename(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name) or name.endswith("."):
        raise ValueError(
            "Use a filename of up to 100 letters, numbers, dots, underscores or hyphens"
        )
    return uuid4().hex[:12] + "-" + name


async def send_upload(
    target, parameters, platform, source: Path, name: str, digest: str
) -> dict:
    username = parameters.get("username", "")
    pin = parameters.get("host-key", "")
    key = parameters.get("private-key", "")
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username)
        or not key
        or len(pin.splitlines()) != 1
    ):
        raise ValueError("Invalid upload SSH configuration")
    parts = pin.split()
    if len(parts) != 3 or parts[1] not in {
        "ecdsa-sha2-nistp256",
        "ssh-ed25519",
        "ssh-rsa",
    }:
        raise ValueError("Invalid upload SSH pin")
    metadata = {"name": name, "size": source.stat().st_size, "sha256": digest}
    if platform == "windows":
        root = "/C:/Users/rmmremote/NorthGateRMM-Ops"
        encoded = base64.b64encode(json.dumps(metadata).encode()).decode()
        script = (
            "$metadata = [Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String('"
            + encoded
            + "')) | ConvertFrom-Json;\n"
            + Path(__file__)
            .with_name("receive_ops_file_windows.ps1")
            .read_text(encoding="utf-8")
        )
        command = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
        command += base64.b64encode(script.encode("utf-16-le")).decode()
    elif platform == "linux":
        root = "/var/lib/NorthGateRMM-Ops"
        command = (
            "/usr/bin/python3 /usr/local/libexec/northgate-rmm/receive_ops_file.py"
        )
    else:
        raise ValueError("Unsupported platform")
    with tempfile.TemporaryDirectory(prefix="rmm-upload-ssh-") as directory:
        temp = Path(directory)
        for filename, data in [("key", key), ("known_hosts", pin + "\n")]:
            p = temp / filename
            p.write_text(data)
            p.chmod(0o600)
        args = ["/usr/bin/ssh", "-T", "-F", "/dev/null", "-i", str(temp / "key")]
        for option in [
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=" + str(temp / "known_hosts"),
            "HostKeyAlgorithms=" + parts[1],
            "ConnectTimeout=8",
            "ServerAliveInterval=5",
            "ServerAliveCountMax=2",
        ]:
            args += ["-o", option]
        args += [username + "@" + target.address, command]
        batch = (f'-mkdir "{root}"\nput "{source}" "{root}/.upload-{name}"\n').encode()
        transfer = await asyncio.create_subprocess_exec(
            "/usr/bin/sftp",
            "-b",
            "-",
            *args[2:-2],
            args[-2],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(90):
                await transfer.communicate(batch)
                if transfer.returncode:
                    raise ValueError("SFTP transfer failed")
        finally:
            if transfer.returncode is None:
                transfer.kill()
            await transfer.wait()
        header = json.dumps(metadata).encode() + b"\n"
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(90):
                proc.stdin.write(header)
                proc.stdin.close()
                output = await proc.stdout.read(4097)
                code = await proc.wait()
                if code or len(output) > 4096:
                    raise ValueError(
                        "Transfer failed; destination outcome may need checking"
                    )
                result = json.loads(output.decode("utf-8-sig"))
                if (
                    result.get("name") != name
                    or result.get("sha256") != digest
                    or result.get("size") != source.stat().st_size
                ):
                    raise ValueError("Transfer verification failed")
                return result
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()


class RemoteWorkspace:
    def __init__(self, gateway, credentials=None, sender=send_upload):
        self.gateway, self.credentials, self.sender = gateway, credentials or {}, sender
        self.forms = {}
        self.busy = set()

    def register(self, app):
        app.router.add_get("/remote/{endpoint}/workspace", self.workspace)
        app.router.add_get("/remote/{endpoint}/tools", self.tools)
        app.router.add_post("/remote/{endpoint}/tools", self.tools)

    async def workspace(self, request):
        try:
            endpoint = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        await self.gateway.principal(request, endpoint, require_online=False)
        desktop = (
            '<div class="terminal-bar"><h2>Browser desktop</h2>'
            f'<a class="button" href="/remote/{endpoint}/desktop" '
            'target="ssh-terminal">Open browser desktop</a>'
            f'<a class="button" href="/remote/{endpoint}/desktop.rdp">'
            "Download native RDP connection</a></div>"
            if "rdp" in self.gateway.methods[endpoint]
            else ""
        )
        return frame_response(
            desktop
            + f'<iframe title="Credentials and file transfer" src="/remote/{endpoint}/tools" height="250" class="tools-frame"></iframe>'  # noqa: E501 - HTML and fixed command literals
            '<div class="terminal-bar"><h2>SSH terminal</h2>'
            f'<a class="button" target="_blank" rel="noopener" href="/remote/{endpoint}">Open separately</a></div>'  # noqa: E501 - HTML and fixed command literals
            f'<iframe title="SSH terminal" name="ssh-terminal" src="/remote/{endpoint}"></iframe>'  # noqa: E501 - HTML and fixed command literals
        )

    def nonce(self, principal, endpoint, action):
        now = datetime.now(UTC)
        self.forms = {k: v for k, v in self.forms.items() if v[4] > now}
        if len(self.forms) >= 128:
            raise web.HTTPTooManyRequests()
        value = secrets.token_urlsafe(32)
        self.forms[value] = (
            principal.subject,
            principal.session_id,
            endpoint,
            action,
            now + timedelta(minutes=10),
        )
        return value

    def consume(self, value, principal, endpoint, action):
        entry = self.forms.pop(value, None)
        if (
            entry is None
            or entry[:4] != (principal.subject, principal.session_id, endpoint, action)
            or entry[4] <= datetime.now(UTC)
        ):
            raise web.HTTPForbidden(
                text="Form expired. Refresh the tools section and try again."
            )

    async def tools(self, request):
        try:
            endpoint = UUID(request.match_info["endpoint"])
        except ValueError:
            raise web.HTTPNotFound() from None
        principal = await self.gateway.principal(
            request, endpoint, require_online=False
        )
        target, parameters = self.gateway.targets[endpoint]
        device = await asyncio.to_thread(
            self.gateway.operation._store.get_endpoint, endpoint
        )
        folder = (
            r"C:\Users\rmmremote\NorthGateRMM-Ops"
            if device.platform.value == "windows"
            else "/var/lib/NorthGateRMM-Ops"
        )
        message = ""
        if request.method == "POST":
            if request.headers.get("Origin") != self.gateway.origin:
                raise web.HTTPForbidden()
            if request.content_type == "multipart/form-data":
                await self.gateway.principal(request, endpoint)
                if endpoint in self.busy or len(self.busy) >= 4:
                    raise web.HTTPConflict(
                        text="A file transfer is already running. Try again shortly."
                    )
                self.busy.add(endpoint)
                try:
                    message = await self.upload(request, principal, target, parameters)
                finally:
                    self.busy.discard(endpoint)
            else:
                fields = await request.post()
                self.consume(
                    str(fields.get("nonce", "")), principal, endpoint, "reveal"
                )
                if self.gateway.legacy_credential_guard:
                    await self.gateway.legacy_credential_guard(target)
                value = self.credentials.get(endpoint)
                if value is None or value[0] != target.identity_id:
                    raise web.HTTPNotFound(
                        text="No saved credentials for this enrollment"
                    )
                await self.gateway.audit(
                    principal, endpoint, "remote.credentials.revealed", uuid4()
                )
                return frame_response(
                    "<h2>Saved Remote Desktop credentials</h2>"
                    "<p>SSH connects automatically with its saved key. Select and copy these values for native RDP.</p>"  # noqa: E501 - HTML and fixed command literals
                    f'<label>Username<textarea readonly rows="1">{escape(value[1])}</textarea></label>'  # noqa: E501 - HTML and fixed command literals
                    f'<label>Password<textarea readonly rows="1">{escape(value[2])}</textarea></label>'  # noqa: E501 - HTML and fixed command literals
                    f'<a class="button" href="/remote/{endpoint}/tools">Hide credentials</a>'  # noqa: E501 - HTML and fixed command literals
                )
        reveal = self.nonce(principal, endpoint, "reveal")
        upload = self.nonce(principal, endpoint, "upload")
        return frame_response(
            (f'<p class="message">{escape(message)}</p>' if message else "")
            + '<div class="connection-info"><strong>Saved SSH access</strong><p>SSH connects with the saved key. No password entry is needed.</p></div><details class="card"><summary>Remote Desktop credentials</summary><p>Reveal the saved device login only when connecting with native RDP.</p>'  # noqa: E501 - HTML and fixed command literals
            f'<form method="post"><input type="hidden" name="nonce" value="{reveal}">'
            '<button type="submit">Show RDP credentials</button></form></details>'
            f'<section class="card"><p class="tool-eyebrow">File transfer</p><h2>Send a file</h2><p>Destination</p><pre>{escape(folder)}</pre><p class="section-note">Up to 20 MiB per file. Files receive unique names and are not executed automatically.</p>'  # noqa: E501 - HTML and fixed command literals
            f'<form method="post" enctype="multipart/form-data"><input type="hidden" name="nonce" value="{upload}">'  # noqa: E501 - HTML and fixed command literals
            '<label>Choose a file<input type="file" name="file" required aria-label="File to upload"></label><div class="actions"><button class="primary" type="submit">Upload to device</button></div></form></section>'  # noqa: E501 - HTML and fixed command literals
            f'<a class="button" href="/remote/{endpoint}/tools">'
            "Refresh files & access</a>"
        )

    async def upload(self, request, principal, target, parameters):
        reader = await request.multipart()
        part = await reader.next()
        if part is None or part.name != "nonce":
            raise web.HTTPBadRequest(text="Missing upload form token")
        nonce = await part.read_chunk(8192)
        if not part.at_eof() or len(nonce) > 128:
            raise web.HTTPBadRequest()
        self.consume(nonce.decode(), principal, target.endpoint_id, "upload")
        part = await reader.next()
        if part is None or part.name != "file" or not part.filename:
            raise web.HTTPBadRequest(text="Choose a file")
        try:
            name = safe_filename(part.filename)
        except ValueError as error:
            raise web.HTTPBadRequest(text=str(error)) from None
        with tempfile.TemporaryDirectory(prefix="rmm-upload-") as directory:
            source = Path(directory) / "payload"
            size = 0
            digest = hashlib.sha256()
            with source.open("xb") as stream:
                source.chmod(0o600)
                async with asyncio.timeout(90):
                    while chunk := await part.read_chunk(65536):
                        size += len(chunk)
                        if size > MAX_UPLOAD:
                            raise web.HTTPRequestEntityTooLarge(
                                max_size=MAX_UPLOAD, actual_size=size
                            )
                        stream.write(chunk)
                        digest.update(chunk)
            if await reader.next() is not None:
                raise web.HTTPBadRequest(text="Only one file per upload")
            await self.gateway.principal(request, target.endpoint_id)
            if self.gateway.secret_resolver:
                resolved = await self.gateway.secret_resolver(
                    request, principal, target, "ssh"
                )
                if resolved.pop("__rmm_secret_id", ""):
                    parameters = {
                        k: v
                        for k, v in parameters.items()
                        if k
                        not in {
                            "username",
                            "password",
                            "domain",
                            "private-key",
                            "passphrase",
                        }
                    }
                    parameters.update(resolved)
            correlation = uuid4()
            await self.gateway.audit(
                principal,
                target.endpoint_id,
                "remote.file_upload.requested",
                correlation,
            )
            platform = (
                await asyncio.to_thread(
                    self.gateway.operation._store.get_endpoint, target.endpoint_id
                )
            ).platform.value
            try:
                result = await self.sender(
                    target, parameters, platform, source, name, digest.hexdigest()
                )
            except (ValueError, OSError, TimeoutError):
                await self.gateway.audit(
                    principal,
                    target.endpoint_id,
                    "remote.file_upload.failed_or_unknown",
                    correlation,
                )
                return "Transfer could not be confirmed. Check the destination before retrying."  # noqa: E501 - HTML and fixed command literals
            await self.gateway.audit(
                principal,
                target.endpoint_id,
                "remote.file_upload.completed",
                correlation,
            )
            return f"Uploaded {result['name']} to NorthGateRMM-Ops ({size} bytes). SHA-256: {digest.hexdigest()}"  # noqa: E501 - HTML and fixed command literals
