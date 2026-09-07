from __future__ import annotations

import asyncio
import hashlib
import re
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aiohttp import FormData
from aiohttp.test_utils import TestClient, TestServer
from cryptography.exceptions import InvalidTag

from northgate_rmm.errors import AuthorizationError
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_workspace import (
    RemoteWorkspace,
    open_credentials,
    safe_filename,
    seal_credentials,
)
from tests.test_remote_access import POLICY, PRINCIPAL, STATUS, TARGET


def test_saved_credentials_authenticated_encryption():
    values = [
        {
            "endpoint_id": str(TARGET.endpoint_id),
            "identity_id": str(TARGET.identity_id),
            "username": "lab-user",
            "password": "synthetic-secret",
        }
    ]
    blob = seal_credentials(bytes(16), values)
    assert b"synthetic-secret" not in blob
    assert (
        open_credentials(bytes(16), blob)[TARGET.endpoint_id][2] == "synthetic-secret"
    )
    for key, value in [
        (bytes([1]) * 16, blob),
        (bytes(16), blob[:-1] + bytes([blob[-1] ^ 1])),
    ]:
        with pytest.raises(InvalidTag):
            open_credentials(key, value)


@pytest.mark.parametrize(
    "name", ["../escape", r"C:\escape", "-option", ".hidden", "a\nb", "a.", "x" * 101]
)
def test_upload_rejects_path_and_command_injection(name):
    with pytest.raises(ValueError):
        safe_filename(name)


def test_unique_upload_names():
    assert safe_filename("tool.zip") != safe_filename("tool.zip")


def test_workspace_credentials_and_upload_authorization(monkeypatch):
    from northgate_rmm import remote_workspace

    class Operation:
        _policy = POLICY
        _store = SimpleNamespace(
            get_endpoint=lambda _: SimpleNamespace(
                identity_id=TARGET.identity_id, platform=SimpleNamespace(value="linux")
            ),
            endpoint_status=lambda _, now: STATUS,
        )

        def __init__(self):
            self.events = []

        def _authenticate(self, authorization, **kwargs):
            if authorization != "Bearer synthetic":
                raise AuthorizationError("invalid")
            return PRINCIPAL

        def _audit(self, *args, **kwargs):
            self.events.append(kwargs["action"])

    async def scenario():
        operation = Operation()
        gateway = RemoteGateway(
            operation,
            {TARGET.endpoint_id: (TARGET, {})},
            bytes(16),
            "https://operator.test",
        )
        received = []

        async def sender(target, parameters, platform, source, name, digest):
            data = source.read_bytes()
            received.append(data)
            assert digest == hashlib.sha256(data).hexdigest()
            return {"name": name, "size": len(data), "sha256": digest}

        ui = RemoteWorkspace(
            gateway,
            {TARGET.endpoint_id: (TARGET.identity_id, "lab-user", "synthetic-secret")},
            sender,
        )
        app = gateway.application()
        ui.register(app)
        path = f"/remote/{TARGET.endpoint_id}/tools"
        headers = {
            "Authorization": "Bearer synthetic",
            "Origin": "https://operator.test",
        }
        async with TestClient(TestServer(app)) as client:
            assert (await client.get(path)).status == 403
            response = await client.get(path, headers=headers)
            page = await response.text()
            assert "synthetic-secret" not in page
            nonce = re.findall(r'name="nonce" value="([^"]+)"', page)[0]
            denied = await client.post(
                path,
                headers={**headers, "Origin": "https://evil.test"},
                data={"nonce": nonce},
            )
            assert denied.status == 403
            revealed = await client.post(path, headers=headers, data={"nonce": nonce})
            assert revealed.status == 200
            assert "synthetic-secret" in await revealed.text()
            assert revealed.headers["Cache-Control"] == "no-store"
            assert (
                await client.post(path, headers=headers, data={"nonce": nonce})
            ).status == 403
            ui.credentials[TARGET.endpoint_id] = (
                uuid4(),
                "lab-user",
                "synthetic-secret",
            )
            page = await (await client.get(path, headers=headers)).text()
            nonce = re.findall(r'name="nonce" value="([^"]+)"', page)[0]
            assert (
                await client.post(path, headers=headers, data={"nonce": nonce})
            ).status == 404
            for data, expected in [(b"lab-proof", 200), (b"oversized-proof", 413)]:
                monkeypatch.setattr(remote_workspace, "MAX_UPLOAD", 10)
                page = await (await client.get(path, headers=headers)).text()
                nonce = re.findall(r'name="nonce" value="([^"]+)"', page)[1]
                form = FormData()
                form.add_field("nonce", nonce)
                form.add_field("file", data, filename="proof.txt")
                response = await client.post(path, headers=headers, data=form)
                assert response.status == expected
            assert received == [b"lab-proof"]
            assert "remote.credentials.revealed" in operation.events
            assert "remote.file_upload.completed" in operation.events
            embedded = await client.get(
                f"/remote/{TARGET.endpoint_id}/workspace", headers=headers
            )
            assert embedded.status == 200
            assert embedded.headers["X-Frame-Options"] == "SAMEORIGIN"
            assert 'name="ssh-terminal"' in await embedded.text()

    asyncio.run(scenario())


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_upload_transport_preserves_binary_data(monkeypatch, tmp_path, platform):
    import json

    from northgate_rmm.remote_workspace import send_upload

    payload = bytes(range(256)) * 513
    source = tmp_path / "payload"
    source.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    name = safe_filename("proof.bin")
    writes = []
    batches = []
    commands = []

    class Writer:
        def write(self, value):
            writes.append(value)

        async def drain(self):
            pass

        def close(self):
            pass

    class Output:
        async def read(self, count):
            return json.dumps(
                {"name": name, "size": len(payload), "sha256": digest}
            ).encode()

    class Process:
        stdin = Writer()
        stdout = Output()
        returncode = 0

        async def communicate(self, value):
            batches.append(value)
            return (None, None)

        async def wait(self):
            return 0

    async def create(*args, **kwargs):
        commands.append(args)
        assert "StrictHostKeyChecking=yes" in args
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    parameters = {
        "username": "rmmremote",
        "private-key": "synthetic-key",
        "host-key": "10.20.30.40 ssh-ed25519 synthetic-pin",
    }
    result = asyncio.run(
        send_upload(TARGET, parameters, platform, source, name, digest)
    )
    header = json.loads(writes[0])
    assert header["size"] == len(payload)
    assert len(writes) == 1
    assert commands[0][0] == "/usr/bin/sftp"
    assert commands[1][0] == "/usr/bin/ssh"
    assert str(source).encode() in batches[0]
    assert (".upload-" + name).encode() in batches[0]
    assert payload not in batches[0]
    assert result["sha256"] == digest
