"""Workspace credential envelopes, upload policy and transfer failures."""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from aiohttp import FormData, web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import RemoteTarget
from northgate_rmm.remote_workspace import (
    RemoteWorkspace,
    open_credentials,
    seal_credentials,
    send_upload,
)
from tests.test_remote_access import PRINCIPAL, TARGET


@pytest.mark.parametrize("mode", ["short", "excess", "empty_user", "duplicate"])
def test_saved_credentials_reject_invalid_envelope_or_metadata(mode: str) -> None:
    value = {
        "endpoint_id": str(TARGET.endpoint_id),
        "identity_id": str(TARGET.identity_id),
        "username": "" if mode == "empty_user" else "operator",
        "password": uuid4().hex,
    }
    values = [value] * (4097 if mode == "excess" else 2 if mode == "duplicate" else 1)
    blob = b"bad" if mode == "short" else seal_credentials(bytes(16), values)
    with pytest.raises(ValueError):
        open_credentials(bytes(16), blob)


@pytest.mark.parametrize(
    "field,value",
    [
        ("username", "user;id"),
        ("private-key", ""),
        ("host-key", "host ssh-unsupported key"),
        ("platform", "unknown"),
    ],
)
def test_upload_transport_rejects_unpinned_configuration(
    tmp_path: Path, field: str, value: str
) -> None:
    source = tmp_path / "payload"
    source.write_bytes(b"data")
    params = {
        "username": "operator",
        "private-key": "synthetic-key",
        "host-key": "host ssh-ed25519 synthetic",
    }
    platform = value if field == "platform" else "linux"
    if field != "platform":
        params[field] = value
    with pytest.raises(ValueError):
        asyncio.run(send_upload(TARGET, params, platform, source, "file.txt", "0" * 64))


@pytest.mark.parametrize(
    "mode",
    [
        "sftp_failure",
        "sftp_timeout",
        "pipes",
        "oversized",
        "receipt",
        "ssh_failure",
        "ssh_timeout",
    ],
)
def test_upload_transport_failure_always_reaps_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    async def scenario() -> None:
        source = tmp_path / "payload"
        source.write_bytes(b"data")
        written: list[bytes] = []

        class Writer:
            def write(self, data: bytes) -> None:
                written.append(data)

            def close(self) -> None:
                pass

        class Output:
            async def read(self, maximum: int) -> bytes:
                assert maximum == 4097
                if mode == "ssh_timeout":
                    raise TimeoutError()
                return b"x" * 4097 if mode == "oversized" else b"{}"

        class Process:
            def __init__(self, kind: str) -> None:
                self.kind = kind
                self.returncode: int | None = None
                self.stdin = None if mode == "pipes" else Writer()
                self.stdout = Output()
                self.killed = False
                self.waited = 0

            async def communicate(self, data: bytes) -> tuple[bytes, bytes]:
                assert b".upload-file.txt" in data
                if mode == "sftp_timeout":
                    raise TimeoutError()
                self.returncode = 1 if mode == "sftp_failure" else 0
                return b"", b""

            async def wait(self) -> int:
                self.waited += 1
                self.returncode = (
                    1 if self.kind == "ssh" and mode == "ssh_failure" else 0
                )
                return self.returncode

            def kill(self) -> None:
                self.killed = True

        processes: list[Process] = []

        async def spawn(*args: object, **kwargs: object) -> Process:
            process = Process("sftp" if args[0] == "/usr/bin/sftp" else "ssh")
            processes.append(process)
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        params = {
            "username": "operator",
            "private-key": "synthetic-key",
            "host-key": "host ssh-ed25519 synthetic",
        }
        with pytest.raises((ValueError, TimeoutError)):
            await send_upload(TARGET, params, "linux", source, "file.txt", "0" * 64)
        assert len(processes) == (1 if mode.startswith("sftp") else 2)
        assert all(process.waited for process in processes)
        if mode in {"sftp_timeout", "ssh_timeout", "pipes"}:
            assert processes[-1].killed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode",
    [
        "missing_nonce",
        "long_nonce",
        "missing_file",
        "invalid_filename",
        "extra_file",
        "busy",
        "failure",
        "vault",
        "guard",
        "invalid_endpoint",
    ],
)
def test_workspace_upload_and_reveal_boundaries(tmp_path: Path, mode: str) -> None:
    async def scenario() -> None:
        gateway = MagicMock()
        gateway.key = bytes(16)
        gateway.origin = "https://operator.test"
        gateway.principal = AsyncMock(return_value=PRINCIPAL)
        gateway.audit = AsyncMock()
        gateway.secret_resolver = None
        gateway.legacy_credential_guard = None
        gateway.targets = {
            TARGET.endpoint_id: (
                TARGET,
                {
                    "username": "legacy",
                    "password": uuid4().hex,
                    "host-key": "host ssh-ed25519 synthetic",
                },
            )
        }
        gateway.methods = {
            TARGET.endpoint_id: {"rdp": gateway.targets[TARGET.endpoint_id]}
        }
        gateway.operation._store.get_endpoint.return_value.platform.value = "linux"
        calls: list[dict[str, str]] = []

        async def sender(
            target: RemoteTarget,
            parameters: dict[str, str],
            platform: str,
            source: Path,
            name: str,
            digest: str,
        ) -> dict[str, Any]:
            calls.append(parameters)
            assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
            if mode == "failure":
                raise OSError("uncertain transfer")
            return {"name": name}

        ui = RemoteWorkspace(
            cast(RemoteGateway, gateway),
            {TARGET.endpoint_id: (TARGET.identity_id, "operator", uuid4().hex)},
            sender,
        )
        if mode == "busy":
            ui.busy.add(TARGET.endpoint_id)
        if mode == "vault":
            gateway.secret_resolver = AsyncMock(
                return_value={
                    "__rmm_secret_id": str(uuid4()),
                    "username": "current",
                    "private-key": "current-key",
                }
            )
        if mode == "guard":
            gateway.legacy_credential_guard = AsyncMock(side_effect=web.HTTPConflict())
        app = web.Application()
        ui.register(app)
        async with TestClient(TestServer(app)) as client:
            base = f"/remote/{TARGET.endpoint_id}/tools"
            headers = {"Origin": gateway.origin}
            if mode == "invalid_endpoint":
                for suffix in ("tools", "workspace"):
                    assert (await client.get("/remote/invalid/" + suffix)).status == 404
                return
            if mode == "guard":
                response = await client.post(
                    base,
                    headers=headers,
                    data={"nonce": ui.nonce(PRINCIPAL, TARGET.endpoint_id, "reveal")},
                )
                assert response.status == 409
                gateway.legacy_credential_guard.assert_awaited_once_with(TARGET)
                return
            form = FormData()
            nonce = ui.nonce(PRINCIPAL, TARGET.endpoint_id, "upload")
            if mode != "missing_nonce":
                form.add_field("nonce", "x" * 129 if mode == "long_nonce" else nonce)
            form.add_field(
                "other" if mode == "missing_file" else "file",
                b"data",
                filename="../bad.txt" if mode == "invalid_filename" else "file.txt",
            )
            if mode == "extra_file":
                form.add_field("file", b"second", filename="second.txt")
            response = await client.post(base, headers=headers, data=form)
            if mode == "busy":
                assert response.status == 409
            elif mode in {"failure", "vault"}:
                assert response.status == 200
                text = await response.text()
                if mode == "failure":
                    assert "could not be confirmed" in text
                else:
                    assert "Uploaded" in text
                    assert calls == [
                        {
                            "host-key": "host ssh-ed25519 synthetic",
                            "username": "current",
                            "private-key": "current-key",
                        }
                    ]
            else:
                assert response.status == 400
                assert not calls

    asyncio.run(scenario())


def test_workspace_form_capacity_and_expiration() -> None:
    ui = RemoteWorkspace(cast(RemoteGateway, MagicMock()))
    for index in range(128):
        ui.forms[str(index)] = (
            PRINCIPAL.subject,
            PRINCIPAL.session_id,
            TARGET.endpoint_id,
            "upload",
            datetime.now(UTC) + timedelta(minutes=1),
        )
    with pytest.raises(web.HTTPTooManyRequests):
        ui.nonce(PRINCIPAL, TARGET.endpoint_id, "upload")
    ui.forms["expired"] = (
        PRINCIPAL.subject,
        PRINCIPAL.session_id,
        TARGET.endpoint_id,
        "upload",
        datetime.fromtimestamp(time.time() - 1, UTC),
    )
    with pytest.raises(web.HTTPForbidden):
        ui.consume("expired", PRINCIPAL, TARGET.endpoint_id, "upload")
