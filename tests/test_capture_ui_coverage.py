"""Capture lease ownership, artifact release and cleanup exercised through HTTP."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request

from northgate_rmm.capture_store import CaptureStore
from northgate_rmm.capture_ui import CaptureUI
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import RemoteTarget
from tests.test_remote_access import PRINCIPAL, TARGET


@pytest.mark.parametrize(
    "mode",
    [
        "download",
        "tampered",
        "artifact_failure",
        "unknown_artifact",
        "lease",
        "lease_failure",
        "lease_expired",
        "lease_wrong_session",
        "stop",
        "delete",
        "delete_unconfirmed",
        "state_failure",
        "configuration",
        "page",
    ],
)
def test_capture_http_authority_and_artifact_integrity(
    tmp_path: Path, mode: str
) -> None:
    async def scenario() -> None:
        payload = b"synthetic-artifact"
        job_id = str(uuid4())
        manifest = {
            "name": "summary.txt",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        job: dict[str, Any] = {
            "id": job_id,
            "endpoint_id": str(TARGET.endpoint_id),
            "identity_id": str(TARGET.identity_id),
            "state": "capturing",
            "artifacts": [manifest],
        }
        calls: list[str] = []

        async def runner(
            target: RemoteTarget,
            params: dict[str, str],
            platform: str,
            envelope: dict[str, str],
            destination: Path | None,
        ) -> dict[str, Any]:
            claims = json.loads(base64.b64decode(envelope["payload"]))
            action = claims["action"]
            calls.append(action)
            if action == "capabilities":
                return {
                    "state": "ready",
                    "interfaces": [
                        {"CaptureName": "1", "Name": '<img src=x onerror="alert(1)">'}
                    ],
                }
            if action == "artifact":
                if mode == "artifact_failure":
                    raise OSError("transport failed")
                assert destination is not None
                destination.write_bytes(payload)
                return (
                    {**manifest, "sha256": "0" * 64} if mode == "tampered" else manifest
                )
            if action == "keepalive" and mode == "lease_failure":
                raise ValueError("lease ended")
            if action == "status" and mode == "state_failure":
                raise TimeoutError("offline")
            if action == "delete":
                return {"deleted": mode != "delete_unconfirmed"}
            if action == "stop":
                job["state"] = "stopped"
            return job

        gateway = MagicMock()
        gateway.key = bytes(16)
        gateway.origin = "https://operator.test"
        gateway.principal = AsyncMock(return_value=PRINCIPAL)
        gateway.audit = AsyncMock()
        gateway.targets = {TARGET.endpoint_id: (TARGET, {})}
        gateway.operation._store.get_endpoint.return_value.platform.value = "linux"
        store = CaptureStore(tmp_path)
        store.add(TARGET.endpoint_id, TARGET.identity_id, PRINCIPAL, job)
        ui = CaptureUI(cast(RemoteGateway, gateway), store, runner, setup=True)
        ui.leases["lease-token"] = (
            PRINCIPAL.subject,
            PRINCIPAL.session_id,
            TARGET.endpoint_id,
            job_id,
            time.time() + (-1 if mode == "lease_expired" else 600),
        )
        if mode == "lease_wrong_session":
            with store.connect() as db:
                db.execute(
                    "UPDATE jobs SET session=? WHERE id=?", ("different", job_id)
                )
        app = web.Application()
        ui.register(app)
        async with TestClient(TestServer(app)) as client:
            base = f"/remote/{TARGET.endpoint_id}/capture"
            if mode in {"download", "tampered", "artifact_failure", "unknown_artifact"}:
                name = "unknown.txt" if mode == "unknown_artifact" else "summary.txt"
                response = await client.get(f"{base}/file/{job_id}/{name}")
                assert response.status == (
                    200
                    if mode == "download"
                    else 404
                    if mode == "unknown_artifact"
                    else 502
                )
                if mode == "download":
                    assert await response.read() == payload
                    assert (
                        response.headers["Content-Disposition"]
                        == f'attachment; filename="{job_id}-summary.txt"'
                    )
                    assert gateway.principal.await_count == 4
                assert not list(tmp_path.glob("*.download"))
            elif mode.startswith("lease"):
                response = await client.post(
                    base + "/lease",
                    data={"token": "lease-token"},
                    headers={"Origin": gateway.origin},
                )
                expected = (
                    200 if mode == "lease" else 409 if mode == "lease_failure" else 403
                )
                assert response.status == expected
                if expected == 200:
                    assert await response.json() == {"renewed": True}
                if expected == 403:
                    assert calls == []
            elif mode in {"stop", "delete", "delete_unconfirmed"}:
                action = "stop" if mode == "stop" else "delete"
                response = await client.post(
                    base,
                    data={
                        "nonce": ui.nonce(PRINCIPAL, TARGET.endpoint_id),
                        "action": action,
                        "job": job_id,
                    },
                    headers={"Origin": gateway.origin},
                    allow_redirects=False,
                )
                assert response.status == (502 if mode == "delete_unconfirmed" else 303)
                row = store.get(
                    TARGET.endpoint_id, TARGET.identity_id, PRINCIPAL.subject, job_id
                )
                if mode == "delete":
                    assert row is None
                elif mode == "stop":
                    assert (
                        row is not None
                        and json.loads(row["payload"])["state"] == "stopped"
                    )
                else:
                    assert row is not None
            elif mode == "configuration":
                response = await client.get(base + "/config")
                assert response.status == 200
                body = await response.json()
                assert body["endpoint_id"] == str(TARGET.endpoint_id)
                assert len(base64.b64decode(body["public_key"])) == 32
                assert "private_key" not in body
            elif mode == "state_failure":
                response = await client.get(base + "/state?job=" + job_id)
                assert response.status == 503
            else:
                response = await client.get(base)
                assert response.status == 200
                html = await response.text()
                assert '<img src=x onerror="alert(1)">' not in html
                assert "&lt;img" in html
                assert "Install capture tools" in html
                assert (
                    "script-src 'sha256-" in response.headers["Content-Security-Policy"]
                )

    asyncio.run(scenario())


def test_capture_form_and_storage_limits_fail_closed(tmp_path: Path) -> None:
    gateway = MagicMock(key=bytes(16), origin="https://operator.test")
    store = CaptureStore(tmp_path / "data")
    ui = CaptureUI(cast(RemoteGateway, gateway), store)
    for index in range(256):
        ui.forms[str(index)] = (
            PRINCIPAL.subject,
            PRINCIPAL.session_id,
            TARGET.endpoint_id,
            time.time() + 600,
        )
    with pytest.raises(web.HTTPTooManyRequests):
        ui.nonce(PRINCIPAL, TARGET.endpoint_id)
    with pytest.raises(web.HTTPNotFound):
        ui.row(TARGET.endpoint_id, TARGET, PRINCIPAL, "not-uuid")
    with pytest.raises(web.HTTPNotFound):
        ui.row(TARGET.endpoint_id, TARGET, PRINCIPAL, uuid4())
    request = make_mocked_request(
        "POST", "/", headers={"Origin": gateway.origin, "Content-Length": "9000"}
    )
    with pytest.raises(web.HTTPRequestEntityTooLarge):
        ui.origin(request)
    with pytest.raises(ValueError, match="Authenticated request"):
        asyncio.run(ui.rpc(TARGET, {}, "linux", PRINCIPAL, "status"))
    gateway.principal = AsyncMock(
        return_value=MagicMock(subject="other", session_id="other")
    )
    with pytest.raises(web.HTTPForbidden):
        asyncio.run(ui.rpc(TARGET, {}, "linux", PRINCIPAL, "status", request=request))
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        CaptureStore(linked)
    root = tmp_path / "linked-database"
    root.mkdir()
    (root / "capture.sqlite3").symlink_to(tmp_path / "other-database")
    with pytest.raises(ValueError, match="symlink"):
        CaptureStore(root)
