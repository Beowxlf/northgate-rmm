"""Installation is endpoint-scoped, session-bound and dispatched only explicitly."""

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.capture_setup import CaptureSetup
from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore


@pytest.mark.parametrize(
    "failure",
    [
        "",
        "permission",
        "offline",
        "old_worker",
        "upgrade_worker",
        "enrollment",
        "catalog",
        "origin",
        "token",
    ],
)
def test_capture_install_dispatch(tmp_path, failure):
    async def scenario():
        endpoint, identity = uuid4(), uuid4()
        principal = SimpleNamespace(
            subject="owner",
            session_id="session",
            roles={"remote_operator"},
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        async def authenticate(*args, **kwargs):
            return principal

        async def audit(*args):
            pass

        gateway = SimpleNamespace(
            key=bytes(16),
            origin="https://operator.test",
            principal=authenticate,
            audit=audit,
            operation=SimpleNamespace(
                _store=SimpleNamespace(
                    get_endpoint=lambda _: SimpleNamespace(
                        identity_id=identity, platform=SimpleNamespace(value="linux")
                    )
                ),
                _policy=SimpleNamespace(permits=lambda *a: failure != "permission"),
            ),
        )
        store = ManagementStore(tmp_path, bytes(16))
        store.worker = lambda _: dict(
            ready=failure != "offline",
            identity=str(uuid4() if failure == "enrollment" else identity),
            capabilities={
                "version": "1.1.0-lab.2",
                "features": {
                    "capture_installer": failure not in {"old_worker", "upgrade_worker"}
                },
            },
        )
        management = Management(gateway, store)
        setup = CaptureSetup(management)
        if failure != "catalog":
            management.extended.catalog.mkdir()
            entry = {
                "manifest": {
                    "component": "wxlfgar",
                    "platform": "linux",
                    "version": "0.2.0",
                    "sha256": "a" * 64,
                },
                "signature": base64.b64encode(bytes(64)).decode(),
                "url": "https://management.test/v1/management/releases/" + "a" * 64,
            }
            p = management.extended.catalog / "release.json"
            p.write_text(json.dumps(entry))
            p.chmod(0o600)
            if failure == "upgrade_worker":
                entry["manifest"].update(component="worker", version="1.1.0-lab.4")
                p.write_text(json.dumps(entry))
        app = web.Application()
        setup.register(app)
        async with TestClient(TestServer(app)) as client:
            url = f"/remote/{endpoint}/capture/setup"
            response = await client.get(url)
            assert response.status == 200
            state = await response.json()
            # Polling must not fill the shared form-token store.
            for _ in range(135):
                assert (await (await client.get(url)).json())["csrf"] == state["csrf"]
            assert len(management.forms) == 1
            headers = {
                "Origin": "https://wrong.test"
                if failure == "origin"
                else gateway.origin,
                "Authorization": "Bearer synthetic",
            }
            fields = {"csrf": "wrong" if failure == "token" else state["csrf"]}
            response = await client.post(url, json=fields, headers=headers)
            if failure == "upgrade_worker":
                assert state["mode"] == "worker" and state["available"]
                assert response.status == 202
                job = store.job((await response.json())["job"], private=True)
                assert job["action"] == "update.install"
                assert job["exercise"] == "capture-setup-worker"
                assert job["payload"]["params"]["component"] == "worker"
                assert "public_key" not in job["payload"]["params"]
            elif failure:
                assert response.status in {403, 409}
                assert store.list(endpoint) == []
            else:
                assert response.status == 202
                job = (await response.json())["job"]
                saved = store.job(job, private=True)
                assert saved["action"] == "capture.install"
                assert saved["identity"] == str(identity)
                assert saved["session"] == "session"
                assert saved["payload"]["params"]["public_key"]
                assert (
                    await client.post(url, json=fields, headers=headers)
                ).status == 403
                new = await (await client.get(url)).json()
                assert not new["available"]
                response = await client.post(
                    url, json={"csrf": new["csrf"]}, headers=headers
                )
                assert (await response.json())["job"] == job
                assert len(store.list(endpoint)) == 1

    asyncio.run(scenario())
