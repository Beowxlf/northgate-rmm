import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.tool_catalog import ToolCatalog


@pytest.mark.parametrize(
    "mode",
    [
        "normal",
        "case_denied",
        "artifact_denied",
        "bad_origin",
        "request_id",
        "invalid_input",
        "case_link_failed",
        "existing_invalid_replay",
    ],
)
def test_tool_dispatch_is_idempotent_scoped_and_csrf_bound(tmp_path, mode):
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

        async def case_authorizer(*args):
            if mode == "case_link_failed":
                return
            raise web.HTTPForbidden(text="Case not in scope")

        async def case_linker(*args):
            raise web.HTTPBadRequest(text="Post-queue case link failed")

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
                _policy=SimpleNamespace(permits=lambda *a: True),
            ),
        )
        store = ManagementStore(tmp_path, bytes(16))
        store.worker = lambda _: {
            "ready": True,
            "identity": str(identity),
            "capabilities": {"features": {"tool_catalog": True}},
        }
        management = Management(gateway, store)
        catalog = ToolCatalog(
            management,
            case_authorizer=case_authorizer,
            case_linker=case_linker if mode == "case_link_failed" else None,
        )
        app = web.Application()
        catalog.register(app)
        async with TestClient(TestServer(app)) as client:
            url = f"/remote/{endpoint}/tool-catalog"
            state = await (await client.get(url)).json()
            assert len(state["tools"]) >= 8
            for _ in range(140):
                again = await (await client.get(url)).json()
                assert again["csrf"] == state["csrf"]
            assert len(management.forms) == 1
            fields = {
                "csrf": state["csrf"],
                "action": "tool.run",
                "tool_id": "health",
                "profile": "snapshot",
                "inputs": {},
                "case_id": str(uuid4())
                if mode in {"case_denied", "case_link_failed"}
                else "",
                "request_id": "bad" if mode == "request_id" else str(uuid4()),
            }
            headers = {
                "Authorization": "Bearer synthetic",
                "Origin": "https://wrong.test"
                if mode == "bad_origin"
                else gateway.origin,
            }
            if mode == "artifact_denied":
                fields = {
                    "csrf": state["csrf"],
                    "action": "tool.artifact.read",
                    "request_id": str(uuid4()),
                    "artifact_id": str(uuid4()),
                    "offset": 0,
                    "size": 32,
                    "case_id": str(uuid4()),
                }
            if mode == "invalid_input":
                fields["inputs"] = {"path": "not accepted by the health profile"}
            response = await client.post(url + "/action", headers=headers, json=fields)
            if mode == "case_link_failed":
                assert response.status == 400
                assert "X-NorthGate-Request-Outcome" not in response.headers
                assert len(store.list(endpoint)) == 1
                replay = await client.post(
                    url + "/action", headers=headers, json=fields
                )
                assert replay.status == 400
                assert "X-NorthGate-Request-Outcome" not in replay.headers
                assert len(store.list(endpoint)) == 1
                return
            if mode == "invalid_input":
                assert response.status == 400
                assert (
                    response.headers["X-NorthGate-Request-Outcome"]
                    == "rejected-before-queue"
                )
                assert not store.list(endpoint)
                fields["inputs"] = {}
                fields["request_id"] = str(uuid4())
                response = await client.post(
                    url + "/action", headers=headers, json=fields
                )
            elif mode not in {"normal", "existing_invalid_replay"}:
                assert response.status in {400, 403}
                if mode == "request_id":
                    assert (
                        response.headers["X-NorthGate-Request-Outcome"]
                        == "rejected-before-queue"
                    )
                else:
                    assert "X-NorthGate-Request-Outcome" not in response.headers
                assert not store.list(endpoint)
                return
            assert response.status == 202
            result = await response.json()
            replay = await client.post(url + "/action", headers=headers, json=fields)
            assert replay.status == 202
            assert await replay.json() == result
            assert len(store.list(endpoint)) == 1
            if mode == "existing_invalid_replay":
                fields["inputs"] = {"path": "invalid after an earlier job exists"}
                invalid = await client.post(
                    url + "/action", headers=headers, json=fields
                )
                assert invalid.status == 400
                assert "X-NorthGate-Request-Outcome" not in invalid.headers
                assert len(store.list(endpoint)) == 1

    asyncio.run(scenario())
