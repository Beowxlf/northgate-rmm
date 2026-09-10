from __future__ import annotations

import asyncio
import json
import re
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.domain import EndpointHealth, Platform
from northgate_rmm.errors import AuthorizationError
from northgate_rmm.inspection import (
    InspectionStore,
    InspectionUI,
    compare,
    validate_result,
)
from northgate_rmm.remote_gateway import RemoteGateway
from tests.test_remote_access import NOW, POLICY, PRINCIPAL, STATUS, TARGET


def result(rows=None, status="ok"):
    return {
        "schema": 1,
        "category": "services",
        "platform": "linux",
        "agent_version": "test",
        "collected_at": NOW.isoformat(),
        "duration_ms": 12,
        "exit_code": 0,
        "status": status,
        "error": "",
        "records": rows if rows is not None else [{"id": "ssh", "state": "running"}],
    }


def test_comparison_detects_add_remove_change_and_preserves_duplicates():
    before = [{"id": "a", "state": "old"}, {"id": "gone"}]
    after = [{"id": "a", "state": "new"}, {"id": "new"}, {"id": "new"}]
    diff = compare(before, after)
    assert len(diff["added"][0]) == 2
    assert diff["removed"][0][0]["id"] == "gone"
    assert diff["changed"][0]["before"][0]["state"] == "old"
    assert not any(compare(after, list(reversed(after))).values())


def test_baseline_survives_history_retention_and_rejects_other_identity(tmp_path):
    store = InspectionStore(tmp_path / "inspection.db")
    id = store.add(
        TARGET.endpoint_id, TARGET.identity_id, "services", "owner", result()
    )
    store.save_baseline(TARGET.endpoint_id, TARGET.identity_id, "services", id, "owner")
    with pytest.raises(ValueError):
        store.save_baseline(uuid4(), TARGET.identity_id, "services", id, "owner")
    for _ in range(101):
        store.add(TARGET.endpoint_id, TARGET.identity_id, "services", "owner", result())
    assert (
        store.baseline(TARGET.endpoint_id, TARGET.identity_id, "services")["run_id"]
        == id
    )
    assert store.baseline(TARGET.endpoint_id, uuid4(), "services") is None
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 100


@pytest.mark.parametrize("status", ["error", "partial"])
def test_incomplete_result_cannot_become_baseline(tmp_path, status):
    store = InspectionStore(tmp_path / "inspection.db")
    id = store.add(
        TARGET.endpoint_id,
        TARGET.identity_id,
        "services",
        "owner",
        result(status=status),
    )
    with pytest.raises(ValueError):
        store.save_baseline(
            TARGET.endpoint_id, TARGET.identity_id, "services", id, "owner"
        )


@pytest.mark.parametrize(
    "change",
    [
        {"category": "shell"},
        {"records": [{"id": "a", "x": "a" * 5000}]},
        {"records": [{"value": "missing id"}]},
        {"collected_at": "2026-01-01"},
    ],
)
def test_rejects_malformed_collector_response(change):
    with pytest.raises(ValueError):
        validate_result({**result(), **change}, "services")


def test_inspection_http_authorization_csrf_baseline_and_offline_history(tmp_path):
    class Operation:
        _policy = POLICY
        health = STATUS
        _store = None

        def _authenticate(self, authorization, **kwargs):
            if authorization != "Bearer synthetic":
                raise AuthorizationError("denied")
            return PRINCIPAL

        def _audit(self, *args, **kwargs):
            pass

    op = Operation()
    op._store = SimpleNamespace(
        get_endpoint=lambda id: SimpleNamespace(
            identity_id=TARGET.identity_id, platform=Platform.LINUX
        ),
        endpoint_status=lambda id, now: op.health,
    )
    calls = []

    async def runner(*args):
        calls.append(args[-1])
        return result([{"id": "<script>alert(1)</script>", "state": "running"}])

    async def scenario():
        gateway = RemoteGateway(
            op, {TARGET.endpoint_id: (TARGET, {})}, bytes(16), "https://operator.test"
        )
        store = InspectionStore(tmp_path / "http.db")
        ui = InspectionUI(gateway, store, runner)
        app = gateway.application()
        ui.register(app)
        async with TestClient(TestServer(app)) as client:
            path = f"/remote/{TARGET.endpoint_id}/inspect?category=services"
            headers = {
                "Authorization": "Bearer synthetic",
                "Origin": "https://operator.test",
            }
            assert (await client.get(path)).status == 403
            response = await client.get(path, headers=headers)
            assert response.status == 200
            # Fleet embeds this real handler in the same-origin device workspace.
            assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
            policy = response.headers["Content-Security-Policy"]
            assert "frame-ancestors 'self'" in policy
            assert "frame-ancestors 'none'" not in policy
            assert "default-src 'none'" in policy
            assert "form-action 'self'" in policy
            nonce = re.search('name="nonce" value="([^"]+)"', await response.text())[1]
            response = await client.post(
                path,
                headers={**headers, "Origin": "https://evil.test"},
                data={"nonce": nonce, "action": "collect"},
            )
            assert response.status == 403 and not calls
            response = await client.post(
                path,
                headers=headers,
                data={"nonce": nonce, "action": "collect"},
                allow_redirects=False,
            )
            assert response.status == 303 and calls == ["services"]
            assert (
                await client.post(
                    path, headers=headers, data={"nonce": nonce, "action": "collect"}
                )
            ).status == 403
            response = await client.get(path, headers=headers)
            html = await response.text()
            assert "&lt;script&gt;" in html and "<script>" not in html
            nonce = re.search('name="nonce" value="([^"]+)"', html)[1]
            id = store.history(TARGET.endpoint_id, TARGET.identity_id, "services")[0][
                "id"
            ]
            assert (
                await client.post(
                    path,
                    headers=headers,
                    data={"nonce": nonce, "action": "baseline", "run": id},
                    allow_redirects=False,
                )
            ).status == 303
            assert (
                json.loads(
                    store.baseline(TARGET.endpoint_id, TARGET.identity_id, "services")[
                        "payload"
                    ]
                )["status"]
                == "ok"
            )
            native = path + "&format=json"
            assert (await client.get(native)).status == 403
            response = await client.get(native, headers=headers)
            assert response.headers["Cache-Control"] == "no-store"
            data = await response.json()
            assert data["category"] == "services"
            assert data["current"]["id"] == id
            assert "<script>" in data["current"]["result"]["records"][0]["id"]
            assert "payload" not in data["history"][0]
            assert data["baseline"]["saved"]
            assert data["comparison"]["changed"]["count"] == 0
            form = {"nonce": data["nonce"], "action": "baseline", "run": id}
            assert (
                await client.post(
                    native,
                    headers={**headers, "Origin": "https://evil.test"},
                    data=form,
                )
            ).status == 403
            response = await client.post(native, headers=headers, data=form)
            assert response.status == 200 and await response.json() == {"saved": True}
            assert (await client.post(native, headers=headers, data=form)).status == 403
            data = await (await client.get(native, headers=headers)).json()
            response = await client.post(
                native,
                headers=headers,
                data={
                    "nonce": data["nonce"],
                    "action": "collect",
                },
            )
            assert response.status == 200 and await response.json() == {"saved": True}
            op.health = replace(STATUS, health=EndpointHealth.OFFLINE)
            assert (await client.get(path, headers=headers)).status == 200
            assert (await client.get(native, headers=headers)).status == 200
            assert (
                await client.post(path, headers=headers, data={"action": "collect"})
            ).status == 403
            assert (
                await client.get(path + "&run=" + str(uuid4()), headers=headers)
            ).status == 404

    asyncio.run(scenario())
