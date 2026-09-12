"""Two real polling lanes: shell coexistence, mutation serialization and cancel."""

import asyncio
import base64
import json
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore


def test_diagnostic_lane_shell_mutation_and_independent_cancellation(tmp_path):
    async def scenario():
        endpoint, identity = uuid4(), uuid4()
        actor = SimpleNamespace(
            subject="owner",
            session_id="session",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        store = ManagementStore(tmp_path, bytes(range(16)))
        management = Management(SimpleNamespace(key=bytes(range(16))), store)

        async def peer(_):
            return SimpleNamespace(endpoint_id=endpoint), SimpleNamespace(
                identity_id=identity
            )

        async def authorize(_):
            pass

        management.worker_identity = peer
        management.authorize_job = authorize

        def add(action, params):
            return store.add(
                endpoint, identity, actor, action, params, "Bearer fixture"
            )

        def finish(job, state="completed"):
            store.result(
                endpoint,
                identity,
                job,
                {
                    "state": state,
                    "exit_code": 0,
                    "output": "synthetic receipt",
                    "truncated": False,
                    "execution_identity": "synthetic",
                },
            )

        health = {
            "tool_id": "health",
            "profile": "snapshot",
            "inputs": {},
            "case_id": "",
        }
        async with TestClient(TestServer(management.worker_application())) as client:

            async def poll(active="", diagnostic="", enabled=True):
                response = await client.post(
                    "/v1/management/poll",
                    json={
                        "nonce": "0123456789abcdef",
                        "active": active,
                        "diagnostic_active": diagnostic,
                        "capabilities": {"features": {"diagnostic_lane": enabled}},
                    },
                )
                assert response.status == 200, await response.text()
                return json.loads(base64.b64decode((await response.json())["payload"]))

            shell = add("shell.start", {"columns": 100, "rows": 30})
            management.shell_leases[shell] = time.time() + 300
            store.dispatch(shell)
            mutation = add(
                "service.control", {"name": "synthetic", "operation": "restart"}
            )
            diagnostic = add("tool.run", health)
            response = await poll(shell)
            assert response["job"] is None
            assert response["diagnostic_job"]["id"] == diagnostic
            assert store.job(mutation)["state"] == "queued"
            controls = {
                c["job"]: c for c in (await poll(shell, diagnostic))["controls"]
            }
            assert not controls[shell]["cancel"] and not controls[diagnostic]["cancel"]
            store.cancel(diagnostic)
            controls = {
                c["job"]: c for c in (await poll(shell, diagnostic))["controls"]
            }
            assert controls[diagnostic]["cancel"] and not controls[shell]["cancel"]
            finish(diagnostic, "cancelled")
            assert (await poll(shell))["job"] is None
            finish(shell)
            next_diagnostic = add("tool.run", health)
            response = await poll()
            assert (
                response["job"]["id"] == mutation and response["diagnostic_job"] is None
            )
            response = await poll(mutation)
            assert response["job"] is None and response["diagnostic_job"] is None
            assert store.job(next_diagnostic)["state"] == "queued"
            store.cancel(mutation)
            controls = {c["job"]: c for c in (await poll(mutation))["controls"]}
            assert controls[mutation]["cancel"]
            finish(mutation, "cancelled")
            response = await poll()
            assert response["diagnostic_job"]["id"] == next_diagnostic
            next_mutation = add(
                "service.control", {"name": "synthetic", "operation": "start"}
            )
            response = await poll(diagnostic=next_diagnostic)
            assert response["job"] is None and response["diagnostic_job"] is None
            assert store.job(next_mutation)["state"] == "queued"
            finish(next_diagnostic)
            assert (await poll())["job"]["id"] == next_mutation
            finish(next_mutation)
            legacy_job = add("tool.run", health)
            response = await poll(enabled=False)
            assert "diagnostic_job" not in response
            assert response["job"]["id"] == legacy_job
            rejected = await client.post(
                "/v1/management/poll",
                json={
                    "nonce": "0123456789abcdef",
                    "active": legacy_job,
                    "diagnostic_active": legacy_job,
                    "capabilities": {},
                },
            )
            assert rejected.status == 403

    asyncio.run(scenario())
