"""Regression cases from adversarial review of the modern workspace."""

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.domain import EndpointHealth, EndpointLifecycle, EndpointStatus
from northgate_rmm.fleet import Fleet
from northgate_rmm.fleet_access import load_grants
from northgate_rmm.fleet_admin import export_events
from northgate_rmm.fleet_models import validate_record
from northgate_rmm.management import Management
from northgate_rmm.management_protocol import validate_action
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.operator_api import OperatorApplication, OperatorAuthorizationPolicy
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import RemoteTarget
from tests.test_fleet import principal


def fixture(root: Path) -> tuple[Fleet, Any, list[dict[str, Any]]]:
    p = principal()
    rows: list[dict[str, Any]] = []
    targets: dict[UUID, tuple[RemoteTarget, dict[str, str]]] = {}
    for name in ("Alpha", "Beta"):
        endpoint, identity = uuid4(), uuid4()
        targets[endpoint] = (RemoteTarget(endpoint, identity, "10.20.30.40"), {})
        rows.append(
            {
                "id": str(endpoint),
                "identity": str(identity),
                "name": name,
                "platform": "linux",
                "lifecycle": "active",
                "health": "online",
                "managed": True,
                "worker_ready": True,
                "metadata": {},
                "capabilities": {"features": {"packages": True}},
                "changes": [],
                "last_job": None,
            }
        )

    def get_endpoint(key: UUID) -> Any:
        return SimpleNamespace(
            endpoint_id=key,
            identity_id=targets[key][0].identity_id,
            platform=SimpleNamespace(value="linux"),
        )

    def authenticate(token: str | None, **kwargs: Any) -> Any:
        if token != "Bearer synthetic":  # noqa: S105 -- synthetic verifier fixture
            raise ValueError("No authentication")
        return p

    operation = SimpleNamespace(
        _authenticate=authenticate,
        _authorization_denial=lambda *a, **k: None,
        _audit=lambda *a, **k: None,
        _policy=OperatorAuthorizationPolicy(p.issuer, p.tenant, p.subject, p.client_id),
        _store=SimpleNamespace(
            get_endpoint=get_endpoint,
            endpoint_status=lambda key, **kw: EndpointStatus(
                key, EndpointLifecycle.ACTIVE, EndpointHealth.ONLINE, datetime.now(UTC)
            ),
        ),
    )
    gateway = RemoteGateway(
        cast(OperatorApplication, operation),
        targets,
        b"x" * 16,
        "https://operator.test",
    )
    management = Management(gateway, ManagementStore(root, gateway.key))
    fleet = Fleet(management)
    cast(Any, fleet).inventory = lambda: rows
    for row in rows:
        management.store.seen(row["id"], row["identity"], row["capabilities"])
    return fleet, p, rows


def test_automation_cannot_replace_its_configured_group(tmp_path: Path) -> None:
    async def scenario() -> None:
        f, p, rows = fixture(tmp_path)
        group = str(uuid4())
        f.store.put("group", group, {"name": "Only Alpha", "parent": ""}, p.subject)
        rows[0]["metadata"]["group"] = group
        policy = str(uuid4())
        f.store.put(
            "policy",
            policy,
            validate_record("policy", {"name": "Scan", "action": "posture"}),
            p.subject,
        )
        auto = str(uuid4())
        f.store.put(
            "automation",
            auto,
            validate_record(
                "automation",
                {
                    "name": "Alpha only",
                    "policy": policy,
                    "group": group,
                    "enabled": True,
                },
            ),
            p.subject,
        )
        result = await f.preview({"policy": policy, "automation": auto}, p)
        assert [r["id"] for r in result["targets"]] == [rows[0]["id"]]

    asyncio.run(scenario())


def test_unseen_exercise_cannot_be_attached_to_rollout(tmp_path: Path) -> None:
    async def scenario() -> None:
        f, p, rows = fixture(tmp_path)
        exercise = str(uuid4())
        f.store.put("exercise", exercise, {"name": "Private"}, "other")
        technician = replace(p, subject="technician")
        f.gateway.operation._policy = replace(
            f.gateway.operation._policy,
            grants=load_grants(
                [
                    {
                        "subject": technician.subject,
                        "endpoints": [rows[0]["id"]],
                        "permissions": ["view", "manage"],
                    },
                ]
            ),
        )
        with pytest.raises(web.HTTPForbidden):
            await f.preview(
                {
                    "operation": {"name": "Scan", "action": "posture"},
                    "exercise": exercise,
                },
                technician,
            )

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "inputs", [{"x": 123}, {"x": "a" * 4097}, {"x": {"nested": True}}]
)
def test_reviewed_script_inputs_share_individual_action_contract(inputs: Any) -> None:
    with pytest.raises(ValueError):
        validate_action(
            "script.run",
            {"script_id": str(uuid4()), "version": "a" * 64, "inputs": inputs},
            "linux",
        )


def test_event_export_rejects_output_checkpoint_alias(tmp_path: Path) -> None:
    store = ManagementStore(tmp_path / "state", b"x" * 16)
    store.event("", "fleet", "fleet.rollout.completed", {"run": "one"})
    destination = tmp_path / "same.json"
    with pytest.raises(ValueError):
        export_events(store, destination, destination)
    assert not destination.exists()


def test_event_export_rejects_database_destination_before_writing(
    tmp_path: Path,
) -> None:
    store = ManagementStore(tmp_path / "state", b"x" * 16)
    store.event("", "fleet", "fleet.rollout.completed", {"run": "one"})
    before = store.path.read_bytes()
    with pytest.raises(ValueError):
        export_events(store, store.path, tmp_path / "cursor")
    assert store.path.read_bytes() == before


def test_changed_failed_job_reopens_acknowledged_alert(tmp_path: Path) -> None:
    async def scenario() -> None:
        f, p, rows = fixture(tmp_path)
        rule = next(
            r for r in f.store.list("rule") if r["value"]["condition"] == "job_failed"
        )
        rule["value"].update(delay=0)
        f.store.put("rule", rule["id"], rule["value"], "system", rule["revision"])
        rows[0]["last_job"] = {"id": "first", "state": "failed"}
        await f.reconcile_alerts(rows)
        alert = next(
            r for r in f.store.list("alert") if r["value"]["rule"] == rule["id"]
        )
        alert["value"]["state"] = "acknowledged"
        f.store.put("alert", alert["id"], alert["value"], p.subject, alert["revision"])
        rows[0]["last_job"] = {"id": "second", "state": "failed"}
        await f.reconcile_alerts(rows)
        assert f.store.get("alert", alert["id"])["value"]["state"] == "open"

    asyncio.run(scenario())


def test_expired_offline_jobs_are_reconciled_without_worker_poll(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        f, p, _rows = fixture(tmp_path)
        preview = await f.preview(
            {"operation": {"name": "Scan", "action": "posture"}}, p
        )
        result = await f.start({"preview": preview["id"]}, p, "Bearer synthetic")
        await f.advance(f.store.get("rollout", result["id"]))
        entry = f.store.get("rollout", result["id"])
        assert len(entry["value"]["jobs"]) == 1
        with f.m.store.connect() as db:
            db.execute("UPDATE jobs SET expires=?", (time.time() - 1,))
        await f.advance(entry)
        assert f.store.get("rollout", result["id"])["value"]["state"] == "failed"

    asyncio.run(scenario())


def test_fleet_http_scopes_csrf_and_assets(tmp_path: Path) -> None:
    async def scenario() -> None:
        f, _p, _rows = fixture(tmp_path)
        app = web.Application()
        f.register(app)
        # Deterministic HTTP contract; scheduler tested separately.
        app.cleanup_ctx.clear()
        async with TestClient(TestServer(app)) as client:
            assert (await client.get("/remote/fleet/api/state")).status == 403
            headers = {"Authorization": "Bearer synthetic", "Origin": f.gateway.origin}
            response = await client.get("/remote/fleet/ui", headers=headers)
            assert response.status == 200
            assert "frame-src 'self'" in response.headers["Content-Security-Policy"]
            for asset in ("fleet.js", "fleet.css"):
                assert (
                    await client.get("/remote/fleet/assets/" + asset, headers=headers)
                ).status == 200
            response = await client.get("/remote/fleet/api/state", headers=headers)
            state = await response.json()
            payload = {"kind": "group", "value": {"name": "Fixture"}}
            assert (
                await client.post(
                    "/remote/fleet/api/save", headers=headers, json=payload
                )
            ).status == 403
            headers["X-CSRF-Token"] = state["csrf"]
            assert (
                await client.post(
                    "/remote/fleet/api/save", headers=headers, json=payload
                )
            ).status == 200
            headers["Origin"] = "https://attacker.invalid"
            assert (
                await client.post(
                    "/remote/fleet/api/save", headers=headers, json=payload
                )
            ).status == 403

    asyncio.run(scenario())


def test_cancel_is_durable_before_a_transient_queue_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    async def scenario() -> None:
        f, p, _rows = fixture(tmp_path)
        preview = await f.preview(
            {"operation": {"name": "Scan", "action": "posture"}}, p
        )
        result = await f.start({"preview": preview["id"]}, p, "Bearer synthetic")
        await f.advance(f.store.get("rollout", result["id"]))
        entry = f.store.get("rollout", result["id"])
        cancel = f.m.store.cancel

        def unavailable(key: str) -> None:
            raise OSError("Synthetic interrupted queue write")

        monkeypatch.setattr(f.m.store, "cancel", unavailable)
        with pytest.raises(OSError):
            await f.control(
                {"id": result["id"], "revision": entry["revision"], "action": "cancel"},
                p,
            )
        durable = f.store.get("rollout", result["id"])
        assert durable["value"]["state"] == "cancelling"
        assert "authorization" not in durable["value"]
        monkeypatch.setattr(f.m.store, "cancel", cancel)
        await f.advance(durable)
        assert f.store.get("rollout", result["id"])["value"]["state"] == "cancelled"
        for key in durable["value"]["jobs"].values():
            assert f.m.store.job(key)["cancel"] == 1

    asyncio.run(scenario())


def test_export_cursor_cannot_silently_skip_after_output_loss(tmp_path: Path) -> None:
    store = ManagementStore(tmp_path / "state", b"x" * 16)
    output, checkpoint = tmp_path / "events.jsonl", tmp_path / "cursor.json"
    store.event("", "fleet", "fleet.rollout.completed", {"run": "one"})
    export_events(store, output, checkpoint)
    output.unlink()
    with pytest.raises(ValueError):
        export_events(store, output, checkpoint)


def test_removing_manage_grant_stops_already_queued_patch(tmp_path: Path) -> None:
    async def scenario() -> None:
        f, p, rows = fixture(tmp_path)
        target = rows[0]
        f.gateway.operation._policy = replace(
            f.gateway.operation._policy,
            subject="different-owner",
            grants=load_grants(
                [
                    {
                        "subject": p.subject,
                        "endpoints": [target["id"]],
                        "permissions": ["view", "patch"],
                    },
                ]
            ),
        )
        key = f.m.store.add(
            target["id"], target["identity"], p, "patches.scan", {}, "Bearer synthetic"
        )
        with pytest.raises(ValueError):
            await f.m.authorize_job(f.m.store.job(key, private=True))

    asyncio.run(scenario())


def test_crash_after_queue_insert_does_not_repeat_endpoint_action(
    tmp_path: Path, monkeypatch: Any
) -> None:
    async def scenario() -> None:
        f, p, _rows = fixture(tmp_path)
        preview = await f.preview(
            {"operation": {"name": "Scan", "action": "posture"}}, p
        )
        result = await f.start({"preview": preview["id"]}, p, "Bearer synthetic")
        put = f.store.put

        def interrupted(*args: Any, **kwargs: Any) -> Any:
            if args[0] == "rollout":
                raise OSError("Synthetic persistence interruption")
            return put(*args, **kwargs)

        monkeypatch.setattr(f.store, "put", interrupted)
        with pytest.raises(OSError):
            await f.advance(f.store.get("rollout", result["id"]))
        assert not f.store.get("rollout", result["id"])["value"]["jobs"]
        monkeypatch.setattr(f.store, "put", put)
        await f.advance(f.store.get("rollout", result["id"]))
        assert len(f.store.get("rollout", result["id"])["value"]["jobs"]) == 1
        with f.m.store.connect() as db:
            assert db.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1

    asyncio.run(scenario())


def test_canary_completion_requires_review_before_next_endpoint(tmp_path: Path) -> None:
    async def scenario() -> None:
        f, p, _rows = fixture(tmp_path)
        preview = await f.preview(
            {"operation": {"name": "Scan", "action": "posture"}}, p
        )
        run_id = (await f.start({"preview": preview["id"]}, p, "Bearer synthetic"))[
            "id"
        ]
        await f.advance(f.store.get("rollout", run_id))
        run = f.store.get("rollout", run_id)["value"]
        assert len(run["jobs"]) == 1
        key = next(iter(run["jobs"].values()))
        job = f.m.store.job(key)
        f.m.store.dispatch(key)
        f.m.store.result(
            job["endpoint"],
            job["identity"],
            key,
            {
                "state": "completed",
                "exit_code": 0,
                "output": "fixture",
                "execution_identity": "root",
                "truncated": False,
            },
        )
        await f.advance(f.store.get("rollout", run_id))
        entry = f.store.get("rollout", run_id)
        assert entry["value"]["state"] == "awaiting_review"
        assert len(entry["value"]["jobs"]) == 1
        await f.control(
            {"id": run_id, "revision": entry["revision"], "action": "resume"}, p
        )
        await f.advance(f.store.get("rollout", run_id))
        assert len(f.store.get("rollout", run_id)["value"]["jobs"]) == 2

    asyncio.run(scenario())


def test_scoped_http_state_and_direct_tool_requests_agree(tmp_path: Path) -> None:
    async def scenario() -> None:
        f, p, rows = fixture(tmp_path)
        technician = replace(p, subject="reader")
        cast(Any, f.gateway.operation)._authenticate = lambda *a, **kw: technician
        f.gateway.operation._policy = replace(
            f.gateway.operation._policy,
            grants=load_grants(
                [
                    {
                        "subject": technician.subject,
                        "endpoints": [rows[0]["id"]],
                        "permissions": ["view"],
                    },
                ]
            ),
        )
        app = web.Application()
        f.register(app)
        f.m.register(app)
        app.cleanup_ctx.clear()
        async with TestClient(TestServer(app)) as client:
            headers = {"Authorization": "Bearer synthetic", "Origin": f.gateway.origin}
            response = await client.get("/remote/fleet/api/state", headers=headers)
            body = await response.json()
            assert [d["id"] for d in body["devices"]] == [rows[0]["id"]]
            assert body["devices"][0]["permissions"] == []
            assert not body["admin"]
            for row in rows:
                assert (
                    await client.get(
                        "/remote/" + row["id"] + "/manage", headers=headers
                    )
                ).status == 403
            headers["X-CSRF-Token"] = body["csrf"]
            assert (
                await client.post(
                    "/remote/fleet/api/preview",
                    headers=headers,
                    json={
                        "operation": {"name": "Scan", "action": "posture"},
                    },
                )
            ).status == 200
            # Preview discloses an exclusion, never authorizes a read-only principal.
            denied = await client.post(
                "/remote/fleet/api/preview",
                headers=headers,
                json={
                    "operation": {"name": "Scan", "action": "posture"},
                },
            )
            preview = await denied.json()
            assert preview["targets"] == []
            assert (
                await client.post(
                    "/remote/fleet/api/start",
                    headers=headers,
                    json={
                        "preview": preview["id"],
                    },
                )
            ).status == 400

    asyncio.run(scenario())


def test_deleted_default_rule_stays_deleted_after_restart(tmp_path: Path) -> None:
    fleet, _p, _rows = fixture(tmp_path)
    rule = fleet.store.list("rule")[0]
    fleet.store.delete("rule", rule["id"], rule["revision"])
    restarted = Fleet(fleet.m)
    assert rule["id"] not in {r["id"] for r in restarted.store.list("rule")}


def test_fleet_edits_obey_management_storage_capacity(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fleet, p, _rows = fixture(tmp_path)

    def exhausted() -> None:
        raise ValueError("Management storage limit reached")

    monkeypatch.setattr(fleet.m.store, "maintain", exhausted)
    with pytest.raises(ValueError, match="storage limit"):
        fleet.store.put("group", str(uuid4()), {"name": "Cannot save"}, p.subject)
