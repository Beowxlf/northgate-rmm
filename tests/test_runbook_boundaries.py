"""Deployment validation and authenticated runbook HTTP/scheduler boundaries."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.fleet import Fleet
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.service_runbooks import load_plans
from tests.test_service_runbooks import setup_runbook


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "invalid"),
        ("name", ""),
        ("client", 3),
        ("enabled", 1),
        ("interval", 299),
        ("concurrency", 5),
        ("failure_limit", 0),
        ("endpoints", {}),
        ("endpoints", {"invalid": "invalid"}),
        ("case_id", "invalid"),
        ("steps", []),
        ("steps", [{"name": "x"}]),
        ("steps", [{"name": "", "action": "posture", "params": {}}]),
        ("steps", [{"name": "x", "action": "posture", "params": "bad"}]),
        ("steps", [{"name": "x", "action": "posture", "params": {"big": "x" * 32769}}]),
    ],
)
def test_malformed_runbook_deployment_fails_closed(
    tmp_path: Path, field: str, value: object
) -> None:
    scheduler, plan, _, _ = setup_runbook(tmp_path)
    record = dict(plan)
    record.pop("digest")
    record[field] = value
    assert scheduler.path is not None
    scheduler.path.write_text(json.dumps({"schema": 1, "plans": [record]}))
    with pytest.raises(ValueError):
        load_plans(scheduler.path)


@pytest.mark.parametrize(
    "configuration",
    [
        {},
        {"schema": 2, "plans": []},
        {"schema": 1, "plans": {}},
        {"schema": 1, "plans": [{}]},
        {"schema": 1, "plans": [{}] * 65},
    ],
)
def test_invalid_runbook_envelope(tmp_path: Path, configuration: object) -> None:
    path = tmp_path / "plans.json"
    path.write_text(json.dumps(configuration))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_plans(path)
    assert load_plans(None) == {}


class RunbookFleet:
    def __init__(self) -> None:
        now = datetime.now(UTC)
        self.user = OperatorPrincipal(
            "https://idp.test",
            "lab",
            "owner",
            "session",
            "rmm",
            ("operator",),
            now,
            now + timedelta(hours=1),
            True,
        )
        self.audits: list[str] = []

    async def principal(self, request: web.Request) -> OperatorPrincipal:
        return self.user

    def csrf(self, principal: OperatorPrincipal) -> str:
        return "synthetic-csrf"

    def headers(self) -> dict[str, str]:
        return {"Cache-Control": "no-store"}

    async def audit(self, principal: OperatorPrincipal, action: str, plan: str) -> None:
        self.audits.append(action)


def test_http_runbook_scope_pause_resume_and_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        scheduler, plan, entry, _ = setup_runbook(tmp_path)
        fleet = RunbookFleet()
        scheduler.fleet = cast(Fleet, fleet)
        allowed = True
        monkeypatch.setattr(
            scheduler.m.gateway, "origin", "https://operator.test", raising=False
        )
        policy = SimpleNamespace(permits=lambda *args: allowed)
        monkeypatch.setattr(
            scheduler.m.gateway,
            "operation",
            SimpleNamespace(_policy=policy),
            raising=False,
        )
        app = web.Application()
        scheduler.register(app)
        # Tick is driven explicitly below to avoid timing races.
        app.cleanup_ctx.clear()
        base = "/remote/runbooks"
        headers = {"Origin": "https://operator.test", "X-CSRF-Token": "synthetic-csrf"}
        async with TestClient(TestServer(app)) as http:
            state = await http.get(base + "/state")
            assert state.status == 200
            payload = await state.json()
            assert payload["plans"][0]["ready"] is True
            assert payload["configured"] is True
            entry["enabled"] = False
            payload = await (await http.get(base + "/state")).json()
            assert payload["plans"][0]["ready"] is False
            entry["enabled"] = True
            allowed = False
            payload = await (await http.get(base + "/state")).json()
            assert payload["plans"] == []
            request = {"plan": plan["id"], "action": "run", "request_id": str(uuid4())}
            assert (
                await http.post(base + "/action", json=request, headers=headers)
            ).status == 403
            allowed = True
            assert (await http.post(base + "/action", json=request)).status == 403
            assert (
                await http.post(
                    base + "/action",
                    json=request,
                    headers={"Origin": headers["Origin"]},
                )
            ).status == 403
            assert (
                await http.post(base + "/action", data="{}", headers=headers)
            ).status == 415
            assert (
                await http.post(base + "/action", json={}, headers=headers)
            ).status == 400
            request["action"] = "unsupported"
            assert (
                await http.post(base + "/action", json=request, headers=headers)
            ).status == 400
            request["action"] = "pause"
            assert (
                await http.post(base + "/action", json=request, headers=headers)
            ).status == 200
            assert scheduler.settings(plan["id"])["paused"] is True
            request["action"] = "resume"
            assert (
                await http.post(base + "/action", json=request, headers=headers)
            ).status == 200
            assert scheduler.settings(plan["id"])["paused"] is False
            request["action"] = "run"
            assert (
                await http.post(base + "/action", json=request, headers=headers)
            ).status == 200
            request["action"] = "pause"
            assert (
                await http.post(base + "/action", json=request, headers=headers)
            ).status == 200
            assert scheduler.runs(plan["id"])[0]["state"] == "stopped"
            assert fleet.audits == [
                "runbook.pause",
                "runbook.resume",
                "runbook.run",
                "runbook.pause",
            ]
            assert scheduler.path is not None
            scheduler.path.write_text("{}")
            assert (await http.get(base + "/state")).status == 503

    asyncio.run(scenario())


def test_tick_starts_due_plan_once_and_cancels_when_configuration_disappears(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        scheduler, plan, _, submissions = setup_runbook(tmp_path)
        await scheduler.tick()
        assert scheduler.last_tick is not None and scheduler.last_error is None
        assert len(scheduler.runs(plan["id"], active=True)) == 1
        await scheduler.tick()
        assert len(submissions) == 1
        assert scheduler.settings(plan["id"])["next_due"] > time.time()
        assert scheduler.path is not None
        scheduler.path.write_text("{}")
        with pytest.raises(ValueError):
            await scheduler.tick()
        assert scheduler.runs(plan["id"])[0]["state"] == "stopped"
        assert scheduler.m.store.job(submissions[0])["cancel"]

    asyncio.run(scenario())


def test_runbook_start_guards_and_missing_native(tmp_path: Path) -> None:
    scheduler, plan, _, _ = setup_runbook(tmp_path)
    plan["enabled"] = False
    with pytest.raises(ValueError, match="disabled"):
        asyncio.run(scheduler.begin(plan, str(uuid4())))
    plan["enabled"] = True
    plan["window"] = {"days": [], "start": "00:00", "end": "00:00"}
    with pytest.raises(ValueError, match="maintenance"):
        asyncio.run(scheduler.begin(plan, str(uuid4())))
    plan["window"]["days"] = list(range(7))
    asyncio.run(scheduler.begin(plan, str(uuid4())))
    with pytest.raises(ValueError, match="active run"):
        asyncio.run(scheduler.begin(plan, str(uuid4())))
    scheduler.native = None
    with pytest.raises(ValueError, match="not configured"):
        scheduler.authority(plan)
    run = scheduler.runs()[0]
    asyncio.run(scheduler.advance(run, plan))
    assert run["state"] == "stopped"
