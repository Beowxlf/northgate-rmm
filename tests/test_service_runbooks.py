"""Unattended authority, durable execution and cancellation regression checks."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from aiohttp import web

from northgate_rmm.fleet import Fleet
from northgate_rmm.integration_auth import IntegrationEntry
from northgate_rmm.management import Management, diagnostic_action
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.native_api import NativeAPI
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.service_runbooks import (
    RunbookPlan,
    RunbookRun,
    ServiceRunbooks,
    load_plans,
)


def setup_runbook(
    tmp_path: Path,
) -> tuple[ServiceRunbooks, RunbookPlan, IntegrationEntry, list[str]]:
    endpoint, identity = str(uuid4()), str(uuid4())
    store = ManagementStore(tmp_path / "management", bytes(range(16)))
    plan: dict[str, Any] = {
        "id": str(uuid4()),
        "name": "Read posture then services",
        "client": "scheduled",
        "endpoints": {endpoint: identity},
        "steps": [
            {"name": "Posture", "action": "posture", "params": {}},
            {"name": "Services", "action": "services.list", "params": {}},
        ],
        "interval": 300,
        "window": {"days": list(range(7)), "start": "00:00", "end": "00:00"},
        "enabled": True,
        "concurrency": 1,
        "failure_limit": 1,
        "case_id": "",
    }
    path = tmp_path / "plans.json"
    path.write_text(json.dumps({"schema": 1, "plans": [plan]}))
    path.chmod(0o600)
    entry: IntegrationEntry = {
        "id": "scheduled",
        "token_sha256": "a" * 64,
        "enabled": True,
        "endpoints": {endpoint: identity},
        "actions": ["posture", "services.list"],
    }
    submissions = []

    async def submit(
        entry: dict[str, Any],
        e: str,
        device: SimpleNamespace,
        action: str,
        params: dict[str, Any],
        request_id: str,
    ) -> dict[str, str]:
        submissions.append(request_id)
        p = SimpleNamespace(
            subject="integration:scheduled",
            session_id=request_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        store.add(
            e,
            device.identity_id,
            cast(OperatorPrincipal, p),
            action,
            params,
            "service-ticket",
            identifier=request_id,
        )
        return {"job": request_id}

    native = SimpleNamespace(
        auth=SimpleNamespace(entries=lambda: {"scheduled": entry}),
        endpoint=lambda *args, **kw: (endpoint, SimpleNamespace(identity_id=identity)),
        submit=submit,
    )
    m = SimpleNamespace(store=store, gateway=SimpleNamespace(key=bytes(range(16))))
    scheduler = ServiceRunbooks(
        cast(Management, m), cast(Fleet, None), cast(NativeAPI, native), path
    )
    return scheduler, load_plans(path)[plan["id"]], entry, submissions


def complete(scheduler: ServiceRunbooks, job_id: str, state: str = "completed") -> None:
    job = scheduler.m.store.job(job_id)
    scheduler.m.store.dispatch(job_id)
    scheduler.m.store.result(
        job["endpoint"],
        job["identity"],
        job_id,
        {
            "state": state,
            "exit_code": 0 if state == "completed" else 1,
            "output": "verified",
            "execution_identity": "root",
            "truncated": False,
        },
    )


def test_plan_rejects_interactive_or_secret_actions(tmp_path: Path) -> None:
    scheduler, plan, _, _ = setup_runbook(tmp_path)
    serialized_plan = dict(plan)
    serialized_plan.pop("digest")
    for action in ("shell.start", "bitlocker.escrow", "recovery.rotate", "script.run"):
        plan["steps"][0]["action"] = action
        assert scheduler.path is not None
        scheduler.path.write_text(json.dumps({"schema": 1, "plans": [serialized_plan]}))
        with pytest.raises(ValueError):
            load_plans(scheduler.path)


def test_run_requires_current_grant_and_exact_enrollment(tmp_path: Path) -> None:
    scheduler, plan, entry, _ = setup_runbook(tmp_path)
    entry["enabled"] = False
    with pytest.raises(ValueError, match="revoked"):
        asyncio.run(scheduler.begin(plan, str(uuid4())))
    entry["enabled"] = True
    entry["endpoints"][next(iter(plan["endpoints"]))] = str(uuid4())
    with pytest.raises(ValueError, match="enrollment"):
        asyncio.run(scheduler.begin(plan, str(uuid4())))


def test_restart_preserves_sequence_and_request_identity(tmp_path: Path) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    identifier = str(uuid4())
    run = asyncio.run(scheduler.begin(plan, identifier))
    asyncio.run(scheduler.advance(run, plan))
    first = submissions[0]
    fresh = ServiceRunbooks(
        scheduler.m, cast(Fleet, None), scheduler.native, scheduler.path
    )
    resumed = asyncio.run(fresh.begin(plan, identifier))
    asyncio.run(fresh.advance(resumed, plan))
    assert submissions == [first]
    complete(fresh, first)
    asyncio.run(fresh.advance(resumed, plan))
    assert len(submissions) == 2 and submissions[1] != first
    complete(fresh, submissions[1])
    asyncio.run(fresh.advance(resumed, plan))
    assert fresh.runs(plan["id"])[0]["state"] == "completed"


def test_changed_plan_cancels_running_jobs(tmp_path: Path) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    run = asyncio.run(scheduler.begin(plan, str(uuid4())))
    asyncio.run(scheduler.advance(run, plan))
    asyncio.run(scheduler.advance(run, {**plan, "digest": "different"}))
    assert scheduler.m.store.job(submissions[0])["cancel"]
    assert scheduler.runs(plan["id"])[0]["state"] == "stopped"


def test_revoked_service_prevents_following_steps(tmp_path: Path) -> None:
    scheduler, plan, entry, submissions = setup_runbook(tmp_path)
    run = asyncio.run(scheduler.begin(plan, str(uuid4())))
    asyncio.run(scheduler.advance(run, plan))
    entry["actions"] = []
    asyncio.run(scheduler.advance(run, plan))
    assert len(submissions) == 1
    assert scheduler.runs(plan["id"])[0]["error"] == "Service authorization revoked"


def test_failed_step_stops_run_instead_of_reporting_success(tmp_path: Path) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    run = asyncio.run(scheduler.begin(plan, str(uuid4())))
    asyncio.run(scheduler.advance(run, plan))
    complete(scheduler, submissions[0], "failed")
    asyncio.run(scheduler.advance(run, plan))
    assert len(submissions) == 1
    assert scheduler.runs(plan["id"])[0]["state"] == "stopped"


def test_request_id_cannot_overwrite_different_plan(tmp_path: Path) -> None:
    scheduler, plan, _, _ = setup_runbook(tmp_path)
    identifier = str(uuid4())
    asyncio.run(scheduler.begin(plan, identifier))
    with pytest.raises(ValueError, match="another plan"):
        asyncio.run(scheduler.begin({**plan, "id": str(uuid4())}, identifier))


def test_request_id_replay_preserves_run_outside_recent_history(tmp_path: Path) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    identifier = str(uuid4())
    original = asyncio.run(scheduler.begin(plan, identifier))
    original["state"] = "completed"
    original["error"] = "retained original result"
    scheduler.save_run(original)
    for index in range(201):
        later: RunbookRun = {
            **original,
            "id": str(uuid4()),
            "created": original["created"] + index + 1,
        }
        scheduler.save_run(later)
    assert all(row["id"] != identifier for row in scheduler.runs(plan["id"]))
    replay = asyncio.run(scheduler.begin(plan, identifier))
    assert replay == original
    assert replay["state"] == "completed" and submissions == []


def test_request_id_rejects_changed_plan_version(tmp_path: Path) -> None:
    scheduler, plan, _, _ = setup_runbook(tmp_path)
    identifier = str(uuid4())
    original = asyncio.run(scheduler.begin(plan, identifier))
    with pytest.raises(ValueError, match="different plan version"):
        asyncio.run(scheduler.begin({**plan, "digest": "changed"}, identifier))
    assert scheduler.runs(plan["id"])[0] == original


@pytest.mark.parametrize(
    "has_authorizer,has_sink", [(False, True), (True, False), (False, False)]
)
def test_case_run_requires_both_authorizer_and_evidence_sink(
    tmp_path: Path, has_authorizer: bool, has_sink: bool
) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    plan["case_id"] = str(uuid4())

    async def callback(*args: object) -> None:
        return None

    scheduler.case_authorizer = callback if has_authorizer else None
    scheduler.evidence_sink = callback if has_sink else None
    with pytest.raises(ValueError, match="case authorization and an evidence sink"):
        asyncio.run(scheduler.begin(plan, str(uuid4())))
    assert scheduler.runs() == [] and submissions == []


def test_denied_case_cannot_start_or_replay_run(tmp_path: Path) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    plan["case_id"] = str(uuid4())
    permitted = True

    async def authorizer(entry: IntegrationEntry, target: RunbookPlan) -> None:
        assert target["case_id"] == plan["case_id"]
        if not permitted:
            raise web.HTTPForbidden(text="Case scope revoked")

    async def sink(*args: object) -> None:
        return None

    scheduler.case_authorizer, scheduler.evidence_sink = authorizer, sink
    identifier = str(uuid4())
    asyncio.run(scheduler.begin(plan, identifier))
    permitted = False
    for request_id in (identifier, str(uuid4())):
        with pytest.raises(web.HTTPForbidden):
            asyncio.run(scheduler.begin(plan, request_id))
    assert len(scheduler.runs()) == 1 and submissions == []


def test_case_permission_is_checked_again_after_retaining_previous_step(
    tmp_path: Path,
) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    plan["case_id"] = str(uuid4())
    permitted = True
    retained = []

    async def authorizer(entry: IntegrationEntry, target: RunbookPlan) -> None:
        if not permitted:
            raise web.HTTPConflict(text="Case closed")

    async def sink(entry: IntegrationEntry, case_id: str, job_id: str) -> None:
        nonlocal permitted
        retained.append(job_id)
        permitted = False

    scheduler.case_authorizer, scheduler.evidence_sink = authorizer, sink
    run = asyncio.run(scheduler.begin(plan, str(uuid4())))
    asyncio.run(scheduler.advance(run, plan))
    complete(scheduler, submissions[0])
    asyncio.run(scheduler.advance(run, plan))
    assert len(submissions) == 1 and retained == submissions
    assert scheduler.runs()[0]["state"] == "stopped"


def test_case_revocation_cancels_inflight_job(tmp_path: Path) -> None:
    scheduler, plan, _, submissions = setup_runbook(tmp_path)
    plan["case_id"] = str(uuid4())
    permitted = True

    async def authorizer(*args: object) -> None:
        if not permitted:
            raise web.HTTPForbidden()

    async def sink(*args: object) -> None:
        return None

    scheduler.case_authorizer, scheduler.evidence_sink = authorizer, sink
    run = asyncio.run(scheduler.begin(plan, str(uuid4())))
    asyncio.run(scheduler.advance(run, plan))
    permitted = False
    asyncio.run(scheduler.advance(run, plan))
    assert len(submissions) == 1
    assert scheduler.m.store.job(submissions[0])["cancel"]
    assert scheduler.runs()[0]["state"] == "stopped"


@pytest.mark.parametrize(
    "plan_linked,tool_linked,matching",
    [
        (True, False, False),
        (False, True, False),
        (True, True, False),
        (True, True, True),
    ],
)
def test_tool_step_requires_matching_runbook_case(
    tmp_path: Path, plan_linked: bool, tool_linked: bool, matching: bool
) -> None:
    scheduler, plan, _, _ = setup_runbook(tmp_path)
    serialized_plan = dict(plan)
    serialized_plan.pop("digest")
    case_id = str(uuid4())
    plan["case_id"] = case_id if plan_linked else ""
    params: dict[str, object] = {"tool_id": "health", "profile": "history"}
    if tool_linked:
        params["case_id"] = case_id if matching else str(uuid4())
    plan["steps"] = [{"name": "Tool", "action": "tool.run", "params": params}]
    assert scheduler.path is not None
    serialized_plan = {key: value for key, value in plan.items() if key != "digest"}
    scheduler.path.write_text(json.dumps({"schema": 1, "plans": [serialized_plan]}))
    if matching:
        assert load_plans(scheduler.path)[plan["id"]]["case_id"] == case_id
    else:
        with pytest.raises(ValueError, match="Tool step case must match"):
            load_plans(scheduler.path)


@pytest.mark.parametrize(
    "action,params,allowed",
    [
        ("tool.verify", {"tool_id": "osquery"}, True),
        ("tool.run", {"tool_id": "health", "profile": "history"}, True),
        ("tool.run", {"tool_id": "osquery", "profile": "system"}, True),
        ("tool.run", {"tool_id": "evidence", "profile": "bundle"}, False),
        ("tool.install", {}, False),
        ("service.control", {}, False),
    ],
)
def test_diagnostic_lane_excludes_mutations_and_heavy_collectors(
    action: str, params: dict[str, Any], allowed: bool
) -> None:
    assert diagnostic_action(action, params) is allowed
