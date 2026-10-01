"""Fleet inventory provenance, mutable-record guards and evidence coverage."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.domain import (
    Endpoint,
    EndpointHealth,
    EndpointLifecycle,
    EndpointStatus,
    Platform,
)
from northgate_rmm.fleet import Fleet
from northgate_rmm.fleet_models import validate_record
from northgate_rmm.fleet_store import Conflict
from northgate_rmm.management_protocol import canonical
from northgate_rmm.operator_api import OperatorPrincipal
from tests.test_fleet_review import fixture
from tests.test_management import receipt


@pytest.mark.parametrize("reader", ["snapshot", "paged"])
def test_inventory_binds_capabilities_and_baselines_to_current_enrollment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    fleet, actor, rows = fixture(tmp_path / "management")
    p = cast(OperatorPrincipal, actor)
    now = datetime.now(UTC)
    endpoints = [
        Endpoint(
            UUID(row["id"]),
            row["name"],
            Platform.LINUX,
            "amd64",
            UUID(row["identity"]),
            now,
        )
        for row in rows
    ]
    endpoints.extend(
        Endpoint(uuid4(), f"Unmanaged{i}", Platform.LINUX, "amd64", uuid4(), now)
        for i in range(99)
    )

    def status(endpoint: UUID, **kwargs: object) -> EndpointStatus:
        return EndpointStatus(
            endpoint,
            EndpointLifecycle.ACTIVE,
            EndpointHealth.ONLINE,
            now if endpoint == endpoints[0].endpoint_id else None,
        )

    source = fleet.gateway.operation._store
    if reader == "snapshot":
        monkeypatch.setattr(
            source,
            "fleet_snapshot",
            lambda **_: [
                (endpoint, status(endpoint.endpoint_id)) for endpoint in endpoints
            ],
            raising=False,
        )
    else:
        pages = iter([endpoints[:100], endpoints[100:]])
        monkeypatch.setattr(
            source, "list_endpoint_page", lambda **_: next(pages), raising=False
        )
        monkeypatch.setattr(source, "endpoint_status", status)
    first = rows[0]["id"]
    fleet.store.put("asset", first, {"name": "Reviewed alias"}, p.subject)
    fleet.store.put(
        "baseline",
        first,
        {"created": 1.0, "snapshot": {"architecture": "arm64", "platform": "linux"}},
        p.subject,
    )
    fleet.m.store.seen(rows[1]["id"], uuid4(), {"private_old_enrollment": True})
    job = fleet.m.store.add(
        endpoints[0].endpoint_id,
        endpoints[0].identity_id,
        p,
        "recovery.rotate",
        {},
        "Bearer synthetic",
    )
    fleet.m.store.dispatch(job)
    fleet.m.store.result(
        endpoints[0].endpoint_id,
        endpoints[0].identity_id,
        job,
        receipt("synthetic escrow fixture"),
    )
    actual = Fleet.inventory(fleet)
    assert len(actual) == 101
    assert actual[0]["name"] == "Reviewed alias" and actual[0]["worker_ready"]
    assert actual[0]["changes"] == [
        {"field": "architecture", "before": "arm64", "after": "amd64"}
    ]
    assert actual[0]["last_job"]["id"] == job
    assert actual[0]["recovery_receipts"][0]["kind"] == "recovery.rotate"
    assert not actual[1]["worker_ready"] and actual[1]["capabilities"] == {}
    assert not actual[2]["managed"] and actual[2]["worker_seen"] is None
    assert actual[1]["last_seen"] is None


def test_record_mutations_require_owner_revision_and_acyclic_dependencies(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        fleet, actor, rows = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)

        async def save(
            kind: str, value: dict[str, object], **extra: object
        ) -> dict[str, Any]:
            return await fleet.perform(
                "save", {"kind": kind, "value": value, **extra}, p, "Bearer synthetic"
            )

        parent = await save("group", {"name": "Parent"})
        child = await save("group", {"name": "Child", "parent": parent["id"]})
        rows[0]["metadata"]["group"] = child["id"]
        assert fleet.members(parent["id"], rows) == [rows[0]]
        with pytest.raises(ValueError, match="no longer exists"):
            fleet.members(str(uuid4()), rows)
        with pytest.raises(ValueError, match="contain themselves"):
            await save(
                "group",
                {"name": "Cycle", "parent": child["id"]},
                id=parent["id"],
                revision=parent["revision"],
            )
        with pytest.raises(ValueError, match="dependent"):
            await fleet.perform(
                "delete",
                {"kind": "group", "id": parent["id"], "revision": parent["revision"]},
                p,
                "Bearer synthetic",
            )
        asset = await save(
            "asset", {"name": "Renamed", "group": child["id"]}, id=rows[0]["id"]
        )
        assert asset["value"]["group"] == child["id"]
        policy = await save("policy", {"name": "Read", "action": "posture"})
        automation = await save(
            "automation", {"name": "Periodic read", "policy": policy["id"]}
        )
        assert automation["value"]["policy"] == policy["id"]
        with pytest.raises(ValueError, match="dependent"):
            await fleet.perform(
                "delete",
                {"kind": "policy", "id": policy["id"], "revision": policy["revision"]},
                p,
                "Bearer synthetic",
            )
        other = replace(p, subject="other")
        for operation in ("save", "delete"):
            with pytest.raises(web.HTTPForbidden):
                await fleet.perform(
                    operation,
                    {
                        "kind": "group",
                        "id": parent["id"],
                        "value": {"name": "Forbidden"},
                    },
                    other,
                    "Bearer synthetic",
                )
        view = await save("view", {"name": "Owner view"})
        with pytest.raises(web.HTTPForbidden):
            await fleet.perform(
                "save",
                {
                    "kind": "view",
                    "id": view["id"],
                    "revision": view["revision"],
                    "value": {"name": "Changed"},
                },
                other,
                "Bearer synthetic",
            )
        with pytest.raises(web.HTTPForbidden):
            await fleet.perform(
                "delete",
                {"kind": "view", "id": view["id"], "revision": view["revision"]},
                other,
                "Bearer synthetic",
            )
        assert (
            await fleet.perform(
                "delete",
                {"kind": "view", "id": view["id"], "revision": view["revision"]},
                p,
                "Bearer synthetic",
            )
        )["deleted"] == view["id"]
        with pytest.raises(ValueError, match="Unknown"):
            await fleet.perform("unknown", {}, p, "Bearer synthetic")

    asyncio.run(scenario())


def test_baseline_and_alert_transitions_keep_revision_and_scope_checks(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        fleet, actor, rows = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        endpoint = rows[0]["id"]
        rows[0]["snapshot"] = {"architecture": "amd64"}
        first = await fleet.perform(
            "baseline", {"endpoint": endpoint}, p, "Bearer synthetic"
        )
        second = await fleet.perform(
            "baseline", {"endpoint": endpoint}, p, "Bearer synthetic"
        )
        assert second["revision"] == first["revision"] + 1
        rows[0]["worker_ready"] = False
        with pytest.raises(ValueError, match="authenticated worker"):
            await fleet.perform(
                "baseline", {"endpoint": endpoint}, p, "Bearer synthetic"
            )
        with pytest.raises(web.HTTPForbidden):
            await fleet.perform(
                "baseline",
                {"endpoint": endpoint},
                replace(p, roles=("viewer",)),
                "Bearer synthetic",
            )
        alert = fleet.store.put(
            "alert", str(uuid4()), {"endpoint": endpoint, "state": "open"}, "system"
        )
        for state in ("snoozed", "acknowledged", "resolved", "open"):
            alert = await fleet.perform(
                "alert",
                {
                    "id": alert["id"],
                    "revision": alert["revision"],
                    "state": state,
                    "seconds": 60,
                    "note": "Reviewed",
                },
                p,
                "Bearer synthetic",
            )
            assert alert["value"]["state"] == state
            assert bool(alert["value"]["snooze_until"]) == (state == "snoozed")
        with pytest.raises(ValueError, match="Invalid alert"):
            await fleet.perform(
                "alert",
                {"id": alert["id"], "revision": alert["revision"], "state": "invalid"},
                p,
                "Bearer synthetic",
            )
        with pytest.raises(web.HTTPForbidden):
            await fleet.perform(
                "alert",
                {"id": alert["id"], "state": "open"},
                replace(p, roles=("viewer",)),
                "Bearer synthetic",
            )

    asyncio.run(scenario())


def test_rollout_export_excludes_command_output_and_binds_digest(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        fleet, actor, _rows = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        exercise = fleet.store.put(
            "exercise", str(uuid4()), {"name": "Evidence fixture"}, p.subject
        )
        preview = await fleet.preview(
            {
                "operation": {"name": "Read posture", "action": "posture"},
                "exercise": exercise["id"],
            },
            p,
        )
        started = await fleet.start({"preview": preview["id"]}, p, "Bearer synthetic")
        await fleet.advance(fleet.store.get("rollout", started["id"]))
        entry = fleet.store.get("rollout", started["id"])
        job = next(iter(entry["value"]["jobs"].values()))
        saved = fleet.m.store.job(job)
        fleet.m.store.dispatch(job)
        fleet.m.store.result(
            saved["endpoint"],
            saved["identity"],
            job,
            receipt("must-not-export-command-output"),
        )
        exported = await fleet.perform(
            "export", {"exercise": exercise["id"]}, p, "Bearer synthetic"
        )
        assert (
            exported["sha256"]
            == hashlib.sha256(canonical(exported["data"])).hexdigest()
        )
        assert exported["data"]["runs"][0]["jobs"][0]["id"] == job
        assert "must-not-export" not in json.dumps(exported)
        assert "authorization" not in json.dumps(exported)
        assert (await fleet.export({}, p))["data"]["exercise"] is None
        with pytest.raises(web.HTTPForbidden):
            await fleet.export(
                {"exercise": exercise["id"]}, replace(p, subject="other")
            )
        with pytest.raises(Conflict):
            await fleet.control(
                {"id": started["id"], "revision": 999, "action": "pause"}, p
            )
        paused = await fleet.control(
            {"id": started["id"], "revision": entry["revision"], "action": "pause"}, p
        )
        assert paused["state"] == "paused"
        current = fleet.store.get("rollout", started["id"])
        before = current["revision"]
        await fleet.advance(current)
        assert fleet.store.get("rollout", started["id"])["revision"] == before
        with pytest.raises(ValueError, match="approving session"):
            await fleet.control(
                {"id": started["id"], "revision": before, "action": "resume"},
                replace(p, session_id="other-session"),
            )
        assert (
            await fleet.control(
                {"id": started["id"], "revision": before, "action": "resume"}, p
            )
        )["state"] == "scheduled"

    asyncio.run(scenario())


@pytest.mark.parametrize("broken", [False, True])
def test_scheduler_records_only_sanitized_failure_and_releases_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    broken: bool,
) -> None:
    async def scenario() -> None:
        fleet, _, _ = fixture(tmp_path / "management")
        if broken:

            def failure() -> list[dict[str, Any]]:
                raise RuntimeError("sensitive request data")

            monkeypatch.setattr(fleet, "inventory", failure)

        async def stop_sleep(seconds: float) -> None:
            assert seconds == 10
            raise asyncio.CancelledError()

        monkeypatch.setattr(asyncio, "sleep", stop_sleep)
        with pytest.raises(asyncio.CancelledError):
            await fleet.scheduler()
        assert bool(fleet.last_error) == broken
        assert (fleet.last_tick is None) == broken
        assert "sensitive request data" not in caplog.text
        context = fleet.lifecycle(web.Application())
        await anext(context)
        with pytest.raises(StopAsyncIteration):
            await anext(context)

    asyncio.run(scenario())


def test_mutation_parser_rejects_nonobject_or_oversized_requests(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        fleet, actor, _ = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        app = web.Application()
        # Register API routes without starting the unrelated scheduler.
        app.router.add_post("/remote/fleet/api/{operation}", fleet.mutate)
        headers = {
            "Authorization": "Bearer synthetic",
            "Origin": fleet.gateway.origin,
            "X-CSRF-Token": fleet.csrf(p),
        }
        async with TestClient(TestServer(app)) as client:
            payloads: list[object] = [[], "invalid", {"oversized": "x" * 262144}]
            for payload in payloads:
                response = await client.post(
                    "/remote/fleet/api/save", json=payload, headers=headers
                )
                assert response.status == 400
            assert (
                await client.post(
                    "/remote/fleet/api/save", data="not-json", headers=headers
                )
            ).status == 400

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "defect",
    [
        "platform",
        "unmanaged",
        "offline",
        "packages",
        "permission",
        "role",
        "selection_type",
        "selection_limit",
        "selection_missing",
        "inactive",
        "group",
    ],
)
def test_preview_excludes_unready_devices_and_rejects_invalid_target_scope(
    tmp_path: Path, defect: str
) -> None:
    async def scenario() -> None:
        from northgate_rmm.fleet_access import load_grants

        fleet, actor, rows = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        value: dict[str, Any] = {
            "operation": {"name": "Read posture", "action": "posture"}
        }
        expected: str | None = None
        if defect == "platform":
            value["operation"]["platform"] = "windows"
            expected = "Platform"
        if defect == "unmanaged":
            rows[0]["managed"] = False
            expected = "Management enrollment"
        if defect == "offline":
            rows[0]["health"] = "offline"
            expected = "offline"
        if defect == "packages":
            value["operation"]["action"] = "patches.scan"
            rows[0]["capabilities"]["features"]["packages"] = False
            expected = "Package manager"
        if defect == "permission":
            p = replace(p, subject="scoped-technician")
            fleet.gateway.operation._policy = replace(
                fleet.gateway.operation._policy,
                grants=load_grants(
                    [
                        {
                            "subject": p.subject,
                            "endpoints": [row["id"] for row in rows],
                            "permissions": ["view"],
                        }
                    ]
                ),
            )
            expected = "permissions"
        if defect == "role":
            p = replace(p, roles=("viewer",))
        if defect == "selection_type":
            value["endpoints"] = "not-a-list"
        if defect == "selection_limit":
            value["endpoints"] = [rows[0]["id"]] * 501
        if defect == "selection_missing":
            value["endpoints"] = [str(uuid4())]
        if defect == "inactive":
            for row in rows:
                row["lifecycle"] = "revoked"
        if defect == "group":
            value["group"] = str(uuid4())
        if expected:
            result = await fleet.preview(value, p)
            assert (
                result["excluded"]
                and expected.lower() in result["excluded"][0]["reason"].lower()
            )
            if defect in {"platform", "permission"}:
                assert result["targets"] == []
            else:
                assert [target["id"] for target in result["targets"]] == [rows[1]["id"]]
        else:
            with pytest.raises(web.HTTPForbidden if defect == "role" else ValueError):
                await fleet.preview(value, p)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "defect",
    [
        "disabled",
        "group",
        "policy_changed",
        "automation_changed",
        "expired",
        "no_targets",
    ],
)
def test_start_revalidates_preview_and_automation_revisions(
    tmp_path: Path, defect: str
) -> None:
    async def scenario() -> None:
        fleet, actor, rows = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        policy = fleet.store.put(
            "policy",
            str(uuid4()),
            validate_record("policy", {"name": "Read", "action": "posture"}),
            p.subject,
        )
        auto = fleet.store.put(
            "automation",
            str(uuid4()),
            validate_record(
                "automation",
                {
                    "name": "Recurring",
                    "policy": policy["id"],
                    "enabled": defect != "disabled",
                },
            ),
            p.subject,
        )
        value = {"policy": policy["id"], "automation": auto["id"]}
        if defect == "group":
            value["group"] = str(uuid4())
        if defect in {"disabled", "group"}:
            with pytest.raises(ValueError):
                await fleet.preview(value, p)
            return
        if defect == "no_targets":
            for row in rows:
                row["worker_ready"] = False
        preview = await fleet.preview(value, p)
        if defect == "policy_changed":
            fleet.store.put(
                "policy", policy["id"], policy["value"], p.subject, policy["revision"]
            )
        if defect == "automation_changed":
            fleet.store.put(
                "automation", auto["id"], auto["value"], p.subject, auto["revision"]
            )
        if defect == "expired":
            stored = fleet.store.get("preview", preview["id"])
            fleet.store.put(
                "preview",
                preview["id"],
                {**stored["value"], "expires": 0},
                p.subject,
                stored["revision"],
            )
        with pytest.raises(Conflict if defect.endswith("changed") else ValueError):
            await fleet.start({"preview": preview["id"]}, p, "Bearer synthetic")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "condition",
    [
        "expired",
        "authorization",
        "capacity",
        "enrollment",
        "worker",
        "scheduled",
        "failure_limit",
    ],
)
def test_advance_tracks_failures_and_never_dispatches_after_binding_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, condition: str
) -> None:
    from northgate_rmm.management_store import QueueFull

    async def scenario() -> None:
        fleet, actor, rows = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        preview = await fleet.preview(
            {"operation": {"name": "Read", "action": "posture"}}, p
        )
        key = (await fleet.start({"preview": preview["id"]}, p, "Bearer synthetic"))[
            "id"
        ]
        entry = fleet.store.get("rollout", key)
        if condition == "expired":
            entry["value"]["expires"] = 0
        if condition == "authorization":
            entry["value"]["session"] = "different-session"
        if condition == "capacity":

            async def full(*args: object) -> None:
                raise QueueFull("Synthetic queue capacity")

            monkeypatch.setattr(fleet, "advance_authorized", full)
        if condition == "enrollment":
            entry["value"]["targets"][0]["identity"] = str(uuid4())
        if condition == "worker":
            fleet.m.store.seen(rows[0]["id"], uuid4(), {})
        if condition == "scheduled":
            entry["value"]["next_due"] = time.time() + 300
        if condition == "failure_limit":
            entry["value"]["errors"][rows[0]["id"]] = "Synthetic dispatch failure"
        await fleet.advance(entry)
        saved = fleet.store.get("rollout", key)["value"]
        assert saved["jobs"] == {}
        expected = {
            "expired": "expired",
            "authorization": "failed",
            "capacity": "waiting_capacity",
            "enrollment": "canary",
            "worker": "canary",
            "scheduled": "scheduled",
            "failure_limit": "failed",
        }[condition]
        assert saved["state"] == expected
        if condition in {"expired", "authorization", "failure_limit"}:
            assert "authorization" not in saved
        if condition in {"enrollment", "worker"}:
            assert rows[0]["id"] in saved["errors"]

    asyncio.run(scenario())


@pytest.mark.parametrize("change", ["cycle", "automation_changed", "policy_changed"])
def test_automation_repeats_only_with_unchanged_approved_policy(
    tmp_path: Path, change: str
) -> None:
    async def scenario() -> None:
        fleet, actor, _ = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        policy = fleet.store.put(
            "policy",
            str(uuid4()),
            validate_record(
                "policy",
                {
                    "name": "Recurring observation",
                    "action": "posture",
                    "review_canary": False,
                },
            ),
            p.subject,
        )
        automation = fleet.store.put(
            "automation",
            str(uuid4()),
            validate_record(
                "automation",
                {
                    "name": "Reviewed schedule",
                    "policy": policy["id"],
                    "enabled": True,
                    "interval": 300,
                },
            ),
            p.subject,
        )
        preview = await fleet.preview(
            {"policy": policy["id"], "automation": automation["id"]}, p
        )
        started = await fleet.start({"preview": preview["id"]}, p, "Bearer synthetic")
        assert (
            await fleet.start({"preview": preview["id"]}, p, "Bearer synthetic")
            == started
        )
        for _ in range(2):
            await fleet.advance(fleet.store.get("rollout", started["id"]))
            current = fleet.store.get("rollout", started["id"])
            for job_id in current["value"]["jobs"].values():
                job = fleet.m.store.job(job_id)
                if job["state"] == "queued":
                    fleet.m.store.dispatch(job_id)
                    fleet.m.store.result(
                        job["endpoint"],
                        job["identity"],
                        job_id,
                        receipt("Synthetic completed observation"),
                    )
        await fleet.advance(fleet.store.get("rollout", started["id"]))
        current = fleet.store.get("rollout", started["id"])
        assert (
            current["value"]["cycle"] == 1 and current["value"]["state"] == "scheduled"
        )
        assert (
            current["value"]["jobs"] == {} and len(current["value"]["history"][0]) == 2
        )
        if change == "cycle":
            return
        record, kind = (
            (automation, "automation")
            if change == "automation_changed"
            else (policy, "policy")
        )
        fleet.store.put(
            kind, record["id"], record["value"], p.subject, record["revision"]
        )
        await fleet.advance(current)
        changed = fleet.store.get("rollout", started["id"])["value"]
        assert changed["state"] == "failed" and "authorization" not in changed
        assert changed["jobs"] == {}

    asyncio.run(scenario())


@pytest.mark.parametrize("condition", ["valid", "missing", "tampered", "platform"])
def test_fleet_script_dispatch_rechecks_reviewed_content(
    tmp_path: Path, condition: str
) -> None:
    from northgate_rmm.management_protocol import seal

    async def scenario() -> None:
        fleet, actor, _ = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        script_id = str(uuid4())
        script = {
            "content": "printf synthetic",
            "inputs": [],
            "platform": "windows" if condition == "platform" else "linux",
            "author": p.subject,
        }
        version = hashlib.sha256(canonical(script)).hexdigest()
        if condition == "tampered":
            script["content"] = "changed after review"
        if condition != "missing":
            with fleet.m.store.connect() as db:
                db.execute(
                    "INSERT INTO scripts VALUES (?,?,?,?)",
                    (
                        script_id,
                        version,
                        time.time(),
                        seal(fleet.gateway.key, script, script_id + "/" + version),
                    ),
                )
        preview = await fleet.preview(
            {
                "operation": {
                    "name": "Reviewed script",
                    "action": "script.run",
                    "platform": "linux",
                    "params": {
                        "script_id": script_id,
                        "version": version,
                        "inputs": {},
                    },
                }
            },
            p,
        )
        run_id = (await fleet.start({"preview": preview["id"]}, p, "Bearer synthetic"))[
            "id"
        ]
        await fleet.advance(fleet.store.get("rollout", run_id))
        run = fleet.store.get("rollout", run_id)["value"]
        if condition == "valid":
            job_id = next(iter(run["jobs"].values()))
            assert (
                fleet.m.store.job(job_id, private=True)["payload"]["params"]["content"]
                == "printf synthetic"
            )
        else:
            assert run["state"] == "failed" and run["jobs"] == {}
            assert "authorization" not in run

    asyncio.run(scenario())


def test_alert_resolution_and_snooze_do_not_erase_active_condition(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        fleet, actor, rows = fixture(tmp_path / "management")
        p = cast(OperatorPrincipal, actor)
        # Isolate one immediate rule so each transition has an unambiguous cause.
        for item in fleet.store.list("rule"):
            fleet.store.delete("rule", item["id"], item["revision"])
        fleet.store.put(
            "rule",
            str(uuid4()),
            validate_record(
                "rule", {"name": "Offline", "condition": "offline", "delay": 0}
            ),
            p.subject,
        )
        rows[0]["health"] = "offline"
        await fleet.reconcile_alerts(rows)
        alert = fleet.store.list("alert")[0]
        for state in ("resolved", "snoozed"):
            updated = await fleet.perform(
                "alert",
                {
                    "id": alert["id"],
                    "revision": alert["revision"],
                    "state": state,
                    "seconds": 60,
                },
                p,
                "Bearer synthetic",
            )
            await fleet.reconcile_alerts(rows)
            alert = fleet.store.get("alert", updated["id"])
            assert (
                alert["value"]["state"] == state and alert["value"]["condition_active"]
            )
        rows[0]["health"] = "online"
        await fleet.reconcile_alerts(rows)
        resolved = fleet.store.get("alert", alert["id"])
        assert (
            resolved["value"]["state"] == "resolved"
            and not resolved["value"]["condition_active"]
        )
        assert "resolved_at" in resolved["value"]

    asyncio.run(scenario())
