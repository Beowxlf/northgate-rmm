"""Meaningful transactional, scope, custody and intake qualification."""

import asyncio
import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.control_plane import ControlPlane
from northgate_rmm.domain import Endpoint, EndpointIdentity, EndpointLifecycle, Platform
from northgate_rmm.operations import Operations
from northgate_rmm.operations_models import MAX_CHUNK, check_secrets
from northgate_rmm.operations_store import Conflict, OperationsStore
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.remote_policy import RemoteTarget


@pytest.fixture
def rig(tmp_path: Any) -> Any:
    now = datetime.now(UTC)
    devices = ControlPlane()
    enrolled = [
        devices.enroll_synthetic_endpoint(
            display_name="Operations test " + str(i),
            platform=platform,
            architecture="amd64",
            public_key_fingerprint="sha256:"
            + hashlib.sha256(str(i).encode()).hexdigest(),
            now=now,
        )
        for i, platform in enumerate((Platform.WINDOWS, Platform.LINUX))
    ]
    endpoints = [str(e.endpoint_id) for e, _ in enrolled]
    identities = {str(e.endpoint_id): str(i.identity_id) for e, i in enrolled}
    actors = {
        name: OperatorPrincipal(
            issuer="https://idp.example",
            tenant="test",
            client_id="operations-test",
            subject=name,
            session_id=name + "-session",
            mfa=True,
            roles=("viewer", "remote_operator"),
            authenticated_at=now,
            expires_at=now + timedelta(hours=1),
        )
        for name in ("owner", "alice", "bob")
    }
    grants = {"alice": {endpoints[0]}, "bob": {endpoints[1]}}
    permissions = {
        "ops.view",
        "case.manage",
        "infrastructure.manage",
        "evidence.manage",
    }
    policy = SimpleNamespace(
        subject="owner",
        admits=lambda s: s in actors,
        permits=lambda s, e, p: (
            s == "owner" or (str(e) in grants.get(s, set()) and p in permissions)
        ),
    )
    gateway = SimpleNamespace(
        key=b"k" * 16,
        origin="https://operator.example",
        targets={uuid_value(e): None for e in endpoints},
        operation=SimpleNamespace(_policy=policy, _store=devices),
    )
    jobs: dict[str, Any] = {}
    management = SimpleNamespace(
        gateway=gateway, store=SimpleNamespace(job=lambda j: jobs[j]), integration=None
    )

    async def principal(request: Any) -> Any:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer ") or header[7:] not in actors:
            raise web.HTTPForbidden()
        return actors[header[7:]]

    fleet = SimpleNamespace(principal=principal, admin=lambda p: p.subject == "owner")
    store = OperationsStore.sqlite_for_tests(
        tmp_path / "ops.db", tmp_path / "artifacts", gateway.key
    )
    operations = Operations(management, fleet, store)
    return SimpleNamespace(
        ops=operations,
        store=store,
        actors=actors,
        endpoints=endpoints,
        identities=identities,
        devices=devices,
        grants=grants,
        permissions=permissions,
        jobs=jobs,
    )


def uuid_value(value: Any) -> Any:
    from uuid import UUID

    return UUID(value)


def replace_enrollment(rig: Any, endpoint: str) -> None:
    """Model a real domain-record replacement without fabricating its attributes."""
    old: Endpoint = rig.devices.get_endpoint(uuid_value(endpoint))
    old_identity: EndpointIdentity = rig.devices.get_identity(old.identity_id)
    identity = replace(old_identity, identity_id=uuid4())
    rig.devices._identities[identity.identity_id] = identity
    rig.devices._endpoints[old.endpoint_id] = replace(
        old, identity_id=identity.identity_id
    )
    rig.identities[endpoint] = str(identity.identity_id)


def call(
    rig: Any, operation: str, value: Any, actor: Any = "owner", request: Any = None
) -> Any:
    return rig.ops.dispatch(
        rig.actors[actor], operation, {**value, "request_id": request or str(uuid4())}
    )


def wazuh_source(rig: Any) -> dict[str, Any]:
    return {
        "id": "northgate-wazuh",
        "agents": {
            "020": {
                "endpoint": rig.endpoints[0],
                "identity": rig.identities[rig.endpoints[0]],
            }
        },
        "detections": {
            "110101": {
                "id": "PM-WIN-PS-001",
                "version": "1.0.0",
                "severity": "high",
                "attack": ["T1059.001"],
                "context_fields": ["win.eventdata.commandLine"],
                "checklist": ["Confirm actor", "Decode without execution"],
            }
        },
        "case_policies": [
            {
                "id": "project-mati-high",
                "enabled": True,
                "rule_ids": ["110101"],
                "minimum_level": 10,
                "group_by": ["endpoint", "detection_id"],
                "window_seconds": 3600,
                "closed_behavior": "new_case",
                "owner": "SOC",
                "team": "SOC",
            }
        ],
    }


def wazuh_alert(identifier: str = "1700000000.1") -> dict[str, Any]:
    return {
        "id": identifier,
        "timestamp": "2026-09-11T18:00:00+00:00",
        "agent": {"id": "020"},
        "rule": {
            "id": "110101",
            "level": 12,
            "description": "Suspicious PowerShell encoded execution",
            "groups": ["project_mati", "powershell"],
        },
        "context": {"win.eventdata.commandLine": "powershell.exe -EncodedCommand test"},
    }


def test_wazuh_alert_auto_creates_groups_and_deduplicates_soc_case(rig: Any) -> None:
    source = wazuh_source(rig)
    first = rig.ops.ingest_wazuh(source, wazuh_alert())
    assert first["duplicate"] is False
    assert first["case"]
    case = rig.store.get("case", first["case"])
    assert case["value"]["type"] == "soc"
    assert case["value"]["category"] == "security"
    assert case["value"]["disposition"] == "undetermined"
    assert case["value"]["containment_status"] == "not_started"
    assert case["value"]["resolution_code"] == "not_set"
    assert case["value"]["alerts"] == [first["alert"]]
    assert case["value"]["automation"]["window_seconds"] == 3600
    assert len(case["value"]["tasks"]) == 2
    alert = rig.store.get("alert", first["alert"])
    assert alert["value"]["attack"] == ["T1059.001"]

    duplicate = rig.ops.ingest_wazuh(source, wazuh_alert())
    assert duplicate == {
        "alert": first["alert"],
        "case": first["case"],
        "duplicate": True,
    }
    assert len(rig.store.records("case")) == 1

    related = rig.ops.ingest_wazuh(source, wazuh_alert("1700000000.2"))
    assert related["case"] == first["case"]
    assert len(rig.store.records("case")) == 1
    assert (
        rig.store.get("case", first["case"])["value"]["automation"]["alert_count"] == 2
    )


def test_closed_case_is_not_reopened_by_new_alert(rig: Any) -> None:
    source = wazuh_source(rig)
    first = rig.ops.ingest_wazuh(source, wazuh_alert())
    with rig.store.lock, rig.store.connection(write=True) as db:
        case = rig.store.get("case", first["case"], db)
        case["value"]["status"] = "closed"
        rig.store.put(db, "case", case["id"], case["value"], "test", case["revision"])
    second = rig.ops.ingest_wazuh(source, wazuh_alert("1700000000.3"))
    assert second["case"] != first["case"]
    assert len(rig.store.records("case")) == 2


def test_soc_resolution_requires_classification_and_containment(rig: Any) -> None:
    case = save(rig, type="soc", category="security")
    case = call(
        rig,
        "case_transition",
        {"id": case["id"], "revision": case["revision"], "status": "triage"},
    )["record"]
    with pytest.raises(ValueError, match="SOC resolution requires"):
        call(
            rig,
            "case_transition",
            {
                "id": case["id"],
                "revision": case["revision"],
                "status": "resolved",
                "outcome": "Controlled test confirmed",
                "verification": "Alert and endpoint evidence reviewed",
            },
        )
    resolved = call(
        rig,
        "case_transition",
        {
            "id": case["id"],
            "revision": case["revision"],
            "status": "resolved",
            "outcome": "Controlled test confirmed",
            "verification": "Alert and endpoint evidence reviewed",
            "disposition": "test_activity",
            "containment_status": "not_required",
            "resolution_code": "no_action",
        },
    )["record"]
    assert resolved["value"]["disposition"] == "test_activity"
    assert resolved["value"]["containment_status"] == "not_required"
    assert resolved["value"]["resolution_code"] == "no_action"


def save(
    rig: Any,
    kind: str = "case",
    name: str = "Investigation",
    endpoints: Any = None,
    actor: Any = "owner",
    **extra: Any,
) -> Any:
    value: dict[str, Any] = {
        "name": name,
        "endpoints": rig.endpoints[:1] if endpoints is None else endpoints,
        **extra,
    }
    return call(rig, "save", {"kind": kind, "value": value, "revision": 0}, actor)[
        "record"
    ]


def test_case_cannot_close_without_tasks_and_verified_outcome(rig: Any) -> None:
    case = save(rig, assignee="alice")
    case = call(
        rig,
        "case_transition",
        {"id": case["id"], "revision": case["revision"], "status": "in_progress"},
    )["record"]
    case = call(
        rig,
        "case_task",
        {
            "id": case["id"],
            "revision": case["revision"],
            "task": {"title": "Verify DNS", "assignee": "alice", "status": "todo"},
        },
    )["record"]
    with pytest.raises(ValueError, match="outstanding tasks"):
        call(
            rig,
            "case_transition",
            {
                "id": case["id"],
                "revision": case["revision"],
                "status": "resolved",
                "outcome": "DNS repaired",
                "verification": "Repeated lookup successful",
            },
        )
    task = case["value"]["tasks"][0]
    with pytest.raises(ValueError):
        call(
            rig,
            "case_task",
            {
                "id": case["id"],
                "revision": case["revision"],
                "task": {**task, "status": "done"},
            },
        )
    case = call(
        rig,
        "case_task",
        {
            "id": case["id"],
            "revision": case["revision"],
            "task": {
                **task,
                "status": "done",
                "verification": "Lookup returned approved resolver",
            },
        },
    )["record"]
    case = call(
        rig,
        "case_transition",
        {
            "id": case["id"],
            "revision": case["revision"],
            "status": "resolved",
            "outcome": "DNS repaired",
            "verification": "Repeated lookup successful",
        },
    )["record"]
    case = call(
        rig,
        "case_transition",
        {"id": case["id"], "revision": case["revision"], "status": "closed"},
    )["record"]
    assert case["value"]["closed_at"] > 0
    assert rig.ops.snapshot(rig.actors["owner"])["metrics"]["verified_closed"] == 1


def test_idempotent_create_stale_revision_and_revoked_replay(rig: Any) -> None:
    request = str(uuid4())
    value: dict[str, Any] = {
        "kind": "case",
        "revision": 0,
        "value": {"name": "Original", "endpoints": rig.endpoints[:1]},
    }
    a = call(rig, "save", value, "alice", request)
    assert call(rig, "save", value, "alice", request) == a
    with pytest.raises(Conflict):
        call(
            rig,
            "save",
            {**value, "value": {**value["value"], "name": "Changed"}},
            "alice",
            request,
        )
    assert len(rig.store.records("case")) == 1
    case = a["record"]
    updated = call(
        rig,
        "save",
        {
            "kind": "case",
            "id": case["id"],
            "revision": 1,
            "value": {"name": "New title", "endpoints": rig.endpoints[:1]},
        },
        "alice",
    )
    with pytest.raises(Conflict):
        call(
            rig,
            "save",
            {
                "kind": "case",
                "id": case["id"],
                "revision": 1,
                "value": {"name": "Stale title", "endpoints": rig.endpoints[:1]},
            },
            "alice",
        )
    assert updated["record"]["revision"] == 2
    assert rig.store.versions("case", case["id"])[-1]["value"]["name"] == "Original"
    rig.grants["alice"] = set()
    with pytest.raises(web.HTTPForbidden):
        call(rig, "save", value, "alice", request)


def test_case_scope_is_all_devices_and_cannot_be_narrowed_to_leak_history(
    rig: Any,
) -> None:
    case = save(rig, endpoints=rig.endpoints)
    assert rig.ops.snapshot(rig.actors["alice"])["cases"] == []
    with pytest.raises(web.HTTPForbidden):
        rig.ops.record_detail(rig.actors["alice"], "case", case["id"])
    call(
        rig,
        "save",
        {
            "kind": "case",
            "id": case["id"],
            "revision": 1,
            "value": {"name": "Still sensitive", "endpoints": rig.endpoints[:1]},
        },
    )
    assert rig.store.get("case", case["id"])["value"]["endpoints"] == sorted(
        rig.endpoints
    )
    with pytest.raises(ValueError, match="Assignee"):
        save(rig, endpoints=rig.endpoints, assignee="alice")


def test_relationship_scopes_follow_dependency_growth(rig: Any) -> None:
    asset = save(rig, "asset", "Workstation")
    service = save(rig, "service", "Application", assets=[asset["id"]])
    case = save(rig, services=[service["id"]])
    assert rig.ops.record_detail(rig.actors["alice"], "case", case["id"])
    call(
        rig,
        "save",
        {
            "kind": "asset",
            "id": asset["id"],
            "revision": 1,
            "value": {"name": "Shared host", "endpoints": rig.endpoints},
        },
    )
    with pytest.raises(web.HTTPForbidden):
        rig.ops.record_detail(rig.actors["alice"], "case", case["id"])


def test_reconciliation_is_explicit_and_preserves_documents(rig: Any) -> None:
    asset = save(rig, "asset", "Stable workstation")
    document = save(
        rig,
        "document",
        "Recovery procedure",
        assets=[asset["id"]],
        content="Contact the owner and verify the repair",
        document_type="runbook",
    )
    endpoint = rig.endpoints[0]
    old = rig.identities[endpoint]
    first = call(
        rig,
        "reconcile",
        {
            "asset": asset["id"],
            "endpoint": endpoint,
            "identity": old,
            "reason": "Verified VM identifier",
        },
    )
    replace_enrollment(rig, endpoint)
    with pytest.raises(Conflict):
        call(
            rig,
            "reconcile",
            {
                "asset": asset["id"],
                "endpoint": endpoint,
                "identity": old,
                "reason": "Stale mapping",
            },
        )
    call(
        rig,
        "reconcile",
        {
            "asset": asset["id"],
            "endpoint": endpoint,
            "identity": rig.identities[endpoint],
            "reason": "Owner verified reinstall",
        },
    )
    assert first["record"]["id"] == asset["id"]
    assert rig.store.get("document", document["id"])["value"]["assets"] == [asset["id"]]
    with rig.store.connection() as db:
        assert (
            db.execute("SELECT count(*) AS n FROM ops_enrollments").fetchone()["n"] == 2
        )


@pytest.mark.parametrize("operation", ["reconcile", "wazuh"])
@pytest.mark.parametrize(
    "fault",
    [
        "pending",
        "issued",
        "retired",
        "revoked",
        "missing_endpoint",
        "missing_identity",
        "foreign_identity",
    ],
)
def test_current_enrollment_uses_real_identity_lifecycle_and_binding(
    rig: Any, operation: str, fault: str
) -> None:
    endpoint = rig.endpoints[0]
    device = rig.devices.get_endpoint(uuid_value(endpoint))
    identity = rig.devices.get_identity(device.identity_id)
    assert isinstance(device, Endpoint) and isinstance(identity, EndpointIdentity)
    assert not hasattr(device, "lifecycle")
    asset = save(rig, "asset", "Stable test asset")
    if fault == "missing_endpoint":
        del rig.devices._endpoints[device.endpoint_id]
    elif fault == "missing_identity":
        del rig.devices._identities[identity.identity_id]
    elif fault == "foreign_identity":
        rig.devices._identities[identity.identity_id] = replace(
            identity, endpoint_id=uuid_value(rig.endpoints[1])
        )
    elif fault == "revoked":
        rig.devices.revoke_identity(
            identity.identity_id,
            reason="Qualification revocation",
            actor_id="owner",
            now=datetime.now(UTC),
        )
    else:
        rig.devices._identities[identity.identity_id] = replace(
            identity, status=EndpointLifecycle(fault)
        )
    with pytest.raises(Conflict):
        if operation == "reconcile":
            call(
                rig,
                "reconcile",
                {
                    "asset": asset["id"],
                    "endpoint": endpoint,
                    "identity": str(identity.identity_id),
                    "reason": "Verified host",
                },
            )
        else:
            rig.ops.ingest_wazuh(
                {
                    "id": "wazuh-contract",
                    "agents": {
                        "001": {
                            "endpoint": endpoint,
                            "identity": str(identity.identity_id),
                        }
                    },
                },
                {
                    "id": "event-contract",
                    "agent": {"id": "001"},
                    "timestamp": "2026-09-09T12:00:00Z",
                    "rule": {"id": "1001", "level": 8, "description": "Fixture alert"},
                },
            )
    assert rig.store.get("asset", asset["id"])["revision"] == 1
    assert rig.store.records("alert") == []
    with rig.store.connection() as db:
        assert (
            db.execute("SELECT count(*) AS n FROM ops_enrollments").fetchone()["n"] == 0
        )


def test_resumable_encrypted_evidence_integrity_and_retention(rig: Any) -> None:
    case = save(rig)
    data = b"A" * MAX_CHUNK + b"last segment"
    item = call(
        rig,
        "upload_begin",
        {
            "case": case["id"],
            "name": "diagnostics.txt",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "media_type": "text/plain",
            "redacted": True,
        },
    )["upload"]
    for index in [1, 0]:
        part = data[index * MAX_CHUNK : (index + 1) * MAX_CHUNK]
        v = {
            "upload": item["id"],
            "index": index,
            "data": base64.b64encode(part).decode(),
            "sha256": hashlib.sha256(part).hexdigest(),
        }
        call(rig, "upload_chunk", v)
        assert call(rig, "upload_chunk", v)["upload"]["received"] <= len(data)
    result = call(rig, "upload_finish", {"upload": item["id"]})["upload"]
    assert result["state"] == "complete" and result["retained"]
    assert rig.store.read_chunk(item["id"], 1) == b"last segment"
    assert b"last segment" not in rig.store._path(item["id"], 1).read_bytes()
    assert rig.store.cleanup_partials() == 0
    assert rig.store.artifact(item["id"])["state"] == "complete"
    with pytest.raises(web.HTTPForbidden):
        call(rig, "upload_cancel", {"upload": item["id"]}, "bob")


def test_partial_cancel_releases_reservation_and_cannot_be_downloaded(rig: Any) -> None:
    case = save(rig)
    data = b"bounded report"
    item = call(
        rig,
        "upload_begin",
        {
            "case": case["id"],
            "name": "partial.txt",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "media_type": "text/plain",
            "redacted": True,
        },
    )["upload"]
    with pytest.raises(Conflict, match="missing chunks"):
        call(rig, "upload_finish", {"upload": item["id"]})
    call(rig, "upload_cancel", {"upload": item["id"]})
    rig.store.cleanup_partials()
    assert not rig.store.artifact(item["id"])["retained"]


@pytest.mark.parametrize(
    "value",
    [
        {"password": "example"},
        {"private_key": "value"},
        "-----BEGIN " + "PRIVATE KEY-----",
        "123456-123456-123456-123456-123456-123456-123456-123456",
        "access_token=" + "abcdefghijklmnop",
    ],
)
def test_secret_patterns_are_not_accepted_as_notes(value: Any) -> None:
    with pytest.raises(ValueError):
        check_secrets(value)


def test_pin_copies_final_receipt_and_rejects_secret_jobs(rig: Any) -> None:
    case = save(rig)
    key = str(uuid4())
    rig.jobs[key] = {
        "id": key,
        "endpoint": rig.endpoints[0],
        "identity": rig.identities[rig.endpoints[0]],
        "action": "posture",
        "state": "completed",
        "created": 100,
        "receipt": {"output": "Firewall enabled", "exit_code": 0},
    }
    evidence = call(rig, "pin_job", {"case": case["id"], "job": key})["evidence"]
    del rig.jobs[key]
    assert evidence["state"] == "complete"
    assert json.loads(rig.store.read_chunk(evidence["id"], 0))["action"] == "posture"
    rig.jobs[key] = {"endpoint": rig.endpoints[0], "action": "bitlocker.escrow"}
    with pytest.raises(web.HTTPForbidden):
        call(rig, "pin_job", {"case": case["id"], "job": key})


def test_wazuh_normalizes_deduplicates_and_rejects_stale_identity(rig: Any) -> None:
    endpoint = rig.endpoints[0]
    source = {
        "id": "wazuh-test",
        "agents": {"001": {"endpoint": endpoint, "identity": rig.identities[endpoint]}},
    }
    event: dict[str, Any] = {
        "id": "123.abc",
        "timestamp": "2026-09-09T12:00:00Z",
        "agent": {"id": "001"},
        "rule": {
            "id": "1001",
            "level": 8,
            "description": "Startup configuration changed",
            "groups": ["syscheck"],
        },
        "full_log": "password=must-never-be-retained",
        "data": {"private_key": "must-never-be-retained"},
    }
    a = rig.ops.ingest_wazuh(source, event)
    assert not a["duplicate"]
    assert rig.ops.ingest_wazuh(source, event) == {
        "alert": a["alert"],
        "duplicate": True,
    }
    assert "must-never" not in json.dumps(rig.store.get("alert", a["alert"]))
    changed = {**event, "rule": {**event["rule"], "level": 9}}
    with pytest.raises(Conflict):
        rig.ops.ingest_wazuh(source, changed)
    replace_enrollment(rig, endpoint)
    with pytest.raises(Conflict):
        rig.ops.ingest_wazuh(source, event)


def test_http_auth_csrf_and_cross_scope(rig: Any) -> None:
    async def scenario() -> None:
        app = web.Application(client_max_size=2 * MAX_CHUNK)
        rig.ops.register(app)
        async with TestClient(TestServer(app)) as client:
            assert (await client.get("/remote/ops/api/state")).status == 403
            state = await (
                await client.get(
                    "/remote/ops/api/state", headers={"Authorization": "Bearer owner"}
                )
            ).json()
            args = {
                "kind": "case",
                "value": {"name": "Browser case", "endpoints": rig.endpoints},
                "revision": 0,
                "request_id": str(uuid4()),
            }
            headers = {
                "Authorization": "Bearer owner",
                "Origin": "https://operator.example",
                "X-CSRF-Token": state["csrf"],
            }
            denied = await client.post(
                "/remote/ops/api/save",
                headers={**headers, "Origin": "https://evil.example"},
                json=args,
            )
            assert denied.status == 403
            response = await client.post(
                "/remote/ops/api/save", headers=headers, json=args
            )
            assert response.status == 200
            record = (await response.json())["record"]
            assert (
                await client.get(
                    "/remote/ops/api/record/case/" + record["id"],
                    headers={"Authorization": "Bearer alice"},
                )
            ).status == 403

    asyncio.run(scenario())


def test_empty_workspace_exposes_only_explicit_scoped_capabilities(rig: Any) -> None:
    state = rig.ops.snapshot(rig.actors["alice"])
    assert state["cases"] == []
    assert state["capabilities"]["case.manage"]
    assert set(state["endpoint_capabilities"]) == {rig.endpoints[0]}
    rig.permissions.remove("ops.view")
    assert not rig.ops.snapshot(rig.actors["alice"])["capabilities"]["case.manage"]
    with pytest.raises(web.HTTPForbidden):
        save(rig, actor="alice")


def test_http_fragmented_json_is_read_completely(rig: Any) -> None:
    async def scenario() -> None:
        app = web.Application()
        rig.ops.register(app)
        async with TestClient(TestServer(app)) as client:
            owner = rig.actors["owner"]
            raw = json.dumps(
                {
                    "request_id": str(uuid4()),
                    "kind": "case",
                    "revision": 0,
                    "value": {
                        "name": "Slow fragmented browser request",
                        "endpoints": rig.endpoints[:1],
                    },
                }
            ).encode()

            async def fragments() -> Any:
                for offset in range(0, len(raw), 20):
                    yield raw[offset : offset + 20]
                    await asyncio.sleep(0.001)

            response = await client.post(
                "/remote/ops/api/save",
                data=fragments(),
                headers={
                    "Authorization": "Bearer owner",
                    "Origin": "https://operator.example",
                    "X-CSRF-Token": rig.ops.csrf(owner),
                    "Content-Type": "application/json",
                },
            )
            assert response.status == 200
            assert (await response.json())["record"]["value"][
                "name"
            ] == "Slow fragmented browser request"

    asyncio.run(scenario())


def test_identical_requests_racing_commit_one_record(rig: Any) -> None:
    from concurrent.futures import ThreadPoolExecutor

    request = str(uuid4())
    value = {
        "kind": "case",
        "revision": 0,
        "value": {"name": "Concurrent intake", "endpoints": rig.endpoints[:1]},
    }
    with ThreadPoolExecutor(max_workers=4) as pool:
        replies = list(
            pool.map(lambda _: call(rig, "save", value, request=request), range(4))
        )
    assert all(v == replies[0] for v in replies)
    assert len(rig.store.records("case")) == 1


def test_upload_full_digest_failure_does_not_publish_evidence(rig: Any) -> None:
    case = save(rig)
    data = b"measured diagnostics"
    item = call(
        rig,
        "upload_begin",
        {
            "case": case["id"],
            "name": "mismatch.txt",
            "size": len(data),
            "sha256": "0" * 64,
            "media_type": "text/plain",
            "redacted": True,
        },
    )["upload"]
    call(
        rig,
        "upload_chunk",
        {
            "upload": item["id"],
            "index": 0,
            "data": base64.b64encode(data).decode(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    )
    with pytest.raises(ValueError, match="digest"):
        call(rig, "upload_finish", {"upload": item["id"]})
    assert rig.store.artifact(item["id"])["state"] == "uploading"


def test_native_actor_keeps_explicit_scope_and_current_enrollment(rig: Any) -> None:
    endpoint = rig.endpoints[0]
    entry = {
        "id": "native-test",
        "actions": ["ops.view", "case.manage"],
        "endpoints": {endpoint: rig.identities[endpoint]},
    }
    active = True

    def current(e: Any) -> Any:
        if not active:
            raise ValueError("Revoked")
        return e

    def native_endpoint(e: Any, key: Any, permission: str) -> Any:
        if (
            permission not in e["actions"]
            or e["endpoints"].get(key) != rig.identities[key]
        ):
            raise web.HTTPForbidden()
        return uuid_value(key), RemoteTarget(
            endpoint_id=uuid_value(key),
            identity_id=uuid_value(rig.identities[key]),
            address="10.10.150.25",
        )

    rig.ops.m.integration = SimpleNamespace(
        auth=SimpleNamespace(current=current), endpoint=native_endpoint
    )

    async def scenario() -> None:
        args = {
            "kind": "case",
            "revision": 0,
            "value": {"name": "Native scoped case", "endpoints": [endpoint]},
            "request_id": str(uuid4()),
        }
        result = await rig.ops.native_call(entry, "save", args)
        assert result["record"]["subject"] == "integration:native-test"
        with pytest.raises(web.HTTPForbidden):
            await rig.ops.native_call(
                entry, "save", {**args, "request_id": str(uuid4()), "kind": "asset"}
            )
        replace_enrollment(rig, endpoint)
        assert (await rig.ops.native_call(entry, "state", {}))["cases"] == []
        with pytest.raises(web.HTTPForbidden):
            await rig.ops.native_call(entry, "save", args)

    asyncio.run(scenario())
    active = False


def test_wazuh_http_requires_its_own_identity_and_rejects_browser(
    rig: Any, tmp_path: Any
) -> None:
    token = "t" * 48
    path = tmp_path / "wazuh.json"
    source = {
        "id": "wazuh-http",
        "enabled": True,
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "agents": {
            "001": {
                "endpoint": rig.endpoints[0],
                "identity": rig.identities[rig.endpoints[0]],
            }
        },
    }
    path.write_text(json.dumps({"sources": [source]}))
    path.chmod(0o600)
    rig.ops.wazuh_registry = path
    event = {
        "id": "event1",
        "timestamp": "2026-09-09T12:00:00Z",
        "agent": {"id": "001"},
        "rule": {"id": "1001", "level": 8, "description": "Configuration changed"},
    }

    async def scenario() -> None:
        app = web.Application()
        rig.ops.register(app)
        async with TestClient(TestServer(app)) as client:
            path = "/remote/ops/intake/wazuh"
            assert (await client.post(path, json=event)).status == 401
            assert (
                await client.post(
                    path,
                    json=event,
                    headers={
                        "Authorization": "Bearer " + token,
                        "Origin": "https://operator.example",
                    },
                )
            ).status == 403
            response = await client.post(
                path, json=event, headers={"Authorization": "Bearer " + token}
            )
            assert response.status == 202
            assert not (await response.json())["duplicate"]
            source["enabled"] = False
            rig.ops.wazuh_registry.write_text(json.dumps({"sources": [source]}))
            assert (
                await client.post(
                    path, json=event, headers={"Authorization": "Bearer " + token}
                )
            ).status == 401

    asyncio.run(scenario())
