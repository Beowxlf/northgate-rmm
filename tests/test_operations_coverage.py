"""Detection intake, automatic case grouping and evidence HTTP regressions."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.operations import Operations, RetriableIntake
from tests.test_operations import call, save
from tests.test_operations import rig as rig
from tests.test_operations_scope import retain_evidence


def detection() -> dict[str, Any]:
    return {
        "id": "LAB-INTEGRITY",
        "version": "1.2.3",
        "severity": "high",
        "attack": ["T1565.001"],
        "checklist": ["Review retained context", "Verify affected endpoint"],
        "context_fields": ["path"],
    }


def policy() -> dict[str, Any]:
    return {
        "id": "lab-policy",
        "enabled": True,
        "rule_ids": ["550"],
        "minimum_level": 5,
        "window_seconds": 3600,
        "group_by": ["endpoint", "detection_id"],
        "owner": "SOC",
        "tags": ["synthetic"],
    }


def intake(rig: SimpleNamespace) -> tuple[dict[str, Any], dict[str, Any]]:
    endpoint = rig.endpoints[0]
    source = {
        "id": "fixture-source",
        "enabled": True,
        "agents": {"020": {"endpoint": endpoint, "identity": rig.identities[endpoint]}},
        "detections": {"550": detection()},
        "case_policies": [policy()],
    }
    payload = {
        "id": "event-1",
        "timestamp": "2026-09-10T11:34:14+00:00",
        "agent": {"id": "020"},
        "rule": {
            "id": "550",
            "level": 9,
            "description": "Synthetic integrity observation",
            "groups": ["syscheck"],
        },
        "context": {"path": "/synthetic/observed-file"},
    }
    return source, payload


@pytest.mark.parametrize(
    "change",
    [
        {"id": "lowercase"},
        {"version": "1.2"},
        {"attack": "T1000"},
        {"attack": ["T1000"] * 17},
        {"checklist": ["Review"] * 33},
        {"context_fields": ["path"] * 33},
        {"context_fields": "path"},
    ],
)
def test_detection_metadata_must_be_versioned_and_bounded(
    change: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        Operations.detection({"detections": {"550": {**detection(), **change}}}, "550")
    with pytest.raises(ValueError, match="approved detection"):
        Operations.detection({"detections": {}}, "550")
    assert Operations.detection({}, "550")["id"] == "WAZUH-550"


@pytest.mark.parametrize(
    "change",
    [
        {"window_seconds": 299},
        {"window_seconds": True},
        {"group_by": []},
        {"group_by": "endpoint"},
        {"group_by": ["raw_log"]},
        {"group_by": ["endpoint"] * 4},
        {"closed_behavior": "reopen"},
    ],
)
def test_case_policy_grouping_must_be_explicit_and_bounded(
    change: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="grouping policy"):
        Operations.case_policy({"case_policies": [{**policy(), **change}]}, "550", 9)
    assert Operations.case_policy({"case_policies": [policy()]}, "other", 9) is None
    assert Operations.case_policy({"case_policies": [policy()]}, "550", 2) is None
    with pytest.raises(ValueError, match="Multiple"):
        Operations.case_policy({"case_policies": [policy(), policy()]}, "550", 9)


@pytest.mark.parametrize("policies", ["not-a-list", [{}] * 101])
def test_case_policy_collection_is_bounded(policies: object) -> None:
    with pytest.raises(ValueError, match="collection"):
        Operations.case_policy({"case_policies": policies}, "550", 9)


def test_auto_case_groups_current_window_then_starts_new_case_after_closure(
    rig: SimpleNamespace,
) -> None:
    operations = cast(Operations, rig.ops)
    source, payload = intake(rig)
    operations.intake_failure(
        source["id"], payload["id"], "unmapped_device", "Synthetic mapping pending"
    )
    operations.intake_failure(
        source["id"],
        payload["id"],
        "unmapped_device",
        "Synthetic mapping still pending",
    )
    result = operations.ingest_wazuh(source, payload)
    case = rig.store.get("case", result["case"])
    assert case["value"]["automation"]["alert_count"] == 1
    assert [task["title"] for task in case["value"]["tasks"]] == detection()[
        "checklist"
    ]
    assert case["value"]["priority"] == "high"
    assert "Operations test 0" in case["value"]["name"]
    assert "T1565.001" in case["value"]["description"]
    failures = [
        item
        for item in rig.store.records("alert")
        if item["value"].get("intake_status")
    ]
    assert len(failures) == 1 and failures[0]["value"]["intake_status"] == "resolved"
    assert failures[0]["value"]["resolved_alert"] == result["alert"]
    duplicate = operations.ingest_wazuh(source, payload)
    assert duplicate == {**result, "duplicate": True}
    second = operations.ingest_wazuh(source, {**payload, "id": "event-2"})
    assert second["case"] == result["case"]
    case = rig.store.get("case", result["case"])
    assert case["value"]["automation"]["alert_count"] == 2
    assert sorted(case["value"]["alerts"]) == sorted([result["alert"], second["alert"]])
    with rig.store.connection(write=True) as db:
        rig.store.put(
            db,
            "case",
            case["id"],
            {**case["value"], "status": "closed"},
            "fixture",
            case["revision"],
            "fixture.closed",
        )
    third = operations.ingest_wazuh(source, {**payload, "id": "event-3"})
    assert third["case"] != result["case"]
    assert operations.device_name(str(uuid4())) not in case["value"]["name"]
    assert operations.device_name("invalid") == "invalid"


@pytest.mark.parametrize(
    "defect",
    [
        "mapping",
        "detection",
        "severity",
        "policy",
        "context",
        "level",
        "groups",
        "source",
    ],
)
def test_intake_fails_closed_before_retaining_unapproved_data(
    rig: SimpleNamespace, defect: str
) -> None:
    source, payload = intake(rig)
    if defect == "mapping":
        source["agents"] = {}
    if defect == "detection":
        source["detections"] = {}
    if defect == "severity":
        source["detections"]["550"]["severity"] = "unknown"
    if defect == "policy":
        source["case_policies"][0]["group_by"] = []
    if defect == "context":
        payload["context"]["unapproved"] = "must-not-retain"
    if defect == "level":
        payload["rule"]["level"] = True
    if defect == "groups":
        payload["rule"]["groups"] = "not-a-list"
    if defect == "source":
        source["id"] = "invalid/source"
    expected = (
        RetriableIntake
        if defect in {"mapping", "detection", "severity", "policy"}
        else ValueError
    )
    with pytest.raises(expected):
        rig.ops.ingest_wazuh(source, payload)
    assert rig.store.records("case") == [] and rig.store.records("alert") == []


def test_case_creation_failure_rolls_back_alert_and_source_receipt(
    rig: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, payload = intake(rig)

    def fail(*args: object, **kwargs: object) -> str:
        raise ValueError("Synthetic case persistence failure")

    monkeypatch.setattr(rig.ops, "auto_case", fail)
    with pytest.raises(RetriableIntake, match="case creation failed"):
        rig.ops.ingest_wazuh(source, payload)
    assert rig.store.records("alert") == [] and rig.store.records("case") == []
    with rig.store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM ops_alert_sources").fetchone()[0] == 0


def test_wazuh_http_records_retriable_health_and_recovers_without_duplicates(
    rig: SimpleNamespace, tmp_path: Path
) -> None:
    async def scenario() -> None:
        source, payload = intake(rig)
        token = "A" * 48
        source["token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
        registry = tmp_path / "intake.json"

        def write(value: dict[str, Any]) -> None:
            registry.write_text(json.dumps({"sources": [value]}))
            registry.chmod(0o600)

        write({**source, "agents": {}})
        rig.ops.wazuh_registry = registry
        app = web.Application()
        rig.ops.register(app)
        async with TestClient(TestServer(app)) as client:
            path = "/remote/ops/intake/wazuh"
            headers = {"Authorization": "Bearer " + token}
            assert (
                await client.post(
                    path,
                    headers={**headers, "Origin": "https://other.test"},
                    json=payload,
                )
            ).status == 403
            assert (
                await client.post(
                    path, headers={"Authorization": "Bearer invalid"}, json=payload
                )
            ).status == 401
            assert (
                await client.post(
                    path, headers={"Authorization": "Bearer " + "B" * 48}, json=payload
                )
            ).status == 401
            unavailable = await client.post(path, headers=headers, json=payload)
            assert (
                unavailable.status == 503 and unavailable.headers["Retry-After"] == "30"
            )
            assert "device mapping required" in await unavailable.text()
            write(source)
            response = await client.post(path, headers=headers, json=payload)
            assert response.status == 202
            accepted = await response.json()
            response = await client.post(path, headers=headers, json=payload)
            assert await response.json() == {**accepted, "duplicate": True}
            changed = copy.deepcopy(payload)
            changed["rule"]["description"] = (
                "Different alert with same source identifier"
            )
            assert (
                await client.post(path, headers=headers, json=changed)
            ).status == 409
            changed["rule"]["level"] = 99
            assert (
                await client.post(path, headers=headers, json=changed)
            ).status == 400
            registry.write_text("invalid JSON")
            assert (
                await client.post(path, headers=headers, json=payload)
            ).status == 401
            registry.unlink()
            assert (
                await client.post(path, headers=headers, json=payload)
            ).status == 401

    asyncio.run(scenario())


def test_upload_status_and_downloads_authorize_current_case_scope(
    rig: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        case = save(rig)
        evidence = retain_evidence(rig, case)
        app = web.Application()
        rig.ops.register(app)
        async with TestClient(TestServer(app)) as client:
            status_path = "/remote/ops/api/upload/" + evidence["id"]
            chunks = "/remote/ops/api/evidence/" + evidence["id"] + "/chunks/"
            headers = {"Authorization": "Bearer owner"}
            response = await client.get(status_path, headers=headers)
            assert (
                response.status == 200
                and (await response.json())["upload"]["state"] == "complete"
            )
            assert (
                await client.get(status_path, headers={"Authorization": "Bearer bob"})
            ).status == 403
            assert (
                await client.get("/remote/ops/api/upload/invalid", headers=headers)
            ).status == 400
            assert (
                await client.get(
                    "/remote/ops/api/upload/" + str(uuid4()), headers=headers
                )
            ).status == 404
            assert (await client.get(chunks + "999", headers=headers)).status == 404
            assert (await client.get(chunks + "invalid", headers=headers)).status == 404
            response = await client.get(chunks + "0", headers=headers)
            assert response.status == 200
            assert (await response.json())["sha256"] == evidence["chunks"][0]["sha256"]
            monkeypatch.setattr(rig.store, "read_chunk", lambda *_: b"modified bytes")
            assert (await client.get(chunks + "0", headers=headers)).status == 404
            assert (
                await client.get(
                    "/remote/ops/api/record/unsupported/" + case["id"], headers=headers
                )
            ).status == 404
            assert (
                await client.get(
                    "/remote/ops/api/record/case/" + str(uuid4()), headers=headers
                )
            ).status == 404
            assert (
                await client.get("/remote/ops/api/record/case/invalid", headers=headers)
            ).status == 400

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "condition",
    [
        "redaction",
        "filename",
        "media",
        "provenance_keys",
        "provenance_type",
        "provenance_scope",
        "closed",
        "valid",
    ],
)
def test_evidence_upload_validates_redaction_metadata_and_case_binding(
    rig: SimpleNamespace, condition: str
) -> None:
    case = save(rig)
    if condition == "closed":
        with rig.store.connection(write=True) as db:
            case = rig.store.put(
                db,
                "case",
                case["id"],
                {**case["value"], "status": "closed"},
                "fixture",
                case["revision"],
                "fixture.closed",
            )
    body: dict[str, Any] = {
        "case": case["id"],
        "name": "reviewed.txt",
        "size": 1,
        "sha256": hashlib.sha256(b"x").hexdigest(),
        "redacted": True,
        "media_type": "text/plain",
        "provenance": {
            "endpoint_id": rig.endpoints[0],
            "identity_id": rig.identities[rig.endpoints[0]],
            "collector_version": "fixture-1",
        },
    }
    if condition == "redaction":
        body["redacted"] = False
    if condition == "filename":
        body["name"] = "../outside.txt"
    if condition == "media":
        body["media_type"] = "application/x-executable"
    if condition == "provenance_keys":
        body["provenance"]["arbitrary"] = "unapproved"
    if condition == "provenance_type":
        body["provenance"] = ["invalid"]
    if condition == "provenance_scope":
        body["provenance"]["endpoint_id"] = rig.endpoints[1]
    if condition == "valid":
        upload = call(rig, "upload_begin", body)["upload"]
        assert upload["provenance"]["collector_version"] == "fixture-1"
        assert (
            upload["provenance"]["source_claim"]
            == "collector-supplied; verify against signed receipt"
        )
        with pytest.raises(web.HTTPForbidden):
            call(rig, "upload_cancel", {"upload": upload["id"]}, actor="alice")
    else:
        with pytest.raises(
            web.HTTPForbidden if condition == "provenance_scope" else ValueError
        ):
            call(rig, "upload_begin", body)
        assert rig.store.artifacts(case["id"]) == []


def test_linking_alert_expands_case_scope_and_records_retained_detail(
    rig: SimpleNamespace,
) -> None:
    source, payload = intake(rig)
    source.pop("case_policies")
    alert = rig.ops.ingest_wazuh(source, payload)
    case = save(rig, endpoints=rig.endpoints[1:])
    linked = call(
        rig,
        "link_alert",
        {"id": case["id"], "revision": case["revision"], "alert": alert["alert"]},
    )["record"]
    assert linked["value"]["alerts"] == [alert["alert"]]
    assert set(linked["value"]["endpoints"]) == set(rig.endpoints)
    with pytest.raises(web.HTTPForbidden):
        rig.ops.record_detail(rig.actors["alice"], "case", case["id"])
    owner = rig.ops.record_detail(rig.actors["owner"], "case", case["id"])
    assert owner["record"]["revision"] == linked["revision"]
    assert owner["timeline"] and owner["versions"]


def test_relationship_expansion_is_bounded_and_keeps_all_linked_endpoints(
    rig: SimpleNamespace,
) -> None:
    first = save(rig, "asset", "First", endpoints=rig.endpoints[:1])
    second = save(rig, "asset", "Second", endpoints=rig.endpoints[1:])
    relation = save(
        rig,
        "relationship",
        "Dependency",
        endpoints=[],
        source={"kind": "asset", "id": first["id"]},
        target={"kind": "asset", "id": second["id"]},
        relation="depends_on",
        confidence="verified",
    )
    assert set(relation["value"]["endpoints"]) == set(rig.endpoints)
    detail = rig.ops.record_detail(rig.actors["owner"], "asset", first["id"])
    assert detail["enrollments"] == []
    with pytest.raises(ValueError, match="bounded lookup limit"):
        rig.ops.expand_scope(
            rig.actors["owner"],
            "case",
            {"assets": [first["id"]], "endpoints": []},
            visited={("asset", str(uuid4())) for _ in range(128)},
        )
    with pytest.raises(ValueError, match="owner assignee"):
        rig.ops.assignee(rig.actors["owner"], {"endpoints": []}, "alice")


@pytest.mark.parametrize(
    "field", ["disposition", "containment_status", "resolution_code"]
)
def test_case_resolution_rejects_unrecognized_security_decisions(
    rig: SimpleNamespace, field: str
) -> None:
    case = save(rig)
    case = call(
        rig,
        "case_transition",
        {"id": case["id"], "revision": case["revision"], "status": "in_progress"},
    )["record"]
    with pytest.raises(ValueError, match="Invalid"):
        call(
            rig,
            "case_transition",
            {
                "id": case["id"],
                "revision": case["revision"],
                "status": "resolved",
                "outcome": "Synthetic resolution",
                "verification": "Synthetic evidence",
                field: "unrecognized",
            },
        )
    assert rig.store.get("case", case["id"])["value"]["status"] == "in_progress"
