"""Retained case content keeps the scope acquired through infrastructure links."""

import asyncio
import base64
import hashlib
import json
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from tests.test_operations import call, save
from tests.test_operations import rig as rig


def grown_case(rig: Any) -> tuple[Any, Any, Any]:
    asset = save(rig, "asset", "Workstation")
    service = save(rig, "service", "Application", assets=[asset["id"]])
    case = save(rig, services=[service["id"]])
    call(
        rig,
        "save",
        {
            "kind": "asset",
            "id": asset["id"],
            "revision": asset["revision"],
            "value": {"name": "Shared infrastructure", "endpoints": rig.endpoints},
        },
    )
    # The new scope was acquired via a dependency, not stored on the case yet.
    assert rig.store.get("case", case["id"])["value"]["endpoints"] == rig.endpoints[:1]
    return asset, service, case


def retain_evidence(rig: Any, case: Any) -> Any:
    data = b"Synthetic observations concerning the second device"
    digest = hashlib.sha256(data).hexdigest()
    item = call(
        rig,
        "upload_begin",
        {
            "case": case["id"],
            "name": "observations.txt",
            "size": len(data),
            "sha256": digest,
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
            "sha256": digest,
        },
    )
    return call(rig, "upload_finish", {"upload": item["id"]})["upload"]


@pytest.mark.parametrize("remove_from", ["case", "service"])
def test_dependency_removal_preserves_retained_notes_and_evidence_scope(
    rig: Any, remove_from: str
) -> None:
    _, service, case = grown_case(rig)
    call(
        rig,
        "note",
        {
            "kind": "case",
            "id": case["id"],
            "text": "Second-device confidential observation",
        },
    )
    evidence = retain_evidence(rig, case)
    original = case if remove_from == "case" else service
    updated = call(
        rig,
        "save",
        {
            "kind": remove_from,
            "id": original["id"],
            "revision": original["revision"],
            "value": {
                "name": "Link removed",
                "endpoints": rig.endpoints[:1],
                "services": [],
            }
            if remove_from == "case"
            else {"name": "Link removed", "endpoints": rig.endpoints[:1], "assets": []},
        },
    )["record"]
    assert updated["value"]["endpoints"] == sorted(rig.endpoints)
    detail = rig.ops.record_detail(rig.actors["owner"], "case", case["id"])
    assert "Second-device confidential observation" in json.dumps(detail["timeline"])
    assert detail["evidence"][0]["id"] == evidence["id"]
    with pytest.raises(web.HTTPForbidden):
        rig.ops.record_detail(rig.actors["alice"], "case", case["id"])
    assert rig.ops.snapshot(rig.actors["alice"])["cases"] == []

    async def download() -> None:
        app = web.Application()
        rig.ops.register(app)
        async with TestClient(TestServer(app)) as client:
            path = "/remote/ops/api/evidence/" + evidence["id"] + "/chunks/0"
            assert (
                await client.get(path, headers={"Authorization": "Bearer alice"})
            ).status == 403
            owner = await client.get(path, headers={"Authorization": "Bearer owner"})
            assert owner.status == 200
            assert (
                base64.b64decode((await owner.json())["data"])
                == b"Synthetic observations concerning the second device"
            )

    asyncio.run(download())


def test_evidence_permission_is_required_on_expanded_scope(rig: Any) -> None:
    _, _, case = grown_case(rig)
    evidence = retain_evidence(rig, case)
    rig.grants["alice"] = set(rig.endpoints)
    policy = rig.ops.gateway.operation._policy
    original = policy.permits
    policy.permits = lambda subject, endpoint, permission: (
        original(subject, endpoint, permission)
        and not (
            subject == "alice"
            and str(endpoint) == rig.endpoints[1]
            and permission == "evidence.manage"
        )
    )
    effective = rig.ops.authorized_record(rig.actors["alice"], "case", case["id"])
    assert effective["value"]["endpoints"] == sorted(rig.endpoints)
    assert rig.ops.snapshot(rig.actors["alice"])["cases"][0]["value"][
        "endpoints"
    ] == sorted(rig.endpoints)
    with pytest.raises(web.HTTPForbidden):
        call(
            rig,
            "upload_begin",
            {
                "case": case["id"],
                "name": "denied.txt",
                "size": 1,
                "sha256": hashlib.sha256(b"x").hexdigest(),
                "redacted": True,
            },
            "alice",
        )

    async def download() -> None:
        app = web.Application()
        rig.ops.register(app)
        async with TestClient(TestServer(app)) as client:
            response = await client.get(
                "/remote/ops/api/evidence/" + evidence["id"] + "/chunks/0",
                headers={"Authorization": "Bearer alice"},
            )
            assert response.status == 403

    asyncio.run(download())


def test_assignee_is_rechecked_after_historical_scope_is_merged(rig: Any) -> None:
    _, _, case = grown_case(rig)
    with pytest.raises(ValueError, match="Assignee"):
        call(
            rig,
            "save",
            {
                "kind": "case",
                "id": case["id"],
                "revision": case["revision"],
                "value": {
                    "name": "Remove dependency",
                    "endpoints": rig.endpoints[:1],
                    "services": [],
                    "assignee": "alice",
                },
            },
        )
