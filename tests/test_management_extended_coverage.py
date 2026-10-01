"""Release integrity and operator/enrollment-bound evidence regression tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.capture_store import CaptureStore
from northgate_rmm.operator_api import OperatorPrincipal
from tests.test_fleet_review import fixture


def test_release_catalog_filters_platform_and_download_rechecks_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        fleet, _, rows = fixture(tmp_path / "management")
        management = fleet.m
        extended = management.extended
        extended.catalog.mkdir()
        for platform in ("linux", "windows"):
            path = extended.catalog / (platform + ".json")
            path.write_text(json.dumps({"manifest": {"platform": platform}}))
            path.chmod(0o600)
        verified: list[str] = []

        async def worker(
            request: web.Request,
        ) -> tuple[SimpleNamespace, SimpleNamespace]:
            verified.append(request.path)
            return SimpleNamespace(), SimpleNamespace()

        monkeypatch.setattr(management, "worker_identity", worker)
        app = web.Application()
        extended.register(app)
        app.router.add_get("/downloads/{digest}", extended.download_release)
        async with TestClient(TestServer(app)) as client:
            catalog = await client.get(
                f"/remote/{rows[0]['id']}/manage/catalog",
                headers={"Authorization": "Bearer synthetic"},
            )
            assert catalog.status == 200
            assert await catalog.json() == {
                "releases": [{"manifest": {"platform": "linux"}}]
            }
            payload = b"reviewed synthetic release bytes"
            digest = hashlib.sha256(payload).hexdigest()
            release = extended.catalog / digest
            release.write_bytes(payload)
            release.chmod(0o600)
            response = await client.get("/downloads/" + digest)
            assert response.status == 200 and await response.read() == payload
            assert response.headers["Cache-Control"] == "no-store"
            release.write_bytes(b"tampered")
            assert (await client.get("/downloads/" + digest)).status == 404
            assert (await client.get("/downloads/" + "f" * 64)).status == 404
            assert (await client.get("/downloads/not-a-digest")).status == 404
            assert len(verified) == 4

    asyncio.run(scenario())


def test_infrastructure_baseline_tracks_changes_without_claiming_identity(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        fleet, actor, rows = fixture(tmp_path / "management")
        principal = cast(OperatorPrincipal, actor)
        management = fleet.m
        endpoint, identity = UUID(rows[0]["id"]), UUID(rows[0]["identity"])
        capture = CaptureStore(tmp_path / "captures")
        nonce = "synthetic-form-token"
        management.forms[nonce] = (
            principal.subject,
            principal.session_id,
            str(endpoint),
            time.time() + 300,
        )
        headers = {
            "Authorization": "Bearer synthetic",
            "Origin": management.gateway.origin,
        }
        app = web.Application()
        management.extended.register(app)
        base = f"/remote/{endpoint}/manage/infrastructure"
        async with TestClient(TestServer(app)) as client:
            empty = await client.get(base, headers=headers)
            assert (await empty.json())["baseline_saved"] is None
            assert (
                await client.post(base, json={"csrf": nonce}, headers=headers)
            ).status == 400
            job: dict[str, Any] = {
                "id": str(uuid4()),
                "report": {
                    "assets": [
                        {
                            "ip": "10.20.30.40",
                            "macs": ["aa:bb:cc:dd:ee:ff"],
                            "roles": ["server"],
                        },
                        {"address": "10.20.30.41", "roles": ["client"]},
                        {"ip": "invalid"},
                        {},
                    ]
                },
                "artifacts": [],
            }
            capture.add(endpoint, identity, principal, job)
            capture.add(
                endpoint,
                identity,
                replace(principal, subject="other"),
                {"id": str(uuid4()), "report": {"assets": [{"ip": "10.20.30.99"}]}},
            )
            assert (
                await client.post(
                    base,
                    json={"csrf": nonce},
                    headers={**headers, "Origin": "https://other.test"},
                )
            ).status == 403
            assert (
                await client.post(base, json={"csrf": nonce}, headers=headers)
            ).status == 200
            initial = await (await client.get(base, headers=headers)).json()
            assert initial["baseline_saved"] is not None
            assert (
                initial["added"] == initial["changed"] == initial["not_observed"] == []
            )
            assert len(initial["assets"][0]["candidate_endpoints"]) == 2
            assert initial["assets"][0]["confidence"] == "address-only candidate"
            assert initial["assets"][1]["confidence"] == "unmapped"
            job["report"] = {
                "assets": [
                    {"ip": "10.20.30.40", "roles": ["router"]},
                    {"ip": "10.20.30.42"},
                ]
            }
            capture.update(job)
            changed = await (await client.get(base, headers=headers)).json()
            assert changed["added"] == ["10.20.30.42"]
            assert changed["changed"] == ["10.20.30.40"]
            assert changed["not_observed"] == ["10.20.30.41"]
            assert "Not observed does not mean offline" in changed["coverage"]
            target, parameters = management.gateway.targets[endpoint]
            management.gateway.targets[endpoint] = (
                replace(target, identity_id=uuid4()),
                parameters,
            )
            refreshed = await (await client.get(base, headers=headers)).json()
            assert refreshed["baseline_saved"] is None and refreshed["assets"] == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "defect",
    [
        "valid",
        "missing",
        "unknown",
        "wrong_operator",
        "wrong_identity",
        "empty_exercise",
        "long_exercise",
        "control_character",
    ],
)
def test_capture_evidence_requires_visible_capture_and_bounded_exercise(
    tmp_path: Path,
    defect: str,
) -> None:
    async def scenario() -> None:
        fleet, actor, rows = fixture(tmp_path / "management")
        principal = cast(OperatorPrincipal, actor)
        management = fleet.m
        endpoint, identity = UUID(rows[0]["id"]), UUID(rows[0]["identity"])
        capture = CaptureStore(tmp_path / "captures")
        identifier = str(uuid4())
        capture.add(
            endpoint,
            uuid4() if defect == "wrong_identity" else identity,
            replace(principal, subject="other")
            if defect == "wrong_operator"
            else principal,
            {
                "id": identifier,
                "artifacts": [{"name": "capture.pcap"}],
                "report": {"findings": ["reviewed finding"]},
            },
        )
        nonce = "synthetic-form-token"
        management.forms[nonce] = (
            principal.subject,
            principal.session_id,
            str(endpoint),
            time.time() + 300,
        )
        body: dict[str, object] = {
            "csrf": nonce,
            "capture": identifier,
            "exercise": "exercise-1",
        }
        if defect == "missing":
            body.pop("capture")
        if defect == "unknown":
            body["capture"] = str(uuid4())
        for condition, value in [
            ("empty_exercise", ""),
            ("long_exercise", "x" * 65),
            ("control_character", "line\nbreak"),
        ]:
            if defect == condition:
                body["exercise"] = value
        app = web.Application()
        management.extended.register(app)
        async with TestClient(TestServer(app)) as client:
            response = await client.post(
                f"/remote/{endpoint}/manage/capture-evidence",
                json=body,
                headers={
                    "Authorization": "Bearer synthetic",
                    "Origin": management.gateway.origin,
                },
            )
            assert response.status == (200 if defect == "valid" else 400)
            with management.store.connect() as db:
                records = db.execute(
                    "SELECT action FROM evidence WHERE exercise='exercise-1'"
                ).fetchall()
            assert [row["action"] for row in records] == (
                ["capture.linked"] if defect == "valid" else []
            )

    asyncio.run(scenario())
