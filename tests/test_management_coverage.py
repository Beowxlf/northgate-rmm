"""Typed job, terminal, reviewed-script and download boundary regression tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.management import Management
from northgate_rmm.management_protocol import canonical, seal
from northgate_rmm.operator_api import OperatorPrincipal
from tests.test_fleet_review import fixture
from tests.test_management import receipt


@dataclass
class ManagementFixture:
    management: Management
    principal: OperatorPrincipal
    endpoint: UUID
    identity: UUID
    nonce: str = "synthetic-management-form"

    @property
    def base(self) -> str:
        return f"/remote/{self.endpoint}/manage"

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer synthetic",
            "Origin": self.management.gateway.origin,
        }

    def app(self) -> web.Application:
        app = web.Application()
        self.management.register(app)
        return app

    def add(
        self,
        action: str,
        params: dict[str, Any],
        *,
        owner: OperatorPrincipal | None = None,
        output: str | None = None,
    ) -> str:
        store = self.management.store
        identifier = store.add(
            self.endpoint,
            self.identity,
            owner or self.principal,
            action,
            params,
            "Bearer synthetic",
            "exercise-fixture",
        )
        if output is not None:
            store.dispatch(identifier)
            store.result(self.endpoint, self.identity, identifier, receipt(output))
        return identifier


@pytest.fixture
def rig(tmp_path: Path) -> ManagementFixture:
    fleet, actor, rows = fixture(tmp_path / "management")
    principal = cast(OperatorPrincipal, actor)
    result = ManagementFixture(
        fleet.m, principal, UUID(rows[0]["id"]), UUID(rows[0]["identity"])
    )
    result.management.forms[result.nonce] = (
        principal.subject,
        principal.session_id,
        str(result.endpoint),
        time.time() + 300,
    )
    return result


@pytest.mark.parametrize(
    "defect",
    [
        "valid",
        "finished",
        "wrong_owner",
        "wrong_action",
        "negative_after",
        "boolean_after",
        "input_list",
        "extra_input",
        "oversized_input",
        "short_columns",
        "boolean_rows",
        "missing_sequence",
    ],
)
def test_terminal_input_is_session_bound_and_bounded(
    rig: ManagementFixture, defect: str
) -> None:
    async def scenario() -> None:
        action = "posture" if defect == "wrong_action" else "shell.start"
        owner = (
            replace(rig.principal, subject="other")
            if defect == "wrong_owner"
            else rig.principal
        )
        job = rig.add(
            action,
            {"columns": 80, "rows": 24} if action == "shell.start" else {},
            owner=owner,
            output="completed" if defect == "finished" else None,
        )
        encoded = base64.b64encode(b"synthetic terminal output").decode()
        rig.management.store.io(job, "out", 1, {"data": encoded})
        body: dict[str, Any] = {
            "csrf": rig.nonce,
            "job": job,
            "sequence": 1,
            "after": 0,
            "input": {
                "data": base64.b64encode(b"help\n").decode(),
                "columns": 80,
                "rows": 24,
            },
        }
        if defect == "negative_after":
            body["after"] = -1
        if defect == "boolean_after":
            body["after"] = True
        if defect == "input_list":
            body["input"] = []
        if defect == "extra_input":
            body["input"]["command"] = "forbidden"
        if defect == "oversized_input":
            body["input"]["data"] = base64.b64encode(b"x" * 16385).decode()
        if defect == "short_columns":
            body["input"]["columns"] = 19
        if defect == "boolean_rows":
            body["input"]["rows"] = True
        if defect == "missing_sequence":
            body.pop("sequence")
        async with TestClient(TestServer(rig.app())) as client:
            response = await client.post(
                rig.base + "/io", json=body, headers=rig.headers
            )
            expected = (
                200
                if defect in {"valid", "finished"}
                else 403
                if defect in {"wrong_owner", "wrong_action"}
                else 400
            )
            assert response.status == expected
            inputs = rig.management.store.frames(job, "in", 0)
            assert len(inputs) == int(defect == "valid")
            if expected == 200:
                result = await response.json()
                assert result["frames"][0]["value"]["data"] == encoded
                assert (job in rig.management.shell_leases) == (defect == "valid")
                response = await client.post(
                    rig.base + "/io",
                    json={"csrf": rig.nonce, "job": job, "after": 1},
                    headers=rig.headers,
                )
                assert (await response.json())["frames"] == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "defect",
    ["valid", "size", "digest", "wrong_owner", "wrong_action", "unfinished", "unknown"],
)
def test_file_download_verifies_retained_result_and_scope(
    rig: ManagementFixture, defect: str
) -> None:
    async def scenario() -> None:
        data = b"synthetic reviewed download"
        payload = {
            "data": base64.b64encode(data).decode(),
            "size": len(data) + int(defect == "size"),
            "sha256": "0" * 64
            if defect == "digest"
            else hashlib.sha256(data).hexdigest(),
        }
        owner = (
            replace(rig.principal, subject="other")
            if defect == "wrong_owner"
            else rig.principal
        )
        job = rig.add(
            "posture" if defect == "wrong_action" else "files.read",
            {"path": "/synthetic"},
            owner=owner,
            output=None if defect == "unfinished" else json.dumps(payload),
        )
        if defect == "unknown":
            job = str(uuid4())
        async with TestClient(TestServer(rig.app())) as client:
            response = await client.post(
                rig.base + "/download",
                json={"csrf": rig.nonce, "job": job},
                headers=rig.headers,
            )
            assert response.status == (
                200
                if defect == "valid"
                else 502
                if defect in {"size", "digest"}
                else 404
            )
            if defect == "valid":
                assert await response.read() == data
                assert response.headers["X-Content-SHA256"] == payload["sha256"]
                assert response.headers["Content-Disposition"].startswith("attachment;")

    asyncio.run(scenario())


def test_script_publication_and_execution_preserve_reviewed_contract(
    rig: ManagementFixture,
) -> None:
    async def scenario() -> None:
        async with TestClient(TestServer(rig.app())) as client:
            script = await client.post(
                rig.base + "/scripts",
                json={
                    "csrf": rig.nonce,
                    "content": "printf '%s' \"$NAME\"",
                    "inputs": ["NAME"],
                },
                headers=rig.headers,
            )
            assert script.status == 200
            contract = await script.json()
            parameters = {**contract, "inputs": {"NAME": "fixture"}}
            response = await client.post(
                rig.base + "/action",
                json={"csrf": rig.nonce, "action": "script.run", "params": parameters},
                headers=rig.headers,
            )
            assert response.status == 202
            identifier = (await response.json())["job"]
            saved = rig.management.store.job(identifier, private=True)
            assert saved["payload"]["params"]["content"] == "printf '%s' \"$NAME\""
            assert saved["payload"]["params"]["inputs"] == {"NAME": "fixture"}
            parameters["inputs"] = {}
            response = await client.post(
                rig.base + "/action",
                json={"csrf": rig.nonce, "action": "script.run", "params": parameters},
                headers=rig.headers,
            )
            assert response.status == 400
            response = await client.get(rig.base + "/config", headers=rig.headers)
            config = await response.json()
            assert config["endpoint_id"] == str(rig.endpoint) and config[
                "identity_id"
            ] == str(rig.identity)
            assert "private_key" not in config
            events = await (
                await client.get(rig.base + "/evidence", headers=rig.headers)
            ).json()
            assert events["endpoint"] == str(rig.endpoint)
            assert events["events"][0]["detail"]["job"] == identifier

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "definition",
    [
        {"content": 1},
        {"content": "x" * 32769},
        {"content": "echo", "inputs": "NAME"},
        {"content": "echo", "inputs": ["lower"]},
        {"content": "echo", "inputs": ["NAME", "NAME"]},
        {"content": "echo", "inputs": [f"VAR{i}" for i in range(17)]},
    ],
)
def test_invalid_reviewed_script_contract_never_persists(
    rig: ManagementFixture, definition: dict[str, object]
) -> None:
    async def scenario() -> None:
        async with TestClient(TestServer(rig.app())) as client:
            response = await client.post(
                rig.base + "/scripts",
                json={"csrf": rig.nonce, **definition},
                headers=rig.headers,
            )
            assert response.status == 400
            with rig.management.store.connect() as db:
                assert db.execute("SELECT COUNT(*) FROM scripts").fetchone()[0] == 0

    asyncio.run(scenario())


@pytest.mark.parametrize("defect", ["absent", "tampered", "platform", "inputs"])
def test_script_dispatch_rechecks_stored_contract(
    rig: ManagementFixture, defect: str
) -> None:
    async def scenario() -> None:
        identifier = str(uuid4())
        payload = {
            "content": "echo synthetic",
            "platform": "windows" if defect == "platform" else "linux",
            "inputs": ["VALUE"],
            "author": rig.principal.subject,
        }
        version = hashlib.sha256(canonical(payload)).hexdigest()
        if defect == "tampered":
            payload["content"] = "changed after review"
        if defect != "absent":
            with rig.management.store.connect() as db:
                db.execute(
                    "INSERT INTO scripts VALUES (?,?,?,?)",
                    (
                        identifier,
                        version,
                        time.time(),
                        seal(
                            rig.management.gateway.key,
                            payload,
                            identifier + "/" + version,
                        ),
                    ),
                )
        async with TestClient(TestServer(rig.app())) as client:
            response = await client.post(
                rig.base + "/action",
                json={
                    "csrf": rig.nonce,
                    "action": "script.run",
                    "params": {
                        "script_id": identifier,
                        "version": version,
                        "inputs": {} if defect == "inputs" else {"VALUE": "synthetic"},
                    },
                },
                headers=rig.headers,
            )
            assert response.status == 400
            assert rig.management.store.list(rig.endpoint) == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "action", [None, "credential.rotate", "capture.install", "tool.verify"]
)
def test_separate_authority_actions_cannot_use_general_dispatch(
    rig: ManagementFixture, action: object
) -> None:
    async def scenario() -> None:
        async with TestClient(TestServer(rig.app())) as client:
            response = await client.post(
                rig.base + "/action",
                json={"csrf": rig.nonce, "action": action},
                headers=rig.headers,
            )
            assert (
                response.status == 400 and rig.management.store.list(rig.endpoint) == []
            )

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "condition",
    [
        "valid",
        "manage_revoked",
        "identity_changed",
        "recovery_role",
        "credential_absent",
        "credential_present",
        "case_absent",
        "case_present",
        "native_secret",
        "native_disabled",
        "native_present",
    ],
)
def test_dispatch_reauthenticates_exact_human_or_integration_authority(
    rig: ManagementFixture, monkeypatch: pytest.MonkeyPatch, condition: str
) -> None:
    from types import SimpleNamespace

    from northgate_rmm.integration_auth import PREFIX
    from northgate_rmm.native_api import NativeAPI

    async def scenario() -> None:
        action = "posture"
        if condition.startswith("credential"):
            action = "credential.rotate"
        if condition in {"recovery_role", "native_secret"}:
            action = "recovery.rotate"
        if condition.startswith("case_"):
            action = "tool.run"
        job_id = rig.add(
            action, {"case_id": "CASE-1"} if condition.startswith("case_") else {}
        )
        job = rig.management.store.job(job_id, private=True)
        calls: list[str] = []
        if condition == "manage_revoked":
            original = rig.management.gateway.operation._policy
            monkeypatch.setattr(
                rig.management.gateway.operation,
                "_policy",
                replace(original, subject="other"),
            )
        if condition == "identity_changed":
            job["identity"] = str(uuid4())
        if condition.startswith("credential"):
            authorized = replace(
                rig.principal, roles=(*rig.principal.roles, "recovery_operator")
            )
            monkeypatch.setattr(
                rig.management.gateway.operation,
                "_authenticate",
                lambda *args, **kwargs: authorized,
            )

        async def allow(*args: object) -> None:
            calls.append(condition)

        if condition == "credential_present":
            monkeypatch.setattr(
                rig.management.gateway,
                "credential_rotation_authorizer",
                allow,
                raising=False,
            )
        if condition == "case_present":
            rig.management.gateway.case_authorizer = allow
        if condition.startswith("native"):
            job["payload"]["authorization"] = PREFIX + "synthetic-approval"
        if condition == "native_present":

            def integration_authorize(value: dict[str, Any]) -> None:
                assert value["id"] == job_id
                calls.append(condition)

            rig.management.integration = cast(
                NativeAPI, SimpleNamespace(authorize_job=integration_authorize)
            )
        successful = condition in {
            "valid",
            "credential_present",
            "case_present",
            "native_present",
        }
        if successful:
            await rig.management.authorize_job(job)
            assert calls == ([] if condition == "valid" else [condition])
        else:
            with pytest.raises(ValueError):
                await rig.management.authorize_job(job)
            assert calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "condition",
    [
        "valid",
        "invalid_nonce",
        "bad_batch",
        "oversized_batch",
        "wrong_binding",
        "oversized_frame",
        "invalid_active",
        "bad_ack",
        "orphan_main",
        "orphan_diagnostic",
        "unauthorized",
    ],
)
def test_worker_frames_and_active_lease_controls_fail_closed(
    rig: ManagementFixture, monkeypatch: pytest.MonkeyPatch, condition: str
) -> None:
    from types import SimpleNamespace

    async def scenario() -> None:
        management = rig.management

        async def worker(_: web.Request) -> tuple[SimpleNamespace, SimpleNamespace]:
            return SimpleNamespace(endpoint_id=rig.endpoint), SimpleNamespace(
                identity_id=rig.identity
            )

        async def authorize(_: dict[str, Any]) -> None:
            if condition == "unauthorized":
                raise ValueError("Permission revoked")

        monkeypatch.setattr(management, "worker_identity", worker)
        monkeypatch.setattr(management, "authorize_job", authorize)
        action = "posture" if condition == "wrong_binding" else "shell.start"
        job = rig.add(action, {})
        management.store.dispatch(job)
        management.shell_leases[job] = time.time() + 300
        management.store.io(job, "in", 1, {"data": base64.b64encode(b"input").decode()})
        body: dict[str, Any] = {
            "nonce": "0123456789abcdef",
            "active": job,
            "input_ack": 0,
            "frames": [
                {
                    "job": job,
                    "sequence": 1,
                    "data": base64.b64encode(b"output").decode(),
                }
            ],
        }
        if condition == "invalid_nonce":
            body["nonce"] = "short"
        if condition == "bad_batch":
            body["frames"] = {}
        if condition == "oversized_batch":
            body["receipts"] = [{}] * 5
        if condition == "oversized_frame":
            body["frames"][0]["data"] = base64.b64encode(b"x" * 16385).decode()
        if condition == "invalid_active":
            body["active"] = "not-an-id"
        if condition == "bad_ack":
            body["input_ack"] = True
        if condition == "orphan_main":
            body["active"] = str(uuid4())
        if condition == "orphan_diagnostic":
            body["diagnostic_active"] = str(uuid4())
        async with TestClient(TestServer(management.worker_application())) as client:
            response = await client.post("/v1/management/poll", json=body)
            rejected = condition in {
                "invalid_nonce",
                "bad_batch",
                "oversized_batch",
                "wrong_binding",
                "oversized_frame",
                "invalid_active",
                "bad_ack",
            }
            assert response.status == (403 if rejected else 200)
            if not rejected:
                payload = json.loads(
                    base64.b64decode((await response.json())["payload"])
                )
                assert payload["frame_ack"] == [[job, 1]]
                controls = {item["job"]: item for item in payload["controls"]}
                if condition in {"orphan_main", "orphan_diagnostic"}:
                    orphan = (
                        body["active"]
                        if condition == "orphan_main"
                        else body["diagnostic_active"]
                    )
                    assert controls[orphan] == {
                        "job": orphan,
                        "cancel": True,
                        "lease": 0,
                    }
                else:
                    assert controls[job]["cancel"] == (condition == "unauthorized")
                    assert controls[job]["input"][0]["sequence"] == 1
                assert (
                    management.store.frames(job, "out", 0)[0]["value"]["data"]
                    == body["frames"][0]["data"]
                )

    asyncio.run(scenario())


def test_request_validation_and_cancel_paths_do_not_dispatch(
    rig: ManagementFixture,
) -> None:
    async def scenario() -> None:
        job = rig.add("posture", {})
        wrong = rig.add("posture", {}, owner=replace(rig.principal, subject="other"))
        async with TestClient(TestServer(rig.app())) as client:
            assert (
                await client.get("/remote/not-a-uuid/manage/state", headers=rig.headers)
            ).status == 404
            assert (
                await client.post(
                    rig.base + "/action", data="not-json", headers=rig.headers
                )
            ).status == 415
            assert (
                await client.post(rig.base + "/action", json=[], headers=rig.headers)
            ).status == 400
            for token in (None, "unknown"):
                assert (
                    await client.post(
                        rig.base + "/action",
                        json={"csrf": token, "action": "cancel", "job": job},
                        headers=rig.headers,
                    )
                ).status == 403
            response = await client.post(
                rig.base + "/action",
                json={"csrf": rig.nonce, "action": "cancel", "job": wrong},
                headers=rig.headers,
            )
            assert (
                response.status == 403 and not rig.management.store.job(wrong)["cancel"]
            )
            response = await client.post(
                rig.base + "/action",
                json={"csrf": rig.nonce, "action": "cancel", "job": job},
                headers=rig.headers,
            )
            assert response.status == 200 and rig.management.store.job(job)["cancel"]
            rig.management.store.seen(rig.endpoint, uuid4(), {})
            state = await (
                await client.get(rig.base + "/state", headers=rig.headers)
            ).json()
            assert (
                not state["worker"]["ready"]
                and "enrollment" in state["worker"]["reason"]
            )
            rig.management.forms = {
                str(index): (
                    rig.principal.subject,
                    rig.principal.session_id,
                    str(rig.endpoint),
                    time.time() + 300,
                )
                for index in range(128)
            }
            assert (await client.get(rig.base, headers=rig.headers)).status == 503

    asyncio.run(scenario())
