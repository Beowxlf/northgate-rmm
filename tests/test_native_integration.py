"""Native service identity, dispatch, revocation and scope regression coverage."""

import asyncio
import hashlib
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.capture_store import CaptureStore
from northgate_rmm.capture_ui import CaptureUI
from northgate_rmm.inspection import InspectionStore
from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.native_api import NativeAPI
from northgate_rmm.native_client import NativeClient, NoRedirect


def fixture(tmp_path):
    endpoint, identity = uuid4(), uuid4()
    registry = tmp_path / "integration.json"
    token = "A" * 43
    entry = dict(
        id="test",
        token_sha256=hashlib.sha256(token.encode()).hexdigest(),
        enabled=True,
        endpoints={str(endpoint): str(identity)},
        actions=["observe", "capabilities", "shell.start", "capture.control"],
    )

    def save():
        registry.write_text(json.dumps(dict(schema=1, clients=[entry])))
        registry.chmod(0o600)

    save()
    device = SimpleNamespace(
        identity_id=identity, platform=SimpleNamespace(value="linux")
    )
    status = SimpleNamespace(
        lifecycle=SimpleNamespace(value="active"),
        health=SimpleNamespace(value="online"),
    )
    audit = []

    async def log(principal, ep, action, correlation):
        assert principal.mfa is False and principal.subject == "integration:test"
        audit.append(action)

    target = SimpleNamespace(endpoint_id=endpoint, identity_id=identity)
    gateway = SimpleNamespace(
        key=bytes(16),
        targets={endpoint: (target, {})},
        audit=log,
        operation=SimpleNamespace(
            _store=SimpleNamespace(
                get_endpoint=lambda _: device, endpoint_status=lambda *a, **k: status
            )
        ),
    )
    store = ManagementStore(tmp_path / "management", bytes(16))
    store.worker = lambda _: dict(ready=True, identity=str(identity), capabilities={})
    management = Management(gateway, store)
    rows = [dict(id=str(endpoint), identity=str(identity), health="online")]
    fleet = SimpleNamespace(
        inventory=lambda: rows, store=SimpleNamespace(list=lambda *a, **k: [])
    )
    capture_actions = []

    async def capture_runner(target, params, platform, envelope, destination):
        import base64

        claims = json.loads(base64.b64decode(envelope["payload"]))
        capture_actions.append(claims["action"])
        return dict(
            id=claims["job_id"],
            endpoint_id=str(endpoint),
            identity_id=str(identity),
            state="capturing",
        )

    capture = CaptureUI(gateway, CaptureStore(tmp_path / "capture"), capture_runner)
    inspection = SimpleNamespace(store=InspectionStore(tmp_path / "inspection.sqlite3"))
    api = NativeAPI(management, fleet, capture, inspection, registry)
    return SimpleNamespace(
        api=api,
        endpoint=endpoint,
        identity=identity,
        entry=entry,
        save=save,
        token=token,
        audit=audit,
        capture_actions=capture_actions,
        device=device,
        status=status,
    )


def test_native_dispatch_idempotency_and_audit(tmp_path):
    async def scenario():
        f = fixture(tmp_path)
        app = web.Application()
        f.api.register(app)
        async with TestClient(TestServer(app)) as client:

            async def call(operation, arguments):
                return await client.post(
                    "/native/v1/rpc",
                    json=dict(operation=operation, arguments=arguments),
                    headers={"Authorization": "Bearer " + f.token},
                )

            response = await call("devices", {})
            assert response.status == 200
            assert len((await response.json())["devices"]) == 1
            identifier = str(uuid4())
            args = dict(
                endpoint=str(f.endpoint),
                action="capabilities",
                params={},
                request_id=identifier,
            )
            assert (await call("submit_job", args)).status == 200
            assert (await (await call("submit_job", args)).json())["reused"]
            job = f.api.m.store.job(identifier, private=True)
            assert f.token not in json.dumps(job)
            assert job["subject"] == "integration:test"
            await f.api.m.authorize_job(job)
            assert f.audit.count("integration.job.requested.capabilities") == 1
            args["action"] = "shell.start"
            args["params"] = dict(columns=80, rows=24)
            assert (await call("submit_job", args)).status == 409
            f.entry["enabled"] = False
            f.save()
            assert (await call("devices", {})).status == 401
            with pytest.raises(ValueError):
                await f.api.m.authorize_job(job)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "change",
    [
        "action",
        "params",
        "endpoint",
        "identity",
        "subject",
        "session",
        "signature",
        "rotation",
        "permission",
        "enrollment",
    ],
)
def test_native_jobs_fail_closed_when_changed(tmp_path, change):
    async def scenario():
        f = fixture(tmp_path)
        result = await f.api.submit(
            f.entry, f.endpoint, f.device, "capabilities", {}, str(uuid4())
        )
        job = f.api.m.store.job(result["job"], private=True)
        if change in {"action", "endpoint", "identity", "subject", "session"}:
            job[change] = "changed"
        elif change == "params":
            job["payload"]["params"] = {"changed": True}
        elif change == "signature":
            job["payload"]["authorization"] += "0"
        elif change == "rotation":
            f.entry["token_sha256"] = "b" * 64
            f.save()
        elif change == "permission":
            f.entry["actions"].remove("capabilities")
            f.save()
        elif change == "enrollment":
            f.device.identity_id = uuid4()
        with pytest.raises((ValueError, web.HTTPException)):
            await f.api.m.authorize_job(job)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "case", ["missing", "invalid", "browser", "scope", "secret", "offline", "oversized"]
)
def test_native_http_boundaries(tmp_path, case):
    async def scenario():
        f = fixture(tmp_path)
        app = web.Application(client_max_size=2 * 1024 * 1024)
        f.api.register(app)
        headers = {"Authorization": "Bearer " + f.token}
        operation, arguments = "devices", {}
        if case == "missing":
            headers = {}
        if case == "invalid":
            headers["Authorization"] = "Bearer invalid"
        if case == "browser":
            headers["Origin"] = "https://untrusted.test"
        if case == "scope":
            operation, arguments = "device", {"endpoint": str(uuid4())}
        if case in {"secret", "offline"}:
            operation, arguments = (
                "submit_job",
                dict(
                    endpoint=str(f.endpoint),
                    action="bitlocker.escrow" if case == "secret" else "capabilities",
                    params={},
                    request_id=str(uuid4()),
                ),
            )
        if case == "offline":
            f.status.health.value = "offline"
        if case == "oversized":
            arguments = {"data": "x" * (1024 * 1024)}
        async with TestClient(TestServer(app)) as client:
            response = await client.post(
                "/native/v1/rpc",
                json=dict(operation=operation, arguments=arguments),
                headers=headers,
            )
            assert response.status in {400, 401, 403, 409, 413}
            assert not f.api.m.store.list(f.endpoint)

    asyncio.run(scenario())


def test_native_capture_reservation_and_keepalive(tmp_path):
    async def scenario():
        f = fixture(tmp_path)
        args = dict(
            endpoint=str(f.endpoint), interface=1, request_id=str(uuid4()), seconds=5
        )
        first = await f.api.call(f.entry, "capture_start", args)
        assert (await f.api.call(f.entry, "capture_start", args))["id"] == first["id"]
        assert f.capture_actions == ["start"]
        await f.api.call(
            f.entry, "capture_status", dict(endpoint=str(f.endpoint), job=first["id"])
        )
        assert f.capture_actions == ["start", "status", "keepalive"]
        args["seconds"] = 10
        with pytest.raises(ValueError):
            await f.api.call(f.entry, "capture_start", args)

    asyncio.run(scenario())


@pytest.mark.parametrize("race", [False, True])
def test_native_capture_completion_does_not_renew_finished_job(tmp_path, race):
    async def scenario():
        import base64

        f = fixture(tmp_path)
        first = await f.api.call(
            f.entry,
            "capture_start",
            dict(endpoint=str(f.endpoint), interface=1, request_id=str(uuid4())),
        )
        calls = []

        async def runner(target, params, platform, envelope, destination):
            action = json.loads(base64.b64decode(envelope["payload"]))["action"]
            calls.append(action)
            if action == "keepalive":
                raise ValueError("Capture already completed")
            return {
                **first,
                "state": "capturing" if race and len(calls) == 1 else "completed",
            }

        f.api.capture.runner = runner
        result = await f.api.call(
            f.entry, "capture_status", dict(endpoint=str(f.endpoint), job=first["id"])
        )
        assert result["state"] == "completed"
        assert calls == (["status", "keepalive", "status"] if race else ["status"])

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost",
        "file:///secret",
        "https://host/path",
        "https://user:pass@host",
    ],
)
def test_native_client_rejects_unsafe_origins(tmp_path, origin):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"origin": origin}))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        NativeClient(path)


def test_native_client_never_forwards_credentials_on_redirect():
    with pytest.raises(ValueError):
        NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test")
