"""Source-level contract checks prepared for the subsequent bug-review phase."""

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from northgate_rmm.capture_store import CaptureStore
from northgate_rmm.capture_transport import request_tool
from northgate_rmm.capture_ui import CaptureUI, script_json, validate_job
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import RemoteTarget


def test_capture_signature_binds_action_and_identity(tmp_path: Path) -> None:
    gateway = SimpleNamespace(key=b"synthetic-key-16", origin="https://operator.test")
    ui = CaptureUI(cast(RemoteGateway, gateway), CaptureStore(tmp_path / "capture"))
    target = SimpleNamespace(endpoint_id=uuid4(), identity_id=uuid4())
    principal = SimpleNamespace(subject="owner", session_id="session")
    envelope = ui.envelope(
        cast(RemoteTarget, target), cast(OperatorPrincipal, principal), "stop", uuid4()
    )
    payload = base64.b64decode(envelope["payload"])
    ui.key.public_key().verify(
        base64.b64decode(envelope["signature"]), b"NorthGate-Wxlfgar-v1\0" + payload
    )
    claims = json.loads(payload)
    assert claims["endpoint_id"] == str(target.endpoint_id)
    assert claims["identity_id"] == str(target.identity_id)
    assert claims["expires"] - claims["issued"] == 45
    assert claims["action"] == "stop"


def test_capture_history_is_bound_to_enrollment(tmp_path: Path) -> None:
    store = CaptureStore(tmp_path / "capture")
    endpoint, identity, job_id = uuid4(), uuid4(), uuid4()
    principal = SimpleNamespace(subject="owner", session_id="session")
    job = {
        "id": str(job_id),
        "endpoint_id": str(endpoint),
        "identity_id": str(identity),
        "state": "capturing",
    }
    store.add(endpoint, identity, cast(OperatorPrincipal, principal), job)
    assert store.get(endpoint, identity, "owner", str(job_id))
    assert store.get(endpoint, uuid4(), "owner", str(job_id)) is None
    assert store.get(endpoint, identity, "other", str(job_id)) is None
    with pytest.raises(ValueError):
        validate_job(job, job_id, endpoint, uuid4())


def test_script_payload_cannot_close_script() -> None:
    payload = {"description": '</script><script>alert("x")</script>\u2028'}
    encoded = script_json(payload)
    assert "<" not in encoded
    assert json.loads(encoded) == payload


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", []),
        ("report", []),
        ("artifacts", {}),
        ("artifacts", [{"name": "../../secret"}]),
        ("report", {"flows": [None]}),
        ("report", {"assets": [{"roles": [None]}]}),
        ("report", {"warnings": "invalid"}),
        ("report", {"packets": float("nan")}),
    ],
)
def test_malformed_capture_response_rejected(field: str, value: object) -> None:
    endpoint, identity, job_id = uuid4(), uuid4(), uuid4()
    job: dict[str, object] = dict(
        id=str(job_id),
        endpoint_id=str(endpoint),
        identity_id=str(identity),
        state="completed",
    )
    job[field] = value
    with pytest.raises(ValueError):
        validate_job(job, job_id, endpoint, identity)


def test_queued_rpc_revalidates_session(tmp_path: Path) -> None:
    async def scenario() -> None:
        principal = SimpleNamespace(subject="owner", session_id="session")
        revoked = False
        calls = []

        async def authenticate(*args: object) -> SimpleNamespace:
            if revoked:
                raise web.HTTPForbidden()
            return principal

        async def runner(*args: object) -> dict[str, Any]:
            calls.append(args)
            raise AssertionError("Revoked request must not reach the capture runner")

        gateway = SimpleNamespace(key=b"synthetic-key-16", principal=authenticate)
        ui = CaptureUI(cast(RemoteGateway, gateway), CaptureStore(tmp_path), runner)
        ui.slots = asyncio.Semaphore(0)
        task = asyncio.create_task(
            ui.rpc(
                cast(
                    RemoteTarget,
                    SimpleNamespace(endpoint_id=uuid4(), identity_id=uuid4()),
                ),
                {},
                "linux",
                cast(OperatorPrincipal, principal),
                "capabilities",
                request=make_mocked_request("POST", "/"),
            )
        )
        await asyncio.sleep(0)
        revoked = True
        ui.slots.release()
        with pytest.raises(web.HTTPForbidden):
            await task
        assert calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode", ["valid", "tampered", "bad_chunk", "empty_chunk", "wrong_size", "truncated"]
)
def test_artifact_transport_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    async def scenario() -> None:
        data = b"synthetic packet data\x00\xff"
        manifest: dict[str, Any] = dict(
            name="capture.pcap", size=len(data), sha256=hashlib.sha256(data).hexdigest()
        )
        if mode == "wrong_size":
            manifest["size"] += 1
        chunk: object = {
            "data": base64.b64encode(
                data if mode != "tampered" else b"X" * len(data)
            ).decode()
        }
        if mode == "bad_chunk":
            chunk = []
        if mode == "empty_chunk":
            chunk = {"data": ""}
        lines = [dict(artifact=manifest), chunk, dict(done=True, size=len(data))]
        if mode == "truncated":
            lines.pop()
        stream = asyncio.StreamReader()
        stream.feed_data(b"".join(json.dumps(line).encode() + b"\n" for line in lines))
        stream.feed_eof()

        class Input:
            def write(self, data: bytes) -> None:
                pass

            async def drain(self) -> None:
                pass

            def close(self) -> None:
                pass

        class Process:
            returncode = 0
            stdin = Input()
            stdout = stream

            async def wait(self) -> int:
                return 0

        async def spawn(*args: object, **kwargs: object) -> Process:
            assert "StrictHostKeyChecking=yes" in args
            return Process()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        params = {
            "username": "rmmremote",
            "host-key": "10.0.0.2 ssh-ed25519 synthetic",
            "private-key": "synthetic-only",
        }
        target = SimpleNamespace(address="10.0.0.2")
        path = tmp_path / "artifact"
        if mode == "valid":
            assert (
                await request_tool(
                    cast(RemoteTarget, target), params, "linux", {}, path
                )
                == manifest
            )
            assert path.read_bytes() == data
        else:
            with pytest.raises(ValueError):
                await request_tool(
                    cast(RemoteTarget, target), params, "linux", {}, path
                )

    asyncio.run(scenario())


def test_capture_origin_and_session_bound_form(tmp_path: Path) -> None:
    gateway = SimpleNamespace(key=b"synthetic-key-16", origin="https://operator.test")
    ui = CaptureUI(cast(RemoteGateway, gateway), CaptureStore(tmp_path))
    with pytest.raises(web.HTTPForbidden):
        ui.origin(
            cast(
                web.Request,
                SimpleNamespace(
                    headers={"Origin": "https://attacker.test"}, content_length=0
                ),
            )
        )
    principal = SimpleNamespace(subject="owner", session_id="session")
    endpoint = uuid4()
    token = ui.nonce(cast(OperatorPrincipal, principal), endpoint)
    assert ui.forms[token][:3] == ("owner", "session", endpoint)


@pytest.mark.parametrize("lost_reply", [False, True])
def test_capture_http_workflow_and_lost_start_reply(
    tmp_path: Path, lost_reply: bool
) -> None:
    import re

    from aiohttp.test_utils import TestClient, TestServer

    async def scenario() -> None:
        endpoint, identity = uuid4(), uuid4()
        principal = SimpleNamespace(subject="owner", session_id="session")
        target = SimpleNamespace(endpoint_id=endpoint, identity_id=identity)

        async def authenticate(*args: object, **kwargs: object) -> SimpleNamespace:
            return principal

        async def audit(*args: object) -> None:
            pass

        jobs: dict[str, dict[str, Any]] = {}

        async def runner(
            target: RemoteTarget,
            params: dict[str, str],
            platform: str,
            envelope: dict[str, str],
            destination: Path | None,
        ) -> dict[str, Any]:
            c = json.loads(base64.b64decode(envelope["payload"]))
            if c["action"] == "capabilities":
                return {
                    "state": "ready",
                    "interfaces": [{"CaptureName": "1", "Name": "Synthetic NIC"}],
                }
            job_id = c["job_id"]
            if c["action"] == "start":
                jobs[job_id] = dict(
                    id=job_id,
                    endpoint_id=str(endpoint),
                    identity_id=str(identity),
                    state="capturing",
                    artifacts=[],
                    started="2026-09-06T12:00:00Z",
                )
                if lost_reply:
                    raise TimeoutError()
            if c["action"] == "status":
                jobs[job_id].update(
                    state="completed",
                    report={
                        "findings": [
                            {"description": "</script><img src=x onerror=alert(1)>"}
                        ],
                        "assets": [],
                        "flows": [],
                        "warnings": [],
                    },
                )
            return jobs[job_id]

        gateway = SimpleNamespace(
            key=b"synthetic-key-16",
            origin="https://operator.test",
            principal=authenticate,
            audit=audit,
            targets={endpoint: (target, {})},
            operation=SimpleNamespace(
                _store=SimpleNamespace(
                    get_endpoint=lambda e: SimpleNamespace(
                        platform=SimpleNamespace(value="linux")
                    )
                )
            ),
        )
        store = CaptureStore(tmp_path)
        ui = CaptureUI(cast(RemoteGateway, gateway), store, runner)
        app = web.Application()
        ui.register(app)
        async with TestClient(TestServer(app)) as client:
            url = f"/remote/{endpoint}/capture"
            page = await client.get(url)
            html = await page.text()
            nonce = re.findall(r'name="nonce" value="([^"]+)"', html)[0]
            assert '<option value="1536">' in html
            fields = dict(
                nonce=nonce,
                action="start",
                seconds="60",
                size="16",
                snaplen="1536",
                interface="1",
                preset="all",
            )
            response = await client.post(
                url,
                data=fields,
                headers={"Origin": gateway.origin},
                allow_redirects=False,
            )
            assert response.status == (502 if lost_reply else 303)
            history = store.history(endpoint, identity, "owner")
            assert len(history) == 1
            job_id = history[0]["id"]
            # The same job remains retrievable even when the start reply is lost.
            state = await client.get(url + "/state?job=" + job_id)
            assert state.status == 200
            assert (await state.json())["state"] == "completed"
            rendered = await client.get(url + "?job=" + job_id)
            html = await rendered.text()
            assert "</script><img" not in html
            assert r"\u003c/script>" in html
            assert "script-src 'sha256-" in rendered.headers["Content-Security-Policy"]
            replay = await client.post(
                url, data=fields, headers={"Origin": gateway.origin}
            )
            assert replay.status == 403

    asyncio.run(scenario())
