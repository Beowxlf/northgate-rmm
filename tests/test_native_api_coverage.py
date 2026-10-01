"""Native request boundaries, catalog dispatch and data-release regression tests."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.management_store import QueueFull
from northgate_rmm.native_api import MAX_NATIVE_BODY
from tests.test_inspection import result as inspection_result
from tests.test_native_integration import fixture
from tests.test_tool_catalog_models import manifest


@pytest.mark.parametrize(
    "mode,status",
    [
        ("origin", 403),
        ("auth", 401),
        ("type", 415),
        ("length", 413),
        ("array", 400),
        ("arguments", 400),
        ("operation", 400),
        ("chunks", 400),
        ("queue", 429),
        ("os", 502),
        ("timeout", 502),
        ("invalid", 400),
    ],
)
def test_native_http_rejects_untrusted_requests_and_dependency_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str, status: int
) -> None:
    async def scenario() -> None:
        f = fixture(tmp_path)
        headers = {
            "Authorization": "Bearer " + f.token,
            "Content-Type": "application/json",
        }
        body = json.dumps({"operation": "describe", "arguments": {}}).encode()
        if mode == "origin":
            headers["Origin"] = "https://operator.test"
        if mode == "auth":
            headers["Authorization"] = "Bearer wrong"
        if mode == "type":
            headers["Content-Type"] = "text/plain"
        if mode in {"length", "chunks"}:
            body = b"x" * (MAX_NATIVE_BODY + 1)
        if mode == "array":
            body = b"[]"
        if mode == "arguments":
            body = b'{"operation":"describe","arguments":[]}'
        if mode == "operation":
            body = b'{"operation":1,"arguments":{}}'
        errors = {
            "queue": QueueFull(),
            "os": OSError(),
            "timeout": TimeoutError(),
            "invalid": ValueError(),
        }
        if mode in errors:
            monkeypatch.setattr(f.api, "call", AsyncMock(side_effect=errors[mode]))
        app = web.Application(client_max_size=3 * 1024 * 1024)
        f.api.register(app)
        async with TestClient(TestServer(app)) as client:
            response = await client.post(
                "/native/v1/rpc",
                headers=headers,
                data=body,
                chunked=True if mode == "chunks" else None,
            )
            assert response.status == status
            assert "Traceback" not in await response.text()

    asyncio.run(scenario())


def test_native_inventory_catalog_and_jobs_are_scoped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def scenario() -> None:
        f = fixture(tmp_path)
        f.entry["actions"] += ["inspection.collect", "tool.install"]
        f.save()
        args = {"endpoint": str(f.endpoint)}
        device = await f.api.call(f.entry, "device", args)
        assert device["device"]["identity"] == str(f.identity)
        assert device["alerts"] == []
        data = inspection_result()
        monkeypatch.setattr(
            "northgate_rmm.inspection.run_inspection", AsyncMock(return_value=data)
        )
        collected = await f.api.call(
            f.entry, "collect_inventory", {**args, "category": "services"}
        )
        assert collected["result"] == data
        snapshots = await f.api.call(
            f.entry, "inventory", {**args, "category": "services"}
        )
        assert snapshots["snapshots"][0]["id"] == collected["snapshot"]
        assert snapshots["snapshots"][0]["result"] == data
        for operation in ("inventory", "collect_inventory"):
            with pytest.raises(ValueError, match="category"):
                await f.api.call(f.entry, operation, {**args, "category": "bad"})
        entry = {
            "manifest": manifest(),
            "signature": base64.b64encode(bytes(64)).decode(),
        }
        monkeypatch.setattr(
            "northgate_rmm.tool_catalog.ToolCatalog.entries",
            MagicMock(return_value=[entry]),
        )
        catalog = await f.api.call(f.entry, "tool_catalog", args)
        osquery = next(tool for tool in catalog["tools"] if tool["id"] == "osquery")
        assert osquery["releases"] == [entry["manifest"]]
        installed = await f.api.call(
            f.entry,
            "install_tool",
            {
                **args,
                "tool_id": "osquery",
                "version": "5.19.0",
                "request_id": str(uuid4()),
            },
        )
        assert installed["action"] == "tool.install"
        for changes in (
            {"tool_id": "unknown", "version": "5.19.0"},
            {"tool_id": "osquery", "version": "0"},
        ):
            with pytest.raises(ValueError, match="approved catalog"):
                await f.api.call(f.entry, "install_tool", {**args, **changes})
        jobs = await f.api.call(f.entry, "jobs", args)
        assert jobs["jobs"][0]["id"] == installed["job"]
        job = await f.api.call(f.entry, "job", {**args, "job": installed["job"]})
        assert job["job"]["action"] == "tool.install"
        with pytest.raises(ValueError, match="catalog"):
            await f.api.call(f.entry, "submit_job", {**args, "action": "tool.install"})
        with pytest.raises(web.HTTPForbidden):
            await f.api.submit(
                f.entry, f.endpoint, f.device, "bitlocker.escrow", {}, str(uuid4())
            )
        with pytest.raises(ValueError, match="Unknown operation"):
            await f.api.call(f.entry, "nonsense", args)
        with pytest.raises(web.HTTPServiceUnavailable):
            await f.api.call(f.entry, "ops.state", {})
        ops = MagicMock(native_call=AsyncMock(return_value={"cases": []}))
        f.api.operations = ops
        assert await f.api.call(f.entry, "ops.state", {}) == {"cases": []}
        ops.native_call.assert_awaited_once_with(f.entry, "state", {})

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "operation,upgrade,component",
    [
        ("capture_setup", False, "wxlfgar"),
        ("capture_setup", True, "worker"),
        ("install_release", False, "agent"),
    ],
)
def test_native_release_dispatch_selects_catalog_and_signing_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operation: str,
    upgrade: bool,
    component: str,
) -> None:
    async def scenario() -> None:
        f = fixture(tmp_path)
        f.entry["actions"] += ["capture.install", "update.install"]
        f.save()
        release = {
            "manifest": {"sha256": "a" * 64, "version": "1.2.0"},
            "url": "https://management.test/v1/management/releases/" + "a" * 64,
            "signature": base64.b64encode(bytes(64)).decode(),
        }
        monkeypatch.setattr(
            f.api.setup,
            "worker_release",
            MagicMock(return_value=release if upgrade else None),
        )
        monkeypatch.setattr(f.api.setup, "release", MagicMock(return_value=release))
        result = await f.api.call(
            f.entry,
            operation,
            {
                "endpoint": str(f.endpoint),
                "component": component,
                "request_id": str(uuid4()),
            },
        )
        job = f.api.m.store.job(result["job"], private=True)
        params = job["payload"]["params"]
        assert params["sha256"] == "a" * 64
        if operation == "capture_setup" and not upgrade:
            assert len(base64.b64decode(params["public_key"])) == 32
        else:
            assert params["component"] == component
        monkeypatch.setattr(f.api.setup, "worker_release", MagicMock(return_value=None))
        monkeypatch.setattr(f.api.setup, "release", MagicMock(return_value=None))
        with pytest.raises(web.HTTPConflict):
            await f.api.call(
                f.entry,
                operation,
                {"endpoint": str(f.endpoint), "component": component},
            )
        with pytest.raises(ValueError, match="component"):
            await f.api.call(
                f.entry,
                "install_release",
                {"endpoint": str(f.endpoint), "component": "bad"},
            )

    asyncio.run(scenario())


def test_native_job_reads_never_release_secret_receipts_or_other_enrollments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def scenario() -> None:
        f = fixture(tmp_path)
        args = {"endpoint": str(f.endpoint)}
        job = {
            "id": str(uuid4()),
            "endpoint": str(f.endpoint),
            "identity": str(f.identity),
            "action": "bitlocker.escrow",
            "subject": "integration:test",
            "receipt": {"secret": "synthetic"},
        }
        monkeypatch.setattr(
            f.api.m.store,
            "list",
            MagicMock(return_value=[dict(job), {**job, "identity": str(uuid4())}]),
        )
        listed = await f.api.call(f.entry, "jobs", args)
        assert len(listed["jobs"]) == 1
        assert "receipt" not in listed["jobs"][0]
        monkeypatch.setattr(f.api.m.store, "job", MagicMock(return_value=dict(job)))
        value = await f.api.call(f.entry, "job", {**args, "job": job["id"]})
        assert "receipt" not in value["job"]
        monkeypatch.setattr(
            f.api.m.store,
            "job",
            MagicMock(return_value={**job, "identity": str(uuid4())}),
        )
        with pytest.raises(web.HTTPNotFound):
            await f.api.call(f.entry, "job", {**args, "job": job["id"]})
        with pytest.raises(web.HTTPForbidden):
            await f.api.call(f.entry, "cancel_job", {**args, "job": job["id"]})

    asyncio.run(scenario())
