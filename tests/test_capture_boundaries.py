"""Capture catalog and native controls reject malformed or excessive work."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from northgate_rmm.capture_store import CaptureStore
from tests.test_native_integration import fixture
from tests.test_remote_access import PRINCIPAL, TARGET


@pytest.mark.parametrize(
    "mode",
    [
        "json",
        "entry",
        "manifest",
        "version_type",
        "version_format",
        "installed",
        "digest",
        "signature",
    ],
)
def test_capture_release_parser_rejects_invalid_catalog_entries(
    tmp_path: Path, mode: str
) -> None:
    f = fixture(tmp_path)
    setup = f.api.setup
    setup.m.extended.catalog.mkdir()
    path = setup.m.extended.catalog / "release.json"
    manifest: dict[str, object] = {
        "component": "wxlfgar",
        "platform": "linux",
        "version": "1.2.0",
        "sha256": "a" * 64,
    }
    entry: object = {
        "manifest": manifest,
        "url": "https://management.test/release",
        "signature": "synthetic",
    }
    if mode == "entry":
        entry = []
    elif mode == "manifest":
        entry = {"manifest": []}
    elif mode == "version_type":
        manifest["version"] = 1
    elif mode == "version_format":
        manifest["version"] = "dev"
    elif mode == "digest":
        manifest["sha256"] = "bad"
    elif mode == "signature":
        entry = {
            "manifest": manifest,
            "url": "https://management.test/release",
            "signature": False,
        }
    path.write_text("{" if mode == "json" else json.dumps(entry))
    path.chmod(0o600)
    assert (
        setup.release("linux", installed="0.0.1" if mode == "installed" else None)
        is None
    )


def test_capture_history_capacity_is_enforced_before_insertion(tmp_path: Path) -> None:
    store = CaptureStore(tmp_path)
    import time

    with store.connect() as db:
        db.executemany(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?)",
            [
                (
                    str(index),
                    str(TARGET.endpoint_id),
                    str(TARGET.identity_id),
                    PRINCIPAL.subject,
                    PRINCIPAL.session_id,
                    time.time(),
                    time.time(),
                    "{}",
                )
                for index in range(2000)
            ],
        )
    with pytest.raises(ValueError, match="history is full"):
        store.add(
            TARGET.endpoint_id, TARGET.identity_id, PRINCIPAL, {"id": str(uuid4())}
        )
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM jobs").fetchone()[0] == 2000


@pytest.mark.parametrize(
    "field,value",
    [
        ("interface", "0"),
        ("interface", "abc"),
        ("seconds", 4),
        ("seconds", "60"),
        ("max_mib", 33),
        ("port", 65536),
        ("preset", "unknown"),
        ("host", "invalid"),
    ],
)
def test_native_capture_rejects_invalid_request_before_dispatch(
    tmp_path: Path, field: str, value: object
) -> None:
    async def scenario() -> None:
        f = fixture(tmp_path)
        params = {
            "endpoint": str(f.endpoint),
            "request_id": str(uuid4()),
            "interface": "1",
            field: value,
        }
        with pytest.raises(ValueError):
            await f.api.call(f.entry, "capture_start", params)
        assert not f.capture_actions
        assert (
            f.api.capture.store.history(f.endpoint, f.identity, "integration:test")
            == []
        )

    asyncio.run(scenario())


def test_native_capture_readback_and_unknown_jobs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def scenario() -> None:
        f = fixture(tmp_path)
        args = {"endpoint": str(f.endpoint)}
        assert await f.api.call(f.entry, "capture_history", args) == {"captures": []}
        await f.api.call(f.entry, "capture_capabilities", args)
        assert f.capture_actions == ["capabilities"]
        with pytest.raises(ValueError, match="owned"):
            await f.api.call(f.entry, "capture_status", {**args, "job": str(uuid4())})
        with pytest.raises(ValueError, match="Unknown capture"):
            await f.api.call(f.entry, "capture_nonsense", args)
        identifier = str(uuid4())
        started = await f.api.call(
            f.entry,
            "capture_start",
            {**args, "request_id": identifier, "interface": "1", "host": "192.0.2.3"},
        )
        captures = await f.api.call(f.entry, "capture_history", args)
        assert captures["captures"][0]["id"] == started["id"]
        with pytest.raises(ValueError, match="identifier conflict"):
            await f.api.call(
                f.entry,
                "capture_start",
                {**args, "request_id": identifier, "interface": "2"},
            )
        stale = dict(started)
        stale["state"] = "capturing"
        runner = AsyncMock(side_effect=[stale, ValueError("lease rejected"), stale])
        monkeypatch.setattr(f.api.capture, "runner", runner)
        with pytest.raises(ValueError, match="could not be renewed"):
            await f.api.call(f.entry, "capture_status", {**args, "job": identifier})
        assert runner.await_count == 3

    asyncio.run(scenario())
