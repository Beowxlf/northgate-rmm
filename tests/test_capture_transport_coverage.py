"""Signed capture transport validation and subprocess termination boundaries."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import pytest

from northgate_rmm.capture_transport import request_tool
from tests.test_remote_access import TARGET


@pytest.mark.parametrize(
    "field,value",
    [
        ("username", "user;id"),
        ("private-key", ""),
        ("host-key", "missing"),
        ("host-key", "host ssh-unsupported key"),
        ("platform", "other"),
    ],
)
def test_capture_transport_rejects_unpinned_configuration(
    field: str, value: str
) -> None:
    params = {
        "username": "operator",
        "private-key": "synthetic-key",
        "host-key": "host ssh-ed25519 synthetic",
    }
    platform = value if field == "platform" else "linux"
    if field != "platform":
        params[field] = value
    with pytest.raises(ValueError):
        asyncio.run(request_tool(TARGET, params, platform, {}))


@pytest.mark.parametrize(
    "mode",
    [
        "windows",
        "pipes",
        "oversized",
        "error",
        "manifest",
        "chunk_missing",
        "trailer",
        "exceeded",
        "extra",
        "exit",
        "malformed",
    ],
)
def test_capture_transport_validates_results_and_cleans_processes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    async def scenario() -> None:
        artifact = mode in {"manifest", "chunk_missing", "trailer", "exceeded"}
        lines: list[object] = [{"state": "ready"}]
        if artifact:
            lines = [
                {"artifact": {"name": "summary.txt", "size": 1, "sha256": "0" * 64}},
                {"data": base64.b64encode(b"a").decode()},
                {"done": True, "size": 1},
            ]
        if mode == "error":
            lines = [{"error": "rejected"}]
        elif mode == "manifest":
            lines[0] = {"artifact": {"name": "unknown"}}
        elif mode == "chunk_missing":
            lines[1] = {}
        elif mode == "trailer":
            lines[2] = {"done": True, "size": 0}
        elif mode == "exceeded":
            lines[1] = {"data": base64.b64encode(b"ab").decode()}
        elif mode == "extra":
            lines.append({"extra": True})
        data = b"".join(json.dumps(line).encode() + b"\n" for line in lines)
        if mode == "malformed":
            data = b"not-json\n"
        elif mode == "oversized":
            data = b"x" * (2 * 1024 * 1024 + 1) + b"\n"
        stream = asyncio.StreamReader(limit=4 * 1024 * 1024)
        stream.feed_data(data)
        stream.feed_eof()
        written: list[bytes] = []

        class Input:
            def write(self, data: bytes) -> None:
                written.append(data)

            async def drain(self) -> None:
                pass

            def close(self) -> None:
                pass

        class Process:
            def __init__(self) -> None:
                self.stdin = None if mode == "pipes" else Input()
                self.stdout = stream
                self.returncode: int | None = None
                self.killed = False
                self.waited = 0

            async def wait(self) -> int:
                self.waited += 1
                self.returncode = 1 if mode == "exit" else 0
                return self.returncode

            def kill(self) -> None:
                self.killed = True

        process = Process()

        async def spawn(*args: object, **kwargs: object) -> Process:
            assert "StrictHostKeyChecking=yes" in args
            assert kwargs["limit"] == 2 * 1024 * 1024
            if mode == "windows":
                command = str(args[-1])
                script = base64.b64decode(command.rsplit(" ", 1)[1]).decode("utf-16-le")
                assert "--capture-request" in script
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        params = {
            "username": "operator",
            "private-key": "synthetic-key",
            "host-key": "host ssh-ed25519 synthetic",
        }
        envelope = {"payload": "signed-content", "signature": "signature"}
        destination = tmp_path / "artifact" if artifact else None
        if mode == "windows":
            assert await request_tool(TARGET, params, "windows", envelope) == {
                "state": "ready"
            }
        else:
            with pytest.raises(ValueError):
                await request_tool(TARGET, params, "linux", envelope, destination)
        assert process.waited >= 1
        assert process.killed is (mode not in {"windows", "exit"})
        if mode != "pipes":
            assert json.loads(written[0]) == envelope

    asyncio.run(scenario())
