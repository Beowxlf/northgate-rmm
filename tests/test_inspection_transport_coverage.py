"""Inspection SSH transport uses pinned, fixed commands and bounded output."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from northgate_rmm.inspection import LIMIT, run_inspection, validate_result
from tests.test_inspection import result
from tests.test_remote_access import TARGET


@pytest.mark.parametrize(
    "platform,mode",
    [
        ("linux", "ok"),
        ("windows", "ok"),
        ("linux", "oversized"),
        ("linux", "exit"),
        ("linux", "malformed"),
        ("linux", "pipes"),
    ],
)
def test_inspection_transport_success_and_failure_cleanup(
    monkeypatch: pytest.MonkeyPatch, platform: str, mode: str
) -> None:
    async def scenario() -> None:
        expected = result()
        expected["platform"] = platform
        output = json.dumps(expected).encode()
        if mode == "oversized":
            output = b"x" * (LIMIT + 1)
        elif mode == "malformed":
            output = b"not-json"
        stream = asyncio.StreamReader()
        stream.feed_data(output)
        stream.feed_eof()

        class Process:
            def __init__(self) -> None:
                self.stdout = None if mode == "pipes" else stream
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
        calls: list[tuple[object, ...]] = []

        async def spawn(*args: object, **kwargs: object) -> Process:
            calls.append(args)
            assert "StrictHostKeyChecking=yes" in args
            assert "BatchMode=yes" in args
            assert "HostKeyAlgorithms=ssh-ed25519" in args
            key_index = args.index("-i") + 1
            key = Path(str(args[key_index]))
            assert key.stat().st_mode & 0o777 == 0o600
            assert key.read_text() == "synthetic-key"
            command = str(args[-1])
            if platform == "windows":
                encoded = command.rsplit(" ", 1)[1]
                decoded = base64.b64decode(encoded).decode("utf-16-le")
                assert "--inspect services" in decoded
                assert "$LASTEXITCODE" in decoded
            else:
                assert (
                    command == "/usr/libexec/northgate-rmm/"
                    "northgate-rmm-agent --inspect services"
                )
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        parameters = {
            "username": "operator",
            "private-key": "synthetic-key",
            "host-key": "10.2.3.4 ssh-ed25519 synthetic",
        }
        if mode == "ok":
            assert (
                await run_inspection(TARGET, parameters, platform, "services")
                == expected
            )
            assert not process.killed
        else:
            with pytest.raises(ValueError):
                await run_inspection(TARGET, parameters, platform, "services")
            assert process.killed is (mode in {"oversized", "pipes"})
        assert process.waited >= 1
        assert len(calls) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "field,value",
    [
        ("platform", "other"),
        ("category", "shell"),
        ("username", "user;id"),
        ("private-key", ""),
        ("host-key", "host"),
        ("host-key", "host ssh-bad key"),
        ("host-key", "host ssh-ed25519 key\nextra"),
    ],
)
def test_inspection_transport_rejects_invalid_configuration_before_spawn(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str
) -> None:
    parameters = {
        "username": "operator",
        "private-key": "synthetic-key",
        "host-key": "10.2.3.4 ssh-ed25519 synthetic",
    }
    platform, category = "linux", "services"
    if field == "platform":
        platform = value
    elif field == "category":
        category = value
    else:
        parameters[field] = value
    spawn = AsyncMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(ValueError):
        asyncio.run(run_inspection(TARGET, parameters, platform, category))
    spawn.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", 2),
        ("category", "other"),
        ("status", "unknown"),
        ("collected_at", "2026-01-01T00:00:00"),
        ("error", "x" * 1025),
        ("duration_ms", "12"),
        ("exit_code", False),
    ],
)
def test_inspection_response_rejects_untrusted_metadata(
    field: str, value: object
) -> None:
    payload: dict[str, object] = dict(result())
    payload[field] = value
    with pytest.raises(ValueError):
        validate_result(payload, "services")
