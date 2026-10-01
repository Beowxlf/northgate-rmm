"""Native transport boundaries and MCP forwarding remain explicit and testable."""

from __future__ import annotations

import asyncio
import io
import json
import ssl
import sys
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import northgate_rmm.native_client as native_client
import northgate_rmm.rmm_mcp as rmm_mcp
from northgate_rmm.native_client import NativeClient


def client_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> NativeClient:
    token = tmp_path / "token"
    token.write_text("A" * 43)
    token.chmod(0o600)
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            dict(
                origin="https://operator.test", token_file=str(token), ca_file="ca.pem"
            )
        )
    )
    config.chmod(0o600)
    context = MagicMock()
    monkeypatch.setattr(ssl, "create_default_context", MagicMock(return_value=context))
    client = NativeClient(config)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    return client


@pytest.mark.parametrize(
    "failure",
    [
        "",
        "large-response",
        "content-type",
        "array-response",
        "http-error",
        "large-request",
    ],
)
def test_native_client_bounds_and_verifies_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    client = client_fixture(monkeypatch, tmp_path)
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"accepted":true}'
    response.headers.get_content_type.return_value = "application/json"
    opener = MagicMock()
    opener.open.return_value = response
    monkeypatch.setattr("urllib.request.build_opener", MagicMock(return_value=opener))
    if failure == "large-response":
        response.read.return_value = b"x" * (8 * 1024 * 1024 + 1)
    elif failure == "content-type":
        response.headers.get_content_type.return_value = "text/html"
    elif failure == "array-response":
        response.read.return_value = b"[]"
    elif failure == "http-error":
        opener.open.side_effect = urllib.error.HTTPError(
            client.url, 403, "forbidden", Message(), io.BytesIO(b"denied")
        )
    if failure:
        error = RuntimeError if failure == "http-error" else ValueError
        with pytest.raises(error):
            client.call(
                "describe",
                payload="x" * (2 * 1024 * 1024) if failure == "large-request" else "",
            )
        if failure == "large-request":
            opener.open.assert_not_called()
    else:
        assert client.call("describe") == {"accepted": True}
        request = opener.open.call_args.args[0]
        assert request.full_url == "https://operator.test/native/v1/rpc"
        assert request.get_header("Authorization") == "Bearer " + "A" * 43
        assert json.loads(request.data) == {"operation": "describe", "arguments": {}}
        response.read.assert_called_once_with(8 * 1024 * 1024 + 1)


def test_native_cli_prints_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = MagicMock()
    client.call.return_value = {"devices": []}
    factory = MagicMock(return_value=client)
    monkeypatch.setattr(native_client, "NativeClient", factory)
    monkeypatch.setattr(
        sys,
        "argv",
        ["native", "--config", "config.json", "devices", "--arguments", '{"limit":2}'],
    )
    native_client.main()
    factory.assert_called_once_with(Path("config.json"))
    client.call.assert_called_once_with("devices", limit=2)
    assert json.loads(capsys.readouterr().out) == {"devices": []}


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, operation: str, **arguments: object) -> dict[str, object]:
        self.calls.append((operation, arguments))
        return {"operation": operation, "arguments": arguments}


def test_mcp_tools_forward_typed_arguments_and_flags() -> None:
    client = RecordingClient()
    server = rmm_mcp.build_server(client)
    cases: list[tuple[str, str, dict[str, object]]] = [
        ("describe", "describe", {}),
        ("list_devices", "devices", {}),
        ("get_device", "device", {"endpoint": "ep"}),
        ("list_jobs", "jobs", {"endpoint": "ep"}),
        ("get_job", "job", {"endpoint": "ep", "job": "job"}),
        ("get_inventory", "inventory", {"endpoint": "ep"}),
        ("operations_state", "ops.state", {}),
        ("operations_record", "ops.record", {"kind": "case", "id": "case"}),
        (
            "save_operations_record",
            "ops.save",
            {
                "kind": "case",
                "id": "case",
                "revision": 1,
                "value": {},
                "request_id": "request",
            },
        ),
        (
            "add_case_note",
            "ops.note",
            {"id": "case", "text": "note", "request_id": "request"},
        ),
        (
            "update_case_task",
            "ops.case_task",
            {"id": "case", "revision": 1, "task": {}, "request_id": "request"},
        ),
        (
            "transition_case",
            "ops.case_transition",
            {
                "id": "case",
                "revision": 1,
                "status": "closed",
                "outcome": "fixed",
                "verification": "verified",
                "request_id": "request",
                "disposition": "benign",
            },
        ),
        (
            "retain_job_evidence",
            "ops.pin_job",
            {"case": "case", "job": "job", "request_id": "request"},
        ),
        ("tool_catalog", "tool_catalog", {"endpoint": "ep"}),
        (
            "install_tool",
            "install_tool",
            {
                "endpoint": "ep",
                "tool_id": "health",
                "version": "1",
                "request_id": "request",
            },
        ),
        (
            "collect_inventory",
            "collect_inventory",
            {"endpoint": "ep", "category": "health"},
        ),
        (
            "submit_job",
            "submit_job",
            {
                "endpoint": "ep",
                "action": "capabilities",
                "params": {},
                "request_id": "request",
            },
        ),
        ("cancel_job", "cancel_job", {"endpoint": "ep", "job": "job"}),
        ("terminal_io", "terminal_io", {"endpoint": "ep", "job": "job"}),
        (
            "terminal_io",
            "terminal_io",
            {"endpoint": "ep", "job": "job", "text": "whoami\n", "sequence": 1},
        ),
        (
            "install_release",
            "install_release",
            {"endpoint": "ep", "component": "agent", "request_id": "request"},
        ),
        ("setup_capture", "capture_setup", {"endpoint": "ep", "request_id": "request"}),
        ("capture_history", "capture_history", {"endpoint": "ep"}),
        ("capture_capabilities", "capture_capabilities", {"endpoint": "ep"}),
        (
            "start_capture",
            "capture_start",
            {"endpoint": "ep", "interface": 1, "request_id": "request"},
        ),
        ("capture_status", "capture_status", {"endpoint": "ep", "job": "job"}),
        ("stop_capture", "capture_stop", {"endpoint": "ep", "job": "job"}),
    ]

    async def exercise() -> None:
        tools = {tool.name: tool for tool in await server.list_tools()}
        assert set(tools) == {name for name, _, _ in cases}
        assert tools["list_devices"].annotations is not None
        assert tools["list_devices"].annotations.readOnlyHint is True
        assert tools["submit_job"].annotations is not None
        assert tools["submit_job"].annotations.destructiveHint is True
        for name, operation, args in cases:
            await server.call_tool(name, args)
            actual, forwarded = client.calls[-1]
            assert actual == operation
            for key, value in args.items():
                assert forwarded[key] == value
        terminal_calls = [
            args for operation, args in client.calls if operation == "terminal_io"
        ]
        assert "text" not in terminal_calls[0]
        assert terminal_calls[1]["text"] == "whoami\n"
        transition = next(
            args
            for operation, args in client.calls
            if operation == "ops.case_transition"
        )
        assert transition["disposition"] == "benign"
        assert "containment_status" not in transition

    asyncio.run(exercise())


def test_mcp_cli_starts_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    client, server = MagicMock(), MagicMock()
    factory = MagicMock(return_value=client)
    build = MagicMock(return_value=server)
    monkeypatch.setattr(rmm_mcp, "NativeClient", factory)
    monkeypatch.setattr(rmm_mcp, "build_server", build)
    monkeypatch.setattr(sys, "argv", ["mcp", "--config", "config.json"])
    rmm_mcp.main()
    factory.assert_called_once_with(Path("config.json"))
    build.assert_called_once_with(client)
    server.run.assert_called_once_with(transport="stdio")
