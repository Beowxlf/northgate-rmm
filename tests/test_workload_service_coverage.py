"""Bounded workload HTTP ingress and service startup fail closed."""

from __future__ import annotations

import asyncio
import hashlib
import signal
import ssl
from contextlib import nullcontext
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import web
from multidict import CIMultiDict

import northgate_rmm.workload_service as workload_service
from northgate_rmm.errors import ValidationError


def configuration() -> dict[str, Any]:
    return {
        "bind_address": "127.0.0.1",
        "port": 9443,
        "authority": "workload.example.test",
        "allowed_client_sha256": [hashlib.sha256(b"synthetic-peer").hexdigest()],
        "client_ca_certificate": "synthetic-ca",
        "server_certificate": "synthetic-certificate",
        "server_private_key": "synthetic-key",
    }


def test_workload_ingress_authorization_and_response_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        context = Mock()
        context.options = 0
        monkeypatch.setattr(ssl, "SSLContext", Mock(return_value=context))
        monkeypatch.setattr(
            workload_service,
            "regular_file_reference",
            lambda path, **kw: nullcontext(path),
        )
        monkeypatch.setattr(
            workload_service,
            "private_key_reference",
            lambda path, **kw: nullcontext(path),
        )
        monkeypatch.setattr(
            workload_service, "_require_unprivileged_process", lambda: None
        )
        applications: list[web.Application] = []
        runner = Mock(setup=AsyncMock(), cleanup=AsyncMock())

        def make_runner(application: web.Application, **kwargs: object) -> Mock:
            applications.append(application)
            assert kwargs["handler_cancellation"] is True
            return runner

        monkeypatch.setattr(workload_service, "_HardenedAppRunner", make_runner)
        loop = asyncio.get_running_loop()
        signals: dict[int, Any] = {}
        monkeypatch.setattr(
            loop,
            "add_signal_handler",
            lambda sig, callback: signals.__setitem__(sig, callback),
        )
        removed: list[int] = []
        monkeypatch.setattr(
            loop, "remove_signal_handler", lambda sig: removed.append(sig)
        )

        async def start() -> None:
            signals[signal.SIGTERM]()

        monkeypatch.setattr(
            workload_service,
            "_BoundedTLSSite",
            Mock(return_value=Mock(start=AsyncMock(side_effect=start))),
        )
        operation = Mock(return_value=(200, {"accepted": True}))
        await workload_service.serve(configuration(), operation, frozenset({"/verify"}))
        assert context.minimum_version is ssl.TLSVersion.TLSv1_3
        assert context.maximum_version is ssl.TLSVersion.TLSv1_3
        assert context.verify_mode == ssl.CERT_REQUIRED
        runner.cleanup.assert_awaited_once()
        assert removed == [signal.SIGTERM, signal.SIGINT]
        handler = next(iter(applications[0].router.routes())).handler

        def request() -> Mock:
            peer = Mock()
            peer.getpeercert.return_value = b"synthetic-peer"
            transport = Mock()
            transport.get_extra_info.return_value = peer
            return Mock(
                method="POST",
                path="/verify",
                query_string="",
                headers=CIMultiDict(
                    {
                        "Host": "workload.example.test",
                        "Content-Type": "application/json",
                    }
                ),
                transport=transport,
                read=AsyncMock(return_value=b"{}"),
            )

        good = request()
        response = await handler(good)
        assert isinstance(response, web.Response) and response.status == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.keep_alive is False
        operation.assert_called_once_with("/verify", b"{}", None)
        for field, value in [
            ("method", "GET"),
            ("path", "/other"),
            ("query_string", "unexpected=1"),
            ("transport", None),
        ]:
            bad = request()
            setattr(bad, field, value)
            response = await handler(bad)
            assert response.status == 403
        for name, value in [
            ("Host", "other.test"),
            ("Content-Type", "text/plain"),
            ("Content-Encoding", "gzip"),
            ("Transfer-Encoding", "chunked"),
            ("Authorization", "x" * 4097),
        ]:
            bad = request()
            bad.headers[name] = value
            assert (await handler(bad)).status == 403
        duplicate = request()
        duplicate.headers.add("Authorization", "first")
        duplicate.headers.add("Authorization", "second")
        assert (await handler(duplicate)).status == 403
        wrong_peer = request()
        wrong_peer.transport.get_extra_info.return_value.getpeercert.return_value = (
            b"unknown"
        )
        assert (await handler(wrong_peer)).status == 403
        operation.assert_called_once()
        operation.return_value = (200, {"oversized": "x" * 65536})
        assert (await handler(request())).status == 503
        operation.side_effect = ValueError("private diagnostic")
        failed = await handler(request())
        assert isinstance(failed, web.Response)
        assert failed.status == 403 and failed.body == b'{"error":"request_rejected"}'

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "field,value",
    [
        ("bind_address", "8.8.8.8"),
        ("port", True),
        ("port", 443),
        ("allowed_client_sha256", []),
        ("allowed_client_sha256", ["bad"]),
        ("allowed_client_sha256", ["A" * 64]),
    ],
)
def test_workload_rejects_unsafe_listener_configuration(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    monkeypatch.setattr(workload_service, "_require_unprivileged_process", lambda: None)
    config = configuration()
    config[field] = value
    with pytest.raises(ValidationError):
        asyncio.run(workload_service.serve(config, Mock(), frozenset({"/verify"})))


def test_workload_cli_startup_failure_and_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "config.json"
    path.write_text("{}")
    monkeypatch.setattr(workload_service, "_require_unprivileged_process", lambda: None)
    operation = Mock()
    factory = Mock(return_value=(operation, frozenset({"/verify"})))
    serve = AsyncMock()
    monkeypatch.setattr(workload_service, "serve", serve)
    assert workload_service.service_main(factory, ["--config", str(path)]) == 0
    serve.assert_awaited_once_with({}, operation, frozenset({"/verify"}))
    factory.side_effect = ValidationError("private configuration")
    assert workload_service.service_main(factory, ["--config", str(path)]) == 1
    assert "private configuration" not in capsys.readouterr().err
