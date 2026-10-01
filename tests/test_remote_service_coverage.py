"""Composition and callback authorization tests for the remote service entry point."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from aiohttp import web

import northgate_rmm.remote_service as remote_service
from northgate_rmm.operator_api import OperatorPrincipal


def test_rotation_requires_secret_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "remote",
            "--operator-config",
            "operator",
            "--targets",
            "targets",
            "--key",
            "key",
            "--origin",
            "https://operator.test",
            "--credential-rotation-config",
            "rotation",
        ],
    )
    with pytest.raises(SystemExit) as error:
        remote_service.main()
    assert error.value.code == 2


@pytest.mark.parametrize("mode", ["base", "all", "secrets", "bad-key"])
def test_remote_service_composes_only_configured_authorities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    endpoint, identity = uuid4(), uuid4()
    targets = tmp_path / "targets.json"
    targets.write_text(
        json.dumps(
            [
                dict(
                    endpoint_id=str(endpoint),
                    identity_id=str(identity),
                    address="10.2.3.4",
                    protocol="ssh",
                    port=22,
                    parameters={},
                )
            ]
        )
    )
    targets.chmod(0o600)
    key = tmp_path / "gateway.key"
    key.write_text(bytes(15 if mode == "bad-key" else 16).hex())
    key.chmod(0o600)
    listener = tmp_path / "listener.json"
    listener.write_text(
        json.dumps(
            dict(
                bind_address="127.0.0.1",
                port=8452,
                authority="worker.test",
                server_certificate="server.pem",
                server_private_key="key.pem",
                endpoint_ca_certificate="ca.pem",
            )
        )
    )
    listener.chmod(0o600)
    saved = tmp_path / "credentials.bin"
    saved.write_bytes(b"test-encrypted-fixture")
    saved.chmod(0o600)
    args = [
        "remote",
        "--operator-config",
        "operator",
        "--targets",
        str(targets),
        "--key",
        str(key),
        "--origin",
        "https://operator.test",
    ]
    if mode == "all":
        args += [
            "--credentials",
            str(saved),
            "--native-desktop-profiles",
            "profiles",
            "--management-listener-config",
            str(listener),
            "--operations-dsn-credential",
            "ops-dsn",
            "--integration-registry",
            "integrations",
            "--secrets-config",
            "secrets",
            "--credential-rotation-config",
            "rotation",
            "--service-runbooks",
            "runbooks",
        ]
    elif mode == "secrets":
        args += ["--secrets-config", "secrets"]
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.delenv("NORTHGATE_RMM_NATIVE_DESKTOP_PROFILES", raising=False)
    monkeypatch.delenv("NORTHGATE_RMM_INTEGRATION_REGISTRY", raising=False)
    config = MagicMock(database_dsn_credential=Path("dsn"))
    monkeypatch.setattr(remote_service, "_require_unprivileged_process", MagicMock())
    monkeypatch.setattr(
        remote_service,
        "load_operator_service_configuration",
        MagicMock(return_value=config),
    )
    monkeypatch.setattr(
        remote_service, "load_database_dsn", MagicMock(return_value="fixture-dsn")
    )
    app = web.Application()
    gateway = MagicMock()
    gateway.application.return_value = app
    gateway_factory = MagicMock(return_value=gateway)
    monkeypatch.setattr(remote_service, "RemoteGateway", gateway_factory)
    factories: dict[str, MagicMock] = {}
    for name in (
        "PostgresControlPlane",
        "MTLSOperatorSessionVerifier",
        "OperatorApplication",
        "RemoteWorkspace",
        "CaptureStore",
        "CaptureUI",
        "ManagementStore",
        "Management",
        "Fleet",
        "InspectionStore",
        "InspectionUI",
    ):
        factories[name] = MagicMock()
        monkeypatch.setattr(remote_service, name, factories[name])
    external: dict[str, MagicMock] = {}
    for module, name in (
        ("remote_sessions", "RemoteSessionStore"),
        ("capture_setup", "CaptureSetup"),
        ("native_desktop", "NativeDesktopProfiles"),
        ("operations", "Operations"),
        ("operations_store", "OperationsStore"),
        ("secrets_api", "SecretsAPI"),
        ("credential_rdp", "FreeRDPNLAVerifier"),
        ("credential_rotation", "CredentialRotationExecutor"),
        ("native_api", "NativeAPI"),
        ("tool_catalog", "ToolCatalog"),
        ("service_runbooks", "ServiceRunbooks"),
    ):
        external[name] = MagicMock()
        monkeypatch.setattr(f"northgate_rmm.{module}.{name}", external[name])
    monkeypatch.setattr(
        "northgate_rmm.listener.AgentListenerConfiguration", MagicMock()
    )
    monkeypatch.setattr(
        "northgate_rmm.listener.build_server_ssl_context",
        MagicMock(return_value="fixture-tls"),
    )
    monkeypatch.setattr(
        "northgate_rmm.credential_rotation.load_rotation_configuration",
        MagicMock(
            return_value=dict(
                executable=Path("xfreerdp"),
                executable_sha256="0" * 64,
                timeout_seconds=10,
            )
        ),
    )
    monkeypatch.setattr(
        remote_service,
        "open_credentials",
        MagicMock(return_value={endpoint: (identity, "fixture-user", "fixture-value")}),
    )
    run = MagicMock()
    monkeypatch.setattr(web, "run_app", run)
    if mode == "bad-key":
        with pytest.raises(ValueError, match="invalid remote configuration"):
            remote_service.main()
        gateway_factory.assert_not_called()
        run.assert_not_called()
        return
    remote_service.main()
    run.assert_called_once_with(
        app, host="127.0.0.1", port=8451, access_log=None, print=None
    )
    assert external["NativeAPI"].called is (mode == "all")
    assert external["CredentialRotationExecutor"].called is (mode == "all")
    assert external["SecretsAPI"].called is (mode != "base")
    for name in ("RemoteWorkspace", "CaptureUI", "Management", "Fleet", "InspectionUI"):
        factories[name].return_value.register.assert_called_once_with(app)
    catalog_callbacks = external["ToolCatalog"].call_args.kwargs
    runbook_callbacks = external["ServiceRunbooks"].call_args.kwargs
    principal = cast(OperatorPrincipal, MagicMock())
    entry = {"actions": ["ops.view", "case.manage", "evidence.manage"]}
    plan = {"case_id": "case-1", "endpoints": [str(endpoint)]}

    async def callbacks() -> None:
        if mode != "all":
            with pytest.raises(web.HTTPConflict):
                await catalog_callbacks["case_authorizer"](
                    principal, endpoint, "case-1"
                )
            with pytest.raises(ValueError, match="operations workspace"):
                await runbook_callbacks["evidence_sink"](entry, "case-1", "job-1")
            with pytest.raises(ValueError, match="operations workspace"):
                await runbook_callbacks["case_authorizer"](entry, plan)
            return
        ops = external["Operations"].return_value
        record = {"value": {"endpoints": [str(endpoint)], "status": "open"}}
        ops.authorized_record.return_value = record
        ops.native_call = AsyncMock(return_value={"record": record})
        await catalog_callbacks["case_authorizer"](principal, endpoint, "case-1")
        for job in ("job-1", {"id": "job-2"}):
            await catalog_callbacks["case_linker"](principal, endpoint, "case-1", job)
        assert ops.dispatch.call_count == 2
        note = ops.dispatch.call_args.args[2]
        assert "Completion must be verified" in note["text"]
        await runbook_callbacks["evidence_sink"](entry, "case-1", "job-1")
        ops.native_call.assert_awaited_with(
            entry,
            "pin_job",
            {
                "case": "case-1",
                "job": "job-1",
                "request_id": ops.native_call.call_args.args[2]["request_id"],
            },
        )
        await runbook_callbacks["case_authorizer"](entry, plan)
        with pytest.raises(web.HTTPForbidden):
            await runbook_callbacks["case_authorizer"]({"actions": []}, plan)
        record["value"]["endpoints"] = []
        with pytest.raises(web.HTTPForbidden):
            await catalog_callbacks["case_authorizer"](principal, endpoint, "case-1")
        with pytest.raises(web.HTTPForbidden):
            await runbook_callbacks["case_authorizer"](entry, plan)
        record["value"]["endpoints"] = [str(endpoint)]
        record["value"]["status"] = "closed"
        with pytest.raises(web.HTTPConflict):
            await catalog_callbacks["case_authorizer"](principal, endpoint, "case-1")
        with pytest.raises(web.HTTPConflict):
            await runbook_callbacks["case_authorizer"](entry, plan)
        runner = MagicMock(setup=AsyncMock(), cleanup=AsyncMock())
        site = MagicMock(start=AsyncMock())
        monkeypatch.setattr(web, "AppRunner", MagicMock(return_value=runner))
        monkeypatch.setattr(web, "TCPSite", MagicMock(return_value=site))
        lifecycle = app.cleanup_ctx[0](app)
        assert isinstance(lifecycle, AsyncGenerator)
        await anext(lifecycle)
        site.start.assert_awaited_once()
        await lifecycle.aclose()
        runner.cleanup.assert_awaited_once()
        site.start.side_effect = OSError("bind failed")
        failed = app.cleanup_ctx[0](app)
        assert isinstance(failed, AsyncGenerator)
        with pytest.raises(OSError, match="bind failed"):
            await anext(failed)
        assert runner.cleanup.await_count == 2

    asyncio.run(callbacks())
