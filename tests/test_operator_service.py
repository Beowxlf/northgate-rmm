from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization

from northgate_rmm.errors import ValidationError
from northgate_rmm.operator_service import (
    _validate_distinct_tls_identities,
    load_operator_service_configuration,
    main,
    run_operator_service,
)
from tests.support.pki import issue_test_endpoint_credential


def _configuration(tmp_path: Path) -> dict[str, object]:
    return {
        "bind_address": "127.0.0.1",
        "port": 8443,
        "authority": "operator.test",
        "server_certificate": str(tmp_path / "server.crt"),
        "server_private_key": str(tmp_path / "server.key"),
        "database_dsn_credential": str(tmp_path / "database-dsn"),
        "verifier_connect_address": "127.0.0.1",
        "verifier_port": 9444,
        "verifier_authority": "idp.test",
        "verifier_ca_certificate": str(tmp_path / "idp-ca.crt"),
        "verifier_client_certificate": str(tmp_path / "verifier-client.crt"),
        "verifier_client_private_key": str(tmp_path / "verifier-client.key"),
        "policy_issuer": "https://idp.test/issuer",
        "policy_tenant": "northgate-test",
        "policy_subject": "operator-001",
        "policy_client_id": "northgate-rmm-test",
    }


def test_operator_service_configuration_composes_separate_boundaries(
    tmp_path: Path,
) -> None:
    path = tmp_path / "operator.json"
    path.write_text(json.dumps(_configuration(tmp_path)), encoding="utf-8")

    configuration = load_operator_service_configuration(path)

    assert configuration.listener.port == 8443
    assert configuration.verifier.port == 9444
    assert configuration.policy.subject == "operator-001"
    assert configuration.policy.required_role == "viewer"
    assert configuration.database_operation_timeout_seconds == 8.0


@pytest.mark.parametrize("change", ["extra", "missing", "zero_port", "bad_role"])
def test_operator_service_configuration_rejects_inexact_values(
    tmp_path: Path,
    change: str,
) -> None:
    value = _configuration(tmp_path)
    if change == "extra":
        value["unexpected"] = True
    elif change == "missing":
        del value["policy_subject"]
    elif change == "zero_port":
        value["port"] = 0
    else:
        value["policy_required_role"] = 7
    path = tmp_path / "operator.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValidationError):
        load_operator_service_configuration(path)


@pytest.mark.parametrize(
    "encoded",
    [b"not-json", b"[]", b'{"bind_address":"127.0.0.1","bind_address":"x"}'],
)
def test_operator_service_configuration_rejects_invalid_documents(
    tmp_path: Path,
    encoded: bytes,
) -> None:
    path = tmp_path / "operator.json"
    path.write_bytes(encoded)

    with pytest.raises(ValidationError):
        load_operator_service_configuration(path)


def test_operator_service_rejects_equivalent_tls_identity_copies(
    tmp_path: Path,
) -> None:
    material = issue_test_endpoint_credential(
        UUID("11111111-1111-4111-8111-111111111111"),
        now=datetime.now(UTC),
    )
    encoded = material.endpoint_certificate.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "server.crt").write_bytes(encoded)
    (tmp_path / "verifier-client.crt").write_bytes(encoded)
    config_path = tmp_path / "operator.json"
    config_path.write_text(json.dumps(_configuration(tmp_path)), encoding="utf-8")
    configuration = load_operator_service_configuration(config_path)

    with pytest.raises(ValidationError, match="identities must be distinct"):
        _validate_distinct_tls_identities(configuration)


def test_operator_service_verifies_dependencies_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import northgate_rmm.operator_service as service_module

    events: list[str] = []
    config_path = tmp_path / "operator.json"
    config_path.write_text(json.dumps(_configuration(tmp_path)), encoding="utf-8")
    configuration = load_operator_service_configuration(config_path)

    class FakeStore:
        def __init__(self, dsn: str, *, operation_timeout_seconds: float) -> None:
            assert dsn == "validated-dsn"
            assert operation_timeout_seconds == 8.0

        def verify_schema_state(self) -> tuple[str, ...]:
            events.append("schema")
            return ("migration",)

        def begin_shutdown(self) -> None:
            events.append("database_shutdown")

    class FakeVerifier:
        def __init__(self, _configuration: object) -> None:
            events.append("verifier")

    class FakeOperation:
        def __init__(self, *_values: object) -> None:
            events.append("operation")

    class FakeListener:
        def __init__(self, _configuration: object, _operation: object) -> None:
            events.append("listener")

        async def start(self) -> None:
            events.append("start")

        async def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(service_module, "_require_unprivileged_process", lambda: None)
    monkeypatch.setattr(
        service_module,
        "_validate_distinct_tls_identities",
        lambda _configuration: events.append("identity_separation"),
    )
    monkeypatch.setattr(
        service_module,
        "load_database_dsn",
        lambda _path: "validated-dsn",
    )
    monkeypatch.setattr(service_module, "PostgresControlPlane", FakeStore)
    monkeypatch.setattr(service_module, "MTLSOperatorSessionVerifier", FakeVerifier)
    monkeypatch.setattr(service_module, "OperatorApplication", FakeOperation)
    monkeypatch.setattr(service_module, "OperatorTLSListener", FakeListener)

    async def exercise() -> None:
        stopped = asyncio.Event()
        stopped.set()
        await run_operator_service(configuration, stop_event=stopped)

    asyncio.run(exercise())

    assert events == [
        "identity_separation",
        "schema",
        "verifier",
        "operation",
        "listener",
        "start",
        "database_shutdown",
        "close",
    ]


def test_operator_service_entrypoint_is_generic_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import northgate_rmm.operator_service as service_module

    monkeypatch.setattr(service_module, "_require_unprivileged_process", lambda: None)
    monkeypatch.setattr(
        service_module,
        "load_operator_service_configuration",
        lambda _path: object(),
    )

    async def fake_run(_configuration: object) -> None:
        return None

    monkeypatch.setattr(service_module, "run_operator_service", fake_run)
    assert main(["--config", str(tmp_path / "config.json")]) == 0

    def fail() -> None:
        raise ValidationError("private internal detail")

    monkeypatch.setattr(service_module, "_require_unprivileged_process", fail)
    assert main(["--config", str(tmp_path / "config.json")]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "northgate-rmm operator service failed closed\n"
    assert "private internal detail" not in captured.err


def test_operator_service_entrypoint_preserves_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import northgate_rmm.operator_service as service_module

    def interrupt() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(service_module, "_require_unprivileged_process", interrupt)
    assert main(["--config", str(tmp_path / "config.json")]) == 130


def test_operator_systemd_unit_is_unprivileged_and_credential_bounded() -> None:
    unit = (
        Path(__file__).parents[1]
        / "deploy"
        / "systemd"
        / "northgate-rmm-operator.service"
    ).read_text(encoding="utf-8")

    assert "User=northgate-rmm-operator" in unit
    assert "Group=northgate-rmm-operator" in unit
    assert "User=root" not in unit
    assert "NoNewPrivileges=yes" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "AmbientCapabilities=\n" in unit
    assert "LoadCredential=database-dsn:" in unit
    assert "LoadCredential=verifier-client-cert:" in unit
    assert "LoadCredential=verifier-client-key:" in unit
    assert (
        "ExecStart=/opt/northgate-rmm/venv/bin/northgate-rmm-operator-service "
        "--config /etc/northgate-rmm/operator-service.json"
    ) in unit
    assert "northgate-rmm-agent" not in unit
    assert "northgate-rmm-enrollment-service" not in unit
