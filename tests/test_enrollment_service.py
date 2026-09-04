from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes, serialization

from northgate_rmm.enrollment_service import (
    _validate_distinct_tls_identities,
    load_endpoint_issuer_trust_root,
    load_enrollment_service_configuration,
    main,
    run_enrollment_service,
)
from northgate_rmm.errors import ValidationError
from tests.support.pki import issue_test_endpoint_credential


def _configuration(tmp_path: Path) -> dict[str, object]:
    return {
        "bind_address": "127.0.0.1",
        "port": 8444,
        "authority": "enroll.test",
        "server_certificate": str(tmp_path / "server.crt"),
        "server_private_key": str(tmp_path / "server.key"),
        "database_dsn_credential": str(tmp_path / "database-dsn"),
        "issuer_connect_address": "127.0.0.1",
        "issuer_port": 9443,
        "issuer_authority": "issuer.test",
        "issuer_ca_certificate": str(tmp_path / "issuer-ca.crt"),
        "issuer_client_certificate": str(tmp_path / "issuer-client.crt"),
        "issuer_client_private_key": str(tmp_path / "issuer-client.key"),
        "endpoint_issuer_trust_root": str(tmp_path / "endpoint-root.crt"),
    }


def test_enrollment_service_configuration_composes_separate_boundaries(
    tmp_path: Path,
) -> None:
    path = tmp_path / "enrollment.json"
    path.write_text(json.dumps(_configuration(tmp_path)), encoding="utf-8")

    configuration = load_enrollment_service_configuration(path)

    assert configuration.listener.port == 8444
    assert configuration.issuer.port == 9443
    assert (
        configuration.listener.server_private_key
        != configuration.issuer.client_private_key
    )
    assert configuration.database_operation_timeout_seconds == 8.0


def test_enrollment_service_rejects_equivalent_tls_identity_copies(
    tmp_path: Path,
) -> None:
    material = issue_test_endpoint_credential(
        UUID("11111111-1111-4111-8111-111111111111"),
        now=datetime.now(UTC),
    )
    encoded = material.endpoint_certificate.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "server.crt").write_bytes(encoded)
    (tmp_path / "issuer-client.crt").write_bytes(encoded)
    config_path = tmp_path / "enrollment.json"
    config_path.write_text(json.dumps(_configuration(tmp_path)), encoding="utf-8")
    configuration = load_enrollment_service_configuration(config_path)

    with pytest.raises(ValidationError, match="identities must be distinct"):
        _validate_distinct_tls_identities(configuration)


@pytest.mark.parametrize("change", ["extra", "missing", "zero_port"])
def test_enrollment_service_configuration_rejects_inexact_values(
    tmp_path: Path,
    change: str,
) -> None:
    value = _configuration(tmp_path)
    if change == "extra":
        value["unexpected"] = True
    elif change == "missing":
        del value["issuer_authority"]
    else:
        value["port"] = 0
    path = tmp_path / "enrollment.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValidationError):
        load_enrollment_service_configuration(path)


@pytest.mark.parametrize(
    "encoded",
    [b"not-json", b"[]", b'{"bind_address":"127.0.0.1","bind_address":"x"}'],
)
def test_enrollment_service_configuration_rejects_invalid_documents(
    tmp_path: Path, encoded: bytes
) -> None:
    path = tmp_path / "enrollment.json"
    path.write_bytes(encoded)

    with pytest.raises(ValidationError):
        load_enrollment_service_configuration(path)


def test_enrollment_service_configuration_rejects_non_integer_issuer_port(
    tmp_path: Path,
) -> None:
    value = _configuration(tmp_path)
    value["issuer_port"] = True
    path = tmp_path / "enrollment.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValidationError, match="issuer_port"):
        load_enrollment_service_configuration(path)


def test_endpoint_issuer_trust_root_requires_exactly_one_ca(tmp_path: Path) -> None:
    material = issue_test_endpoint_credential(
        UUID("11111111-1111-4111-8111-111111111111"),
        now=datetime.now(UTC),
    )
    path = tmp_path / "root.pem"
    path.write_bytes(material.root_certificate.public_bytes(serialization.Encoding.PEM))

    loaded = load_endpoint_issuer_trust_root(path)

    assert loaded.fingerprint(hashes.SHA256()) == (
        material.root_certificate.fingerprint(hashes.SHA256())
    )


def test_endpoint_issuer_trust_root_rejects_invalid_bundle_and_leaf(
    tmp_path: Path,
) -> None:
    material = issue_test_endpoint_credential(
        UUID("11111111-1111-4111-8111-111111111111"),
        now=datetime.now(UTC),
    )
    path = tmp_path / "root.pem"
    path.write_bytes(b"not-a-certificate")
    with pytest.raises(ValidationError, match="invalid"):
        load_endpoint_issuer_trust_root(path)

    root = material.root_certificate.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(root + root)
    with pytest.raises(ValidationError, match="exactly one"):
        load_endpoint_issuer_trust_root(path)

    path.write_bytes(
        material.endpoint_certificate.public_bytes(serialization.Encoding.PEM)
    )
    with pytest.raises(ValidationError, match="not a CA"):
        load_endpoint_issuer_trust_root(path)


def test_enrollment_service_verifies_dependencies_and_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import northgate_rmm.enrollment_service as service_module

    events: list[str] = []
    config_path = tmp_path / "enrollment.json"
    config_path.write_text(json.dumps(_configuration(tmp_path)), encoding="utf-8")
    configuration = load_enrollment_service_configuration(config_path)
    material = issue_test_endpoint_credential(
        UUID("11111111-1111-4111-8111-111111111111"),
        now=datetime.now(UTC),
    )

    class FakeStore:
        def __init__(self, dsn: str, *, operation_timeout_seconds: float) -> None:
            assert dsn == "validated-dsn"
            assert operation_timeout_seconds == 8.0

        def verify_schema_state(self) -> tuple[str, ...]:
            events.append("schema")
            return ("migration",)

        def begin_shutdown(self) -> None:
            events.append("database_shutdown")

    class FakeIssuer:
        def __init__(self, _configuration: object) -> None:
            events.append("issuer")

    class FakeOperation:
        def __init__(self, _store: object, _issuer: object, **_values: object) -> None:
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
        service_module, "load_database_dsn", lambda _path: "validated-dsn"
    )
    monkeypatch.setattr(service_module, "PostgresControlPlane", FakeStore)
    monkeypatch.setattr(service_module, "MTLSIssuerClient", FakeIssuer)
    monkeypatch.setattr(service_module, "EnrollmentService", FakeOperation)
    monkeypatch.setattr(service_module, "EnrollmentTLSListener", FakeListener)
    monkeypatch.setattr(
        service_module,
        "load_endpoint_issuer_trust_root",
        lambda _path: material.root_certificate,
    )

    async def exercise() -> None:
        stopped = asyncio.Event()
        stopped.set()
        await run_enrollment_service(configuration, stop_event=stopped)

    asyncio.run(exercise())

    assert events == [
        "identity_separation",
        "schema",
        "issuer",
        "operation",
        "listener",
        "start",
        "database_shutdown",
        "close",
    ]


def test_enrollment_service_entrypoint_is_generic_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import northgate_rmm.enrollment_service as service_module

    monkeypatch.setattr(service_module, "_require_unprivileged_process", lambda: None)
    monkeypatch.setattr(
        service_module,
        "load_enrollment_service_configuration",
        lambda _path: object(),
    )

    async def fake_run(_configuration: object) -> None:
        return None

    monkeypatch.setattr(service_module, "run_enrollment_service", fake_run)
    assert main(["--config", str(tmp_path / "config.json")]) == 0

    def fail() -> None:
        raise ValidationError("secret internal detail")

    monkeypatch.setattr(service_module, "_require_unprivileged_process", fail)
    assert main(["--config", str(tmp_path / "config.json")]) == 1
    captured = capsys.readouterr()
    assert "failed closed" in captured.err
    assert "secret internal detail" not in captured.err


def test_enrollment_service_entrypoint_preserves_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import northgate_rmm.enrollment_service as service_module

    def interrupt() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(service_module, "_require_unprivileged_process", interrupt)
    assert main(["--config", str(tmp_path / "config.json")]) == 130
