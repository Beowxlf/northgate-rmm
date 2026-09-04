from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from northgate_rmm.agent_service import (
    AgentServiceConfiguration,
    load_agent_service_configuration,
    load_database_dsn,
    run_agent_service,
)
from northgate_rmm.errors import ValidationError
from northgate_rmm.persistence import PostgresControlPlane


def configuration_value(tmp_path: Path) -> dict[str, object]:
    return {
        "bind_address": "127.0.0.1",
        "port": 8443,
        "authority": "agents.test:8443",
        "server_certificate": str(tmp_path / "server.crt"),
        "server_private_key": str(tmp_path / "server.key"),
        "endpoint_ca_certificate": str(tmp_path / "endpoint-ca.crt"),
        "database_dsn_credential": str(tmp_path / "database-dsn"),
        "request_timeout_seconds": 7,
        "database_operation_timeout_seconds": 6,
    }


def write_configuration(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "agent-service.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_load_agent_service_configuration_is_exact_and_contains_no_secret(
    tmp_path: Path,
) -> None:
    path = write_configuration(tmp_path, configuration_value(tmp_path))

    configuration = load_agent_service_configuration(path)

    assert configuration.listener.bind_address == "127.0.0.1"
    assert configuration.listener.port == 8443
    assert configuration.listener.authority == "agents.test:8443"
    assert configuration.listener.request_timeout_seconds == 7.0
    assert configuration.database_operation_timeout_seconds == 6.0
    assert configuration.database_dsn_credential == tmp_path / "database-dsn"


@pytest.mark.parametrize(
    "change",
    [
        {"unexpected": True},
        {"port": 0},
        {"port": True},
        {"bind_address": "0.0.0.0"},  # noqa: S104 - expected rejection case
        {"database_dsn_credential": "relative"},
        {"request_timeout_seconds": "slow"},
    ],
)
def test_agent_service_configuration_rejects_unsafe_values(
    tmp_path: Path, change: dict[str, object]
) -> None:
    value = configuration_value(tmp_path)
    value.update(change)

    with pytest.raises(ValidationError):
        load_agent_service_configuration(write_configuration(tmp_path, value))


def test_agent_service_configuration_rejects_duplicate_fields(tmp_path: Path) -> None:
    path = tmp_path / "agent-service.json"
    path.write_text('{"bind_address":"127.0.0.1","bind_address":"127.0.0.2"}')

    with pytest.raises(ValidationError, match="duplicate"):
        load_agent_service_configuration(path)


def test_agent_service_configuration_rejects_symlink(tmp_path: Path) -> None:
    target = write_configuration(tmp_path, configuration_value(tmp_path))
    link = tmp_path / "linked-config.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("test account cannot create symlinks")

    with pytest.raises(ValidationError, match="opened safely"):
        load_agent_service_configuration(link)


def test_agent_service_configuration_rejects_fifo_without_blocking(
    tmp_path: Path,
) -> None:
    mkfifo = getattr(os, "mkfifo", None)
    if mkfifo is None:
        pytest.skip("POSIX FIFO contract")
    path = tmp_path / "agent-service.fifo"
    mkfifo(path)

    with pytest.raises(ValidationError, match="bounded regular file"):
        load_agent_service_configuration(path)


def test_database_dsn_is_loaded_without_entering_configuration(tmp_path: Path) -> None:
    dsn = "postgresql://service:synthetic@database.test/northgate"
    path = tmp_path / "database-dsn"
    path.write_text(dsn, encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o600)

    assert load_database_dsn(path) == dsn


@pytest.mark.parametrize(
    "value",
    [
        "postgres://database.test/northgate",
        " postgresql://database.test/northgate",
        "postgresql://database.test/northgate\n",
        "postgresql://database.test/northgate\x00tail",
    ],
)
def test_database_dsn_rejects_ambiguous_format(tmp_path: Path, value: str) -> None:
    path = tmp_path / "database-dsn"
    path.write_bytes(value.encode("utf-8"))
    if os.name == "posix":
        path.chmod(0o600)

    with pytest.raises(ValidationError, match="invalid format"):
        load_database_dsn(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission contract")
def test_database_dsn_rejects_group_or_world_access(tmp_path: Path) -> None:
    path = tmp_path / "database-dsn"
    path.write_text("postgresql://database.test/northgate", encoding="utf-8")
    path.chmod(0o640)

    with pytest.raises(ValidationError, match="permissions"):
        load_database_dsn(path)


def test_configuration_requires_real_runtime_types(tmp_path: Path) -> None:
    value = configuration_value(tmp_path)
    value["authority"] = cast(str, 123)

    with pytest.raises(ValidationError, match="authority"):
        load_agent_service_configuration(write_configuration(tmp_path, value))


def test_agent_service_verifies_schema_and_closes_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import northgate_rmm.agent_service as service_module

    events: list[str] = []

    class FakeStore:
        def __init__(self, dsn: str, *, operation_timeout_seconds: float) -> None:
            assert dsn == "postgresql://database.test/northgate"
            assert operation_timeout_seconds == 6.0

        def verify_schema_state(self) -> tuple[str, ...]:
            events.append("schema")
            return ("0001_test.sql",)

        def begin_shutdown(self) -> None:
            events.append("database_shutdown")

    class FakeListener:
        def __init__(self, _listener: object, _store: object) -> None:
            events.append("construct")

        async def start(self) -> None:
            events.append("start")

        async def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(service_module, "PostgresControlPlane", FakeStore)
    monkeypatch.setattr(service_module, "AgentTLSListener", FakeListener)
    dsn_path = tmp_path / "database-dsn"
    dsn_path.write_text("postgresql://database.test/northgate", encoding="utf-8")
    if os.name == "posix":
        dsn_path.chmod(0o600)
    runtime_user_id = dsn_path.stat().st_uid if os.name == "posix" else 1_000
    monkeypatch.setattr(
        service_module,
        "_effective_user_id",
        lambda: runtime_user_id,
    )
    loaded = load_agent_service_configuration(
        write_configuration(tmp_path, configuration_value(tmp_path))
    )
    configuration = AgentServiceConfiguration(
        listener=loaded.listener,
        database_dsn_credential=dsn_path,
        database_operation_timeout_seconds=6.0,
    )

    async def exercise() -> None:
        stopped = asyncio.Event()
        stopped.set()
        await run_agent_service(configuration, stop_event=stopped)

    asyncio.run(exercise())

    assert events == ["schema", "construct", "start", "database_shutdown", "close"]


def test_database_shutdown_cancels_active_connection_and_rejects_new_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import northgate_rmm.persistence as persistence_module

    class FakeConnection:
        def __init__(self) -> None:
            self.cancel_timeout: float | None = None
            self.closed = False

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *args: object) -> None:
            del args

        def cancel_safe(self, *, timeout: float) -> None:
            self.cancel_timeout = timeout

        def close(self) -> None:
            self.closed = True

    connection = FakeConnection()

    def connect_fake(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        return connection

    monkeypatch.setattr(persistence_module, "connect", connect_fake)
    store = PostgresControlPlane("postgresql://database.test/northgate")
    context = store._connect()
    context.__enter__()

    store.begin_shutdown()

    assert connection.cancel_timeout == 1.0
    assert connection.closed is True
    context.__exit__(None, None, None)
    with pytest.raises(ValidationError, match="shutting down"), store._connect():
        pass


def test_agent_service_refuses_root_before_reading_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import northgate_rmm.agent_service as service_module

    monkeypatch.setattr(service_module, "_effective_user_id", lambda: 0)
    configuration = load_agent_service_configuration(
        write_configuration(tmp_path, configuration_value(tmp_path))
    )

    with pytest.raises(ValidationError, match="refuses to run as root"):
        asyncio.run(run_agent_service(configuration))
