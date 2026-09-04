"""Executable lifecycle for the private, agent-only mTLS service.

This process deliberately composes only the post-enrollment agent listener and
the PostgreSQL control-plane adapter. Enrollment and operator traffic require
different service entry points, credentials, and network policy.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import signal
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

from psycopg.conninfo import conninfo_to_dict

from northgate_rmm.errors import ValidationError
from northgate_rmm.listener import AgentListenerConfiguration, AgentTLSListener
from northgate_rmm.persistence import (
    DEFAULT_DATABASE_OPERATION_TIMEOUT_SECONDS,
    PostgresControlPlane,
)

MAX_SERVICE_CONFIGURATION_BYTES = 16_384
MAX_DATABASE_DSN_BYTES = 4_096
_REQUIRED_CONFIGURATION_FIELDS = frozenset(
    {
        "bind_address",
        "port",
        "authority",
        "server_certificate",
        "server_private_key",
        "endpoint_ca_certificate",
        "database_dsn_credential",
    }
)
_OPTIONAL_CONFIGURATION_FIELDS = frozenset(
    {"request_timeout_seconds", "database_operation_timeout_seconds"}
)


@dataclass(frozen=True, slots=True)
class AgentServiceConfiguration:
    """Validated non-secret service settings and secret-file reference."""

    listener: AgentListenerConfiguration
    database_dsn_credential: Path
    database_operation_timeout_seconds: float


def load_agent_service_configuration(path: Path) -> AgentServiceConfiguration:
    """Load one exact JSON configuration without following a final symlink."""

    encoded = _read_regular_file(
        path,
        label="agent service configuration",
        maximum_bytes=MAX_SERVICE_CONFIGURATION_BYTES,
        private=False,
    )
    try:
        value = json.loads(encoded, object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("agent service configuration is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValidationError("agent service configuration must be an object")
    fields = set(value)
    if not fields >= _REQUIRED_CONFIGURATION_FIELDS or not fields <= (
        _REQUIRED_CONFIGURATION_FIELDS | _OPTIONAL_CONFIGURATION_FIELDS
    ):
        raise ValidationError("agent service configuration fields are not exact")

    bind_address = _required_string(value, "bind_address")
    port = value["port"]
    if type(port) is not int or port == 0:
        raise ValidationError("agent service port must be a fixed integer")
    authority = _required_string(value, "authority")
    request_timeout = _bounded_number(
        value.get("request_timeout_seconds", 10.0),
        field="request_timeout_seconds",
        minimum=1.0,
        maximum=30.0,
    )
    database_timeout = _bounded_number(
        value.get(
            "database_operation_timeout_seconds",
            DEFAULT_DATABASE_OPERATION_TIMEOUT_SECONDS,
        ),
        field="database_operation_timeout_seconds",
        minimum=1.0,
        maximum=30.0,
    )
    listener = AgentListenerConfiguration(
        bind_address=bind_address,
        port=port,
        authority=authority,
        server_certificate=_absolute_path(value, "server_certificate"),
        server_private_key=_absolute_path(value, "server_private_key"),
        endpoint_ca_certificate=_absolute_path(value, "endpoint_ca_certificate"),
        request_timeout_seconds=request_timeout,
    )
    return AgentServiceConfiguration(
        listener=listener,
        database_dsn_credential=_absolute_path(value, "database_dsn_credential"),
        database_operation_timeout_seconds=database_timeout,
    )


def load_database_dsn(path: Path) -> str:
    """Read the PostgreSQL DSN from a bounded owner/root-only credential file."""

    encoded = _read_regular_file(
        path,
        label="database DSN credential",
        maximum_bytes=MAX_DATABASE_DSN_BYTES,
        private=True,
    )
    try:
        value = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError("database DSN credential is not UTF-8") from error
    if value != value.strip() or "\x00" in value or "\r" in value or "\n" in value:
        raise ValidationError("database DSN credential has an invalid format")
    try:
        parameters = conninfo_to_dict(value)
        hostname = parameters.get("host", "")
        database_name = parameters.get("dbname", "")
        port_value = parameters.get("port")
        if not isinstance(hostname, str) or not isinstance(database_name, str):
            raise ValueError("database target fields are invalid")
        if "," in hostname:
            raise ValueError("multiple database targets are not supported")
        if port_value is not None and not isinstance(port_value, str):
            raise ValueError("database port is invalid")
        raw_authority = value.removeprefix("postgresql://").split("/", 1)[0]
        raw_host_authority = raw_authority.split("@", 1)[-1]
        if raw_host_authority.endswith(":"):
            raise ValueError("database port is empty")
        if port_value is not None and not 1 <= int(port_value) <= 65_535:
            raise ValueError("database port is outside the supported range")
        raw_query = value.partition("?")[2]
        query_fields = {
            name.lower()
            for name, _field_value in parse_qsl(
                raw_query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        }
        address = ipaddress.ip_address(hostname)
    except ValueError as error:
        raise ValidationError(
            "database DSN credential has an invalid format"
        ) from error
    if (
        not value.startswith("postgresql://")
        or not database_name
        or query_fields & {"host", "hostaddr", "service"}
        or "hostaddr" in parameters
        or "service" in parameters
        or address.is_unspecified
        or not (address.is_private or address.is_loopback)
    ):
        raise ValidationError("database DSN credential has an invalid format")
    return value


async def run_agent_service(
    configuration: AgentServiceConfiguration,
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run the agent listener until SIGINT or SIGTERM, then close its sockets."""

    _require_unprivileged_process()
    dsn = load_database_dsn(configuration.database_dsn_credential)
    store = PostgresControlPlane(
        dsn,
        operation_timeout_seconds=configuration.database_operation_timeout_seconds,
    )
    store.verify_schema_state()
    listener = AgentTLSListener(configuration.listener, store)
    stopped = stop_event or asyncio.Event()
    loop = asyncio.get_running_loop()
    installed_signals: list[signal.Signals] = []
    if stop_event is None:
        for service_signal in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(service_signal, stopped.set)
                installed_signals.append(service_signal)
            except NotImplementedError:
                continue
    try:
        await listener.start()
        await stopped.wait()
    finally:
        store.begin_shutdown()
        try:
            await listener.close()
        finally:
            for service_signal in installed_signals:
                loop.remove_signal_handler(service_signal)


def main(argv: Sequence[str] | None = None) -> int:
    """Validate startup state and run the Debian agent-zone service."""

    parser = argparse.ArgumentParser(prog="northgate-rmm-agent-service")
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        _require_unprivileged_process()
        configuration = load_agent_service_configuration(arguments.config)
        asyncio.run(run_agent_service(configuration))
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("northgate-rmm agent service failed closed", file=sys.stderr)
        return 1
    return 0


def _require_unprivileged_process() -> None:
    if _effective_user_id() == 0:
        raise ValidationError("agent service refuses to run as root")


def _read_regular_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    private: bool,
) -> bytes:
    if not path.is_absolute():
        raise ValidationError(f"{label} path must be absolute")
    if path.is_symlink():
        raise ValidationError(f"{label} could not be opened safely")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise ValidationError(f"{label} is not a bounded regular file")
        if private and os.name == "posix":
            effective_user_id = _effective_user_id()
            if effective_user_id is None:
                raise ValidationError(f"{label} owner could not be verified")
            allowed_owners = {0, effective_user_id}
            if metadata.st_uid not in allowed_owners or metadata.st_mode & 0o077:
                raise ValidationError(f"{label} permissions are too broad")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        if (
            len(encoded) > maximum_bytes
            or final_metadata.st_size != metadata.st_size
            or len(encoded) != final_metadata.st_size
        ):
            raise ValidationError(f"{label} changed or exceeded its size limit")
        return encoded
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError(f"{label} could not be opened safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _effective_user_id() -> int | None:
    get_effective_user = getattr(os, "geteuid", None)
    if get_effective_user is None:
        return None
    value = get_effective_user()
    if type(value) is not int:
        raise RuntimeError("effective user ID has an invalid runtime type")
    return value


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("agent service configuration has a duplicate field")
        result[key] = value
    return result


def _required_string(value: dict[str, Any], field: str) -> str:
    candidate = value[field]
    if type(candidate) is not str or not candidate or not candidate.isprintable():
        raise ValidationError(f"agent service {field} is invalid")
    return candidate


def _absolute_path(value: dict[str, Any], field: str) -> Path:
    candidate = Path(_required_string(value, field))
    if not candidate.is_absolute():
        raise ValidationError(f"agent service {field} path must be absolute")
    return candidate


def _bounded_number(
    value: Any,
    *,
    field: str,
    minimum: float,
    maximum: float,
) -> float:
    if type(value) not in (int, float) or not minimum <= value <= maximum:
        raise ValidationError(f"agent service {field} is outside its allowed range")
    return float(value)


if __name__ == "__main__":  # pragma: no cover - package script is the entry point
    raise SystemExit(main())
