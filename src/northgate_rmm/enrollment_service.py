"""Executable lifecycle for the private one-time enrollment service."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509

from northgate_rmm.agent_service import (
    MAX_SERVICE_CONFIGURATION_BYTES,
    _absolute_path,
    _bounded_number,
    _read_regular_file,
    _require_unprivileged_process,
    _required_string,
    load_database_dsn,
)
from northgate_rmm.enrollment import EnrollmentService
from northgate_rmm.enrollment_listener import (
    EnrollmentListenerConfiguration,
    EnrollmentTLSListener,
)
from northgate_rmm.errors import ValidationError
from northgate_rmm.issuer_client import IssuerClientConfiguration, MTLSIssuerClient
from northgate_rmm.persistence import (
    DEFAULT_DATABASE_OPERATION_TIMEOUT_SECONDS,
    PostgresControlPlane,
)

MAX_TRUST_ROOT_BYTES = 65_536
_REQUIRED_CONFIGURATION_FIELDS = frozenset(
    {
        "bind_address",
        "port",
        "authority",
        "server_certificate",
        "server_private_key",
        "database_dsn_credential",
        "issuer_connect_address",
        "issuer_port",
        "issuer_authority",
        "issuer_ca_certificate",
        "issuer_client_certificate",
        "issuer_client_private_key",
        "endpoint_issuer_trust_root",
    }
)
_OPTIONAL_CONFIGURATION_FIELDS = frozenset(
    {
        "request_timeout_seconds",
        "database_operation_timeout_seconds",
        "issuer_timeout_seconds",
    }
)


@dataclass(frozen=True, slots=True)
class EnrollmentServiceConfiguration:
    listener: EnrollmentListenerConfiguration
    database_dsn_credential: Path
    database_operation_timeout_seconds: float
    issuer: IssuerClientConfiguration
    endpoint_issuer_trust_root: Path


def load_enrollment_service_configuration(
    path: Path,
) -> EnrollmentServiceConfiguration:
    """Load an exact bounded JSON configuration containing path references only."""

    encoded = _read_regular_file(
        path,
        label="enrollment service configuration",
        maximum_bytes=MAX_SERVICE_CONFIGURATION_BYTES,
        private=False,
    )
    try:
        value = json.loads(encoded, object_pairs_hook=_reject_enrollment_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(
            "enrollment service configuration is invalid JSON"
        ) from error
    if not isinstance(value, dict):
        raise ValidationError("enrollment service configuration must be an object")
    fields = set(value)
    if not fields >= _REQUIRED_CONFIGURATION_FIELDS or not fields <= (
        _REQUIRED_CONFIGURATION_FIELDS | _OPTIONAL_CONFIGURATION_FIELDS
    ):
        raise ValidationError("enrollment service configuration fields are not exact")

    bind_address = _required_string(value, "bind_address")
    port = value["port"]
    if type(port) is not int or port == 0:
        raise ValidationError("enrollment service port must be a fixed integer")
    listener = EnrollmentListenerConfiguration(
        bind_address=bind_address,
        port=port,
        authority=_required_string(value, "authority"),
        server_certificate=_absolute_path(value, "server_certificate"),
        server_private_key=_absolute_path(value, "server_private_key"),
        request_timeout_seconds=_bounded_number(
            value.get("request_timeout_seconds", 10.0),
            field="request_timeout_seconds",
            minimum=1.0,
            maximum=30.0,
        ),
    )
    issuer_port = value["issuer_port"]
    if type(issuer_port) is not int:
        raise ValidationError("enrollment service issuer_port must be an integer")
    issuer = IssuerClientConfiguration(
        connect_address=_required_string(value, "issuer_connect_address"),
        port=issuer_port,
        authority=_required_string(value, "issuer_authority"),
        ca_certificate=_absolute_path(value, "issuer_ca_certificate"),
        client_certificate=_absolute_path(value, "issuer_client_certificate"),
        client_private_key=_absolute_path(value, "issuer_client_private_key"),
        timeout_seconds=_bounded_number(
            value.get("issuer_timeout_seconds", 10.0),
            field="issuer_timeout_seconds",
            minimum=1.0,
            maximum=30.0,
        ),
    )
    return EnrollmentServiceConfiguration(
        listener=listener,
        database_dsn_credential=_absolute_path(value, "database_dsn_credential"),
        database_operation_timeout_seconds=_bounded_number(
            value.get(
                "database_operation_timeout_seconds",
                DEFAULT_DATABASE_OPERATION_TIMEOUT_SECONDS,
            ),
            field="database_operation_timeout_seconds",
            minimum=1.0,
            maximum=30.0,
        ),
        issuer=issuer,
        endpoint_issuer_trust_root=_absolute_path(value, "endpoint_issuer_trust_root"),
    )


def load_endpoint_issuer_trust_root(path: Path) -> x509.Certificate:
    """Load exactly one bounded public CA certificate used for chain validation."""

    encoded = _read_regular_file(
        path,
        label="endpoint issuer trust root",
        maximum_bytes=MAX_TRUST_ROOT_BYTES,
        private=False,
    )
    try:
        certificates = x509.load_pem_x509_certificates(encoded)
    except ValueError as error:
        raise ValidationError("endpoint issuer trust root is invalid") from error
    if len(certificates) != 1:
        raise ValidationError("exactly one endpoint issuer trust root is required")
    certificate = certificates[0]
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound as error:
        raise ValidationError("endpoint issuer trust root is not a CA") from error
    if not constraints.ca:
        raise ValidationError("endpoint issuer trust root is not a CA")
    try:
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as error:
        raise ValidationError(
            "endpoint issuer trust root cannot sign certificates"
        ) from error
    if not key_usage.key_cert_sign or certificate.subject != certificate.issuer:
        raise ValidationError("endpoint issuer trust root cannot sign certificates")
    return certificate


def _reject_enrollment_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(
                "enrollment service configuration has a duplicate field"
            )
        result[key] = value
    return result


async def run_enrollment_service(
    configuration: EnrollmentServiceConfiguration,
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Verify dependencies before binding, then shut down fail-closed."""

    _require_unprivileged_process()
    store = PostgresControlPlane(
        load_database_dsn(configuration.database_dsn_credential),
        operation_timeout_seconds=configuration.database_operation_timeout_seconds,
    )
    store.verify_schema_state()
    operation = EnrollmentService(
        store,
        MTLSIssuerClient(configuration.issuer),
        issuer_trust_roots=(
            load_endpoint_issuer_trust_root(configuration.endpoint_issuer_trust_root),
        ),
    )
    listener = EnrollmentTLSListener(configuration.listener, operation)
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
    parser = argparse.ArgumentParser(prog="northgate-rmm-enrollment-service")
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        _require_unprivileged_process()
        configuration = load_enrollment_service_configuration(arguments.config)
        asyncio.run(run_enrollment_service(configuration))
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("northgate-rmm enrollment service failed closed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
