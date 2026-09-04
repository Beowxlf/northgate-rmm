"""Executable lifecycle for the private read-only operator service."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from northgate_rmm.agent_service import (
    MAX_SERVICE_CONFIGURATION_BYTES,
    _absolute_path,
    _bounded_number,
    _read_regular_file,
    _require_unprivileged_process,
    _required_string,
    load_database_dsn,
)
from northgate_rmm.errors import ValidationError
from northgate_rmm.operator_api import OperatorApplication, OperatorAuthorizationPolicy
from northgate_rmm.operator_listener import (
    OperatorListenerConfiguration,
    OperatorTLSListener,
)
from northgate_rmm.operator_verifier import (
    MTLSOperatorSessionVerifier,
    OperatorVerifierConfiguration,
)
from northgate_rmm.persistence import (
    DEFAULT_DATABASE_OPERATION_TIMEOUT_SECONDS,
    PostgresControlPlane,
)
from northgate_rmm.tls_identity import load_tls_identity_public_key

_REQUIRED_CONFIGURATION_FIELDS = frozenset(
    {
        "bind_address",
        "port",
        "authority",
        "server_certificate",
        "server_private_key",
        "database_dsn_credential",
        "verifier_connect_address",
        "verifier_port",
        "verifier_authority",
        "verifier_ca_certificate",
        "verifier_client_certificate",
        "verifier_client_private_key",
        "policy_issuer",
        "policy_tenant",
        "policy_subject",
        "policy_client_id",
    }
)
_OPTIONAL_CONFIGURATION_FIELDS = frozenset(
    {
        "policy_required_role",
        "policy_maximum_session_age_seconds",
        "request_timeout_seconds",
        "database_operation_timeout_seconds",
        "verifier_timeout_seconds",
    }
)


@dataclass(frozen=True, slots=True)
class OperatorServiceConfiguration:
    listener: OperatorListenerConfiguration
    database_dsn_credential: Path
    database_operation_timeout_seconds: float
    verifier: OperatorVerifierConfiguration
    policy: OperatorAuthorizationPolicy


def load_operator_service_configuration(path: Path) -> OperatorServiceConfiguration:
    """Load an exact bounded JSON configuration containing path references only."""

    encoded = _read_regular_file(
        path,
        label="operator service configuration",
        maximum_bytes=MAX_SERVICE_CONFIGURATION_BYTES,
        private=False,
    )
    try:
        value = json.loads(encoded, object_pairs_hook=_reject_operator_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(
            "operator service configuration is invalid JSON"
        ) from error
    if not isinstance(value, dict):
        raise ValidationError("operator service configuration must be an object")
    fields = set(value)
    if not fields >= _REQUIRED_CONFIGURATION_FIELDS or not fields <= (
        _REQUIRED_CONFIGURATION_FIELDS | _OPTIONAL_CONFIGURATION_FIELDS
    ):
        raise ValidationError("operator service configuration fields are not exact")

    port = value["port"]
    if type(port) is not int or port == 0:
        raise ValidationError("operator service port must be a fixed integer")
    listener = OperatorListenerConfiguration(
        bind_address=_required_string(value, "bind_address"),
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
    verifier_port = value["verifier_port"]
    if type(verifier_port) is not int:
        raise ValidationError("operator verifier_port must be an integer")
    verifier = OperatorVerifierConfiguration(
        connect_address=_required_string(value, "verifier_connect_address"),
        port=verifier_port,
        authority=_required_string(value, "verifier_authority"),
        ca_certificate=_absolute_path(value, "verifier_ca_certificate"),
        client_certificate=_absolute_path(value, "verifier_client_certificate"),
        client_private_key=_absolute_path(value, "verifier_client_private_key"),
        timeout_seconds=_bounded_number(
            value.get("verifier_timeout_seconds", 5.0),
            field="verifier_timeout_seconds",
            minimum=1.0,
            maximum=15.0,
        ),
    )
    policy = OperatorAuthorizationPolicy(
        issuer=_required_string(value, "policy_issuer"),
        tenant=_required_string(value, "policy_tenant"),
        subject=_required_string(value, "policy_subject"),
        client_id=_required_string(value, "policy_client_id"),
        required_role=_optional_string(value, "policy_required_role", "viewer"),
        maximum_session_age=timedelta(
            seconds=_bounded_number(
                value.get("policy_maximum_session_age_seconds", 43_200),
                field="policy_maximum_session_age_seconds",
                minimum=300,
                maximum=86_400,
            )
        ),
    )
    return OperatorServiceConfiguration(
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
        verifier=verifier,
        policy=policy,
    )


def _optional_string(value: dict[str, Any], field: str, default: str) -> str:
    candidate = value.get(field, default)
    if type(candidate) is not str or not candidate:
        raise ValidationError(f"operator service {field} must be a non-empty string")
    return candidate


def _reject_operator_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(
                "operator service configuration has a duplicate field"
            )
        result[key] = value
    return result


def _validate_distinct_tls_identities(
    configuration: OperatorServiceConfiguration,
) -> None:
    server_public_key = load_tls_identity_public_key(
        configuration.listener.server_certificate,
        label="operator server certificate",
    )
    verifier_public_key = load_tls_identity_public_key(
        configuration.verifier.client_certificate,
        label="operator verifier client certificate",
    )
    if server_public_key == verifier_public_key:
        raise ValidationError(
            "operator server and verifier client identities must be distinct"
        )


async def run_operator_service(
    configuration: OperatorServiceConfiguration,
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Verify dependencies before binding, then shut down fail-closed."""

    _require_unprivileged_process()
    _validate_distinct_tls_identities(configuration)
    store = PostgresControlPlane(
        load_database_dsn(configuration.database_dsn_credential),
        operation_timeout_seconds=configuration.database_operation_timeout_seconds,
    )
    store.verify_schema_state()
    operation = OperatorApplication(
        store,
        MTLSOperatorSessionVerifier(configuration.verifier),
        configuration.policy,
    )
    listener = OperatorTLSListener(configuration.listener, operation)
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
    parser = argparse.ArgumentParser(prog="northgate-rmm-operator-service")
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        _require_unprivileged_process()
        configuration = load_operator_service_configuration(arguments.config)
        asyncio.run(run_operator_service(configuration))
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("northgate-rmm operator service failed closed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
