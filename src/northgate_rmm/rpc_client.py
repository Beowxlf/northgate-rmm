"""Fixed private mTLS RPC helper for operational services."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from northgate_rmm.errors import ValidationError
from northgate_rmm.private_https import (
    PinnedHTTPSConnection,
    build_mtls_client_context,
    http_authority,
)
from northgate_rmm.workload_service import canonical, strict_object


def call(
    configuration: dict[str, Any], path: str, value: dict[str, Any]
) -> dict[str, Any]:
    address = ipaddress.ip_address(configuration["connect_address"])
    if not any(
        address in ipaddress.ip_network(network)
        for network in (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "fc00::/7",
            "::1/128",
        )
    ):
        raise ValidationError("RPC target must be private")
    context = build_mtls_client_context(
        ca_certificate=Path(configuration["ca_certificate"]),
        client_certificate=Path(configuration["client_certificate"]),
        client_private_key=Path(configuration["client_private_key"]),
        ca_label="RPC root",
        certificate_label="RPC workload certificate",
        private_key_label="RPC workload key",
    )
    connection = PinnedHTTPSConnection(
        connect_address=str(address),
        port=configuration["port"],
        authority=configuration["authority"],
        timeout_seconds=5,
        context=context,
    )
    try:
        connection.request(
            "POST",
            path,
            body=canonical(value),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Host": http_authority(
                    configuration["authority"], configuration["port"]
                ),
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Encoding")
            or response.getheader("Content-Type") != "application/json"
        ):
            raise ValidationError("RPC response unavailable")
        return strict_object(response.read(65537))
    finally:
        connection.close()
