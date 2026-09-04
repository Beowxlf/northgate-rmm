"""Bounded mTLS client for the separately operated endpoint certificate issuer."""

from __future__ import annotations

import base64
import binascii
import http.client
import ipaddress
import json
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from northgate_rmm.enrollment import (
    EndpointIssuanceRequest,
    IssuedEndpointCredential,
)
from northgate_rmm.errors import (
    AuthorizationError,
    ServiceUnavailableError,
    ValidationError,
)

ISSUER_PATH = "/v1/endpoint-certificates"
MAX_ISSUER_RESPONSE_BYTES = 65_536
_ALLOWED_ISSUER_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "::1/128",
    )
)
_DNS_AUTHORITY = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


@dataclass(frozen=True, slots=True)
class IssuerClientConfiguration:
    """Fixed issuer route and the enrollment workload's mTLS identity."""

    connect_address: str
    port: int
    authority: str
    ca_certificate: Path
    client_certificate: Path
    client_private_key: Path
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.connect_address)
        except ValueError as error:
            raise ValidationError("issuer address must be an IP literal") from error
        if not any(address in network for network in _ALLOWED_ISSUER_NETWORKS):
            raise ValidationError("issuer address is outside allowed private networks")
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise ValidationError("issuer port is outside the supported range")
        if _DNS_AUTHORITY.fullmatch(self.authority) is None:
            raise ValidationError("issuer TLS authority is invalid")
        if type(self.timeout_seconds) not in (int, float) or not (
            1.0 <= self.timeout_seconds <= 30.0
        ):
            raise ValidationError("issuer timeout is outside the supported range")
        for path in (
            self.ca_certificate,
            self.client_certificate,
            self.client_private_key,
        ):
            if not path.is_absolute():
                raise ValidationError("issuer TLS paths must be absolute")


class MTLSIssuerClient:
    """Issue public endpoint credentials without possessing issuer key material."""

    def __init__(self, configuration: IssuerClientConfiguration) -> None:
        self._configuration = configuration
        self._context = _build_client_context(configuration)

    def issue_endpoint_certificate(
        self,
        request: EndpointIssuanceRequest,
        *,
        now: datetime,
    ) -> IssuedEndpointCredential:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValidationError("issuer request time must be timezone-aware")
        body = json.dumps(
            {
                "identity_id": str(request.identity_id),
                "endpoint_id": str(request.endpoint_id),
                "public_key_fingerprint": request.public_key_fingerprint,
                "csr": base64.b64encode(request.csr_der).decode("ascii"),
                "requested_at": now.astimezone(UTC).isoformat(),
            },
            separators=(",", ":"),
        ).encode("ascii")
        connection = _PinnedHTTPSConnection(
            self._configuration,
            context=self._context,
        )
        try:
            connection.request(
                "POST",
                ISSUER_PATH,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Accept": "application/json",
                    "Host": self._configuration.authority,
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            content_length = response.getheader("Content-Length")
            if content_length is not None and (
                not content_length.isascii()
                or not content_length.isdigit()
                or int(content_length) > MAX_ISSUER_RESPONSE_BYTES
            ):
                raise ValidationError("issuer response length is invalid")
            encoded = response.read(MAX_ISSUER_RESPONSE_BYTES + 1)
            if len(encoded) > MAX_ISSUER_RESPONSE_BYTES or response.read(1):
                raise ValidationError("issuer response is too large")
            if response.status in {401, 403}:
                raise AuthorizationError("issuer rejected workload identity")
            if response.status in {408, 425, 429} or 500 <= response.status <= 599:
                raise ServiceUnavailableError("issuer is unavailable")
            if response.status != 201:
                raise ValidationError("issuer response status is invalid")
            if response.getheader("Content-Type") != "application/json":
                raise ValidationError("issuer response type is invalid")
            if response.getheader("Content-Encoding") is not None:
                raise ValidationError("issuer response encoding is not allowed")
            return _decode_issuer_response(encoded)
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            raise ServiceUnavailableError("issuer request failed") from error
        finally:
            connection.close()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        configuration: IssuerClientConfiguration,
        *,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            configuration.authority,
            port=configuration.port,
            timeout=float(configuration.timeout_seconds),
            context=context,
        )
        self._connect_address = configuration.connect_address
        self._ssl_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._connect_address, self.port),
            self.timeout,
        )
        try:
            self.sock = self._ssl_context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except BaseException:
            raw_socket.close()
            raise


def _build_client_context(configuration: IssuerClientConfiguration) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.options |= ssl.OP_NO_TICKET
    context.load_verify_locations(cafile=str(configuration.ca_certificate))
    context.load_cert_chain(
        certfile=str(configuration.client_certificate),
        keyfile=str(configuration.client_private_key),
    )
    return context


def _decode_issuer_response(encoded: bytes) -> IssuedEndpointCredential:
    try:
        value = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("issuer response is invalid JSON") from error
    if not isinstance(value, dict) or set(value) != {
        "leaf_certificate",
        "intermediate_certificates",
    }:
        raise ValidationError("issuer response fields are not exact")
    body = cast(dict[str, Any], value)
    leaf = _decode_certificate(body["leaf_certificate"])
    intermediates_value = body["intermediate_certificates"]
    if not isinstance(intermediates_value, list) or len(intermediates_value) > 4:
        raise ValidationError("issuer response chain is invalid")
    intermediates = tuple(_decode_certificate(item) for item in intermediates_value)
    return IssuedEndpointCredential(
        leaf_certificate_der=leaf,
        intermediate_certificates_der=intermediates,
    )


def _decode_certificate(value: object) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= 24_000:
        raise ValidationError("issuer certificate encoding is invalid")
    try:
        encoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValidationError("issuer certificate encoding is invalid") from error
    if not 1 <= len(encoded) <= 16_384:
        raise ValidationError("issuer certificate size is invalid")
    return encoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("issuer response contains a duplicate field")
        result[key] = value
    return result


def _reject_json_constant(_raw: str) -> None:
    raise ValidationError("issuer response contains a non-finite value")
