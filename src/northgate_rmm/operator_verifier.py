"""Bounded mTLS client for current external operator-session verification."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from northgate_rmm.domain import require_aware
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.operator_api import (
    MAX_AUTHORIZATION_HEADER_BYTES,
    OperatorPrincipal,
)
from northgate_rmm.private_https import (
    PinnedHTTPSConnection,
    build_mtls_client_context,
    http_authority,
)

OPERATOR_SESSION_VERIFIER_PATH = "/v1/operator-sessions/verify"
MAX_OPERATOR_SESSION_RESPONSE_BYTES = 16_384
_ALLOWED_VERIFIER_NETWORKS = tuple(
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
_BEARER_AUTHORIZATION = re.compile(r"Bearer [A-Za-z0-9\-._~+/]+={0,}\Z")
_RESPONSE_FIELDS = frozenset(
    {
        "issuer",
        "tenant",
        "subject",
        "session_id",
        "client_id",
        "roles",
        "authenticated_at",
        "expires_at",
        "mfa",
    }
)


@dataclass(frozen=True, slots=True)
class OperatorVerifierConfiguration:
    """Fixed verifier route and the operator service's mTLS workload identity."""

    connect_address: str
    port: int
    authority: str
    ca_certificate: Path
    client_certificate: Path
    client_private_key: Path
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.connect_address)
        except ValueError as error:
            raise ValidationError(
                "operator verifier address must be an IP literal"
            ) from error
        if not any(address in network for network in _ALLOWED_VERIFIER_NETWORKS):
            raise ValidationError(
                "operator verifier address is outside allowed private networks"
            )
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise ValidationError(
                "operator verifier port is outside the supported range"
            )
        if _DNS_AUTHORITY.fullmatch(self.authority) is None:
            raise ValidationError("operator verifier TLS authority is invalid")
        if type(self.timeout_seconds) not in (int, float) or not (
            1.0 <= self.timeout_seconds <= 15.0
        ):
            raise ValidationError(
                "operator verifier timeout is outside the supported range"
            )
        if any(
            not path.is_absolute()
            for path in (
                self.ca_certificate,
                self.client_certificate,
                self.client_private_key,
            )
        ):
            raise ValidationError("operator verifier TLS paths must be absolute")


class MTLSOperatorSessionVerifier:
    """Revalidate one opaque human session without caching positive state."""

    def __init__(self, configuration: OperatorVerifierConfiguration) -> None:
        self._configuration = configuration
        self._context = _build_verifier_context(configuration)

    def verify(self, authorization: str, *, now: datetime) -> OperatorPrincipal:
        require_aware(now, "now")
        if (
            type(authorization) is not str
            or not 1 <= len(authorization) <= MAX_AUTHORIZATION_HEADER_BYTES
            or _BEARER_AUTHORIZATION.fullmatch(authorization) is None
        ):
            raise AuthorizationError("operator session verification failed")
        connection = _PinnedOperatorHTTPSConnection(
            self._configuration,
            context=self._context,
        )
        try:
            connection.request(
                "POST",
                OPERATOR_SESSION_VERIFIER_PATH,
                body=b"",
                headers={
                    "Authorization": authorization,
                    "Content-Length": "0",
                    "Accept": "application/json",
                    "Host": http_authority(
                        self._configuration.authority,
                        self._configuration.port,
                    ),
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            content_length = response.getheader("Content-Length")
            if (
                content_length is None
                or not content_length.isascii()
                or not content_length.isdigit()
                or len(content_length) > len(str(MAX_OPERATOR_SESSION_RESPONSE_BYTES))
                or int(content_length) > MAX_OPERATOR_SESSION_RESPONSE_BYTES
                or response.getheader("Transfer-Encoding") is not None
                or response.getheader("Content-Encoding") is not None
            ):
                raise AuthorizationError("operator session verification failed")
            declared_length = int(content_length)
            encoded = response.read(declared_length + 1)
            if len(encoded) != declared_length or response.read(1):
                raise AuthorizationError("operator session verification failed")
            if response.status in {401, 403}:
                raise AuthorizationError("operator session was rejected")
            if response.status != 200:
                raise AuthorizationError("operator session verification failed")
            if response.getheader("Content-Type") != "application/json":
                raise AuthorizationError("operator session verification failed")
            try:
                return _decode_operator_principal(encoded)
            except ValidationError as error:
                raise AuthorizationError(
                    "operator session verification failed"
                ) from error
        except AuthorizationError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            raise AuthorizationError("operator session verification failed") from error
        finally:
            connection.close()


class _PinnedOperatorHTTPSConnection:
    def __init__(
        self,
        configuration: OperatorVerifierConfiguration,
        *,
        context: ssl.SSLContext,
    ) -> None:
        self._connection = PinnedHTTPSConnection(
            connect_address=configuration.connect_address,
            port=configuration.port,
            authority=configuration.authority,
            timeout_seconds=float(configuration.timeout_seconds),
            context=context,
        )

    def request(self, *args: Any, **kwargs: Any) -> None:
        self._connection.request(*args, **kwargs)

    def getresponse(self) -> http.client.HTTPResponse:
        return self._connection.getresponse()

    def close(self) -> None:
        self._connection.close()


def _build_verifier_context(
    configuration: OperatorVerifierConfiguration,
) -> ssl.SSLContext:
    return build_mtls_client_context(
        ca_certificate=configuration.ca_certificate,
        client_certificate=configuration.client_certificate,
        client_private_key=configuration.client_private_key,
        ca_label="operator verifier CA certificate",
        certificate_label="operator verifier client certificate",
        private_key_label="operator verifier client private key",
    )


def _decode_operator_principal(encoded: bytes) -> OperatorPrincipal:
    try:
        value = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError("operator verifier response is invalid JSON") from error
    if not isinstance(value, dict) or set(value) != _RESPONSE_FIELDS:
        raise ValidationError("operator verifier response fields are not exact")
    body = cast(dict[str, Any], value)
    roles = body["roles"]
    if not isinstance(roles, list):
        raise ValidationError("operator verifier roles are invalid")
    return OperatorPrincipal(
        issuer=body["issuer"],
        tenant=body["tenant"],
        subject=body["subject"],
        session_id=body["session_id"],
        client_id=body["client_id"],
        roles=tuple(roles),
        authenticated_at=_parse_canonical_utc(body["authenticated_at"]),
        expires_at=_parse_canonical_utc(body["expires_at"]),
        mfa=body["mfa"],
    )


def _parse_canonical_utc(value: object) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 64:
        raise ValidationError("operator verifier time is invalid")
    try:
        parsed = datetime.fromisoformat(value)
        require_aware(parsed, "operator verifier time")
        normalized = parsed.astimezone(UTC)
    except (OverflowError, TypeError, ValueError) as error:
        raise ValidationError("operator verifier time is invalid") from error
    if normalized.isoformat() != value:
        raise ValidationError("operator verifier time is not canonical UTC")
    return normalized


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("operator verifier response has a duplicate field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValidationError(f"operator verifier response constant {value!r} is invalid")
