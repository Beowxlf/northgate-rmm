from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from northgate_rmm.enrollment import EndpointIssuanceRequest
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.issuer_client import (
    IssuerClientConfiguration,
    MTLSIssuerClient,
    _decode_issuer_response,
)

NOW = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)


def configuration(tmp_path: Path, **changes: object) -> IssuerClientConfiguration:
    values: dict[str, object] = {
        "connect_address": "10.40.0.10",
        "port": 9443,
        "authority": "issuer.northgate.internal",
        "ca_certificate": tmp_path / "issuer-ca.crt",
        "client_certificate": tmp_path / "enrollment-client.crt",
        "client_private_key": tmp_path / "enrollment-client.key",
        "timeout_seconds": 8.0,
    }
    values.update(changes)
    return IssuerClientConfiguration(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("change", "value", "match"),
    [
        ("connect_address", "issuer.internal", "IP literal"),
        ("connect_address", "8.8.8.8", "private networks"),
        ("connect_address", "192.0.2.1", "private networks"),
        ("port", 0, "port"),
        ("port", True, "port"),
        ("authority", "Issuer.Internal", "authority"),
        ("authority", "issuer", "authority"),
        ("timeout_seconds", 31, "timeout"),
        ("client_private_key", Path("relative.key"), "paths"),
    ],
)
def test_issuer_configuration_rejects_ambiguous_routes(
    tmp_path: Path,
    change: str,
    value: object,
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        configuration(tmp_path, **{change: value})


def test_issuer_client_sends_exact_request_and_bounds_public_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import northgate_rmm.issuer_client as issuer_module

    leaf = b"leaf-certificate"
    intermediate = b"intermediate-certificate"
    response_body = json.dumps(
        {
            "leaf_certificate": base64.b64encode(leaf).decode("ascii"),
            "intermediate_certificates": [
                base64.b64encode(intermediate).decode("ascii")
            ],
        },
        separators=(",", ":"),
    ).encode("ascii")
    observed: dict[str, object] = {}

    class FakeResponse:
        status = 201

        def __init__(self) -> None:
            self._read = False

        def getheader(self, name: str) -> str | None:
            return {
                "Content-Length": str(len(response_body)),
                "Content-Type": "application/json",
            }.get(name)

        def read(self, _amount: int) -> bytes:
            if self._read:
                return b""
            self._read = True
            return response_body

    class FakeConnection:
        def __init__(self, config: object, *, context: object) -> None:
            observed["configuration"] = config
            observed["context"] = context

        def request(
            self,
            method: str,
            path: str,
            *,
            body: bytes,
            headers: dict[str, str],
        ) -> None:
            observed.update(
                method=method,
                path=path,
                body=body,
                headers=headers,
            )

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            observed["closed"] = True

    synthetic_context = object()
    monkeypatch.setattr(
        issuer_module, "_build_client_context", lambda _value: synthetic_context
    )
    monkeypatch.setattr(issuer_module, "_PinnedHTTPSConnection", FakeConnection)
    config = configuration(tmp_path)
    client = MTLSIssuerClient(config)
    request = EndpointIssuanceRequest(
        identity_id=UUID("11111111-1111-4111-8111-111111111111"),
        endpoint_id=UUID("22222222-2222-4222-8222-222222222222"),
        public_key_fingerprint="sha256:" + "a" * 64,
        csr_der=b"canonical-csr",
    )

    credential = client.issue_endpoint_certificate(request, now=NOW)

    assert credential.leaf_certificate_der == leaf
    assert credential.intermediate_certificates_der == (intermediate,)
    assert observed["method"] == "POST"
    assert observed["path"] == "/v1/endpoint-certificates"
    assert observed["context"] is synthetic_context
    assert observed["closed"] is True
    sent = json.loads(observed["body"])  # type: ignore[arg-type]
    assert sent == {
        "identity_id": str(request.identity_id),
        "endpoint_id": str(request.endpoint_id),
        "public_key_fingerprint": request.public_key_fingerprint,
        "csr": base64.b64encode(request.csr_der).decode("ascii"),
        "requested_at": NOW.isoformat(),
    }


def test_issuer_client_maps_workload_rejection_generically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import northgate_rmm.issuer_client as issuer_module

    class RejectedResponse:
        status = 403

        def getheader(self, name: str) -> str | None:
            return "0" if name == "Content-Length" else None

        def read(self, _amount: int) -> bytes:
            return b""

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            pass

        def getresponse(self) -> RejectedResponse:
            return RejectedResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(issuer_module, "_build_client_context", lambda _value: object())
    monkeypatch.setattr(issuer_module, "_PinnedHTTPSConnection", FakeConnection)
    client = MTLSIssuerClient(configuration(tmp_path))
    request = EndpointIssuanceRequest(
        identity_id=UUID("11111111-1111-4111-8111-111111111111"),
        endpoint_id=UUID("22222222-2222-4222-8222-222222222222"),
        public_key_fingerprint="sha256:" + "a" * 64,
        csr_der=b"csr",
    )

    with pytest.raises(AuthorizationError, match="workload identity"):
        client.issue_endpoint_certificate(request, now=NOW)


@pytest.mark.parametrize(
    "value",
    [
        b"{}",
        b'{"leaf_certificate":"eA==","leaf_certificate":"eQ==",'
        b'"intermediate_certificates":[]}',
        b'{"leaf_certificate":"***","intermediate_certificates":[]}',
        b'{"leaf_certificate":"eA==","intermediate_certificates":{},"extra":1}',
    ],
)
def test_issuer_response_requires_exact_bounded_certificate_fields(
    value: bytes,
) -> None:
    with pytest.raises(ValidationError):
        _decode_issuer_response(value)
