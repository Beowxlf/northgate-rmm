from __future__ import annotations

import json
import os
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.operator_verifier import (
    MTLSOperatorSessionVerifier,
    OperatorVerifierConfiguration,
    _decode_operator_principal,
)

NOW = datetime(2026, 9, 4, 11, 30, tzinfo=UTC)
AUTHORIZATION = "Bearer synthetic.session-token"  # gitleaks:allow


def configuration(tmp_path: Path, **changes: object) -> OperatorVerifierConfiguration:
    values: dict[str, object] = {
        "connect_address": "10.40.0.20",
        "port": 9443,
        "authority": "idp.northgate.internal",
        "ca_certificate": tmp_path / "idp-ca.crt",
        "client_certificate": tmp_path / "operator-service.crt",
        "client_private_key": tmp_path / "operator-service.key",
        "timeout_seconds": 5.0,
    }
    values.update(changes)
    return OperatorVerifierConfiguration(**values)  # type: ignore[arg-type]


def principal_body() -> dict[str, object]:
    return {
        "issuer": "https://idp.northgate.internal/issuer",
        "tenant": "northgate",
        "subject": "operator-001",
        "session_id": "session-001",
        "client_id": "northgate-rmm",
        "roles": ["viewer"],
        "authenticated_at": "2026-09-04T11:25:00+00:00",
        "expires_at": "2026-09-04T12:00:00+00:00",
        "mfa": True,
    }


@pytest.mark.parametrize(
    ("change", "value", "match"),
    [
        ("connect_address", "idp.internal", "IP literal"),
        ("connect_address", "8.8.8.8", "private networks"),
        ("port", 0, "port"),
        ("port", True, "port"),
        ("authority", "Idp.Internal", "authority"),
        ("authority", "idp", "authority"),
        ("timeout_seconds", 16, "timeout"),
        ("client_private_key", Path("relative.key"), "paths"),
    ],
)
def test_operator_verifier_configuration_rejects_ambiguous_routes(
    tmp_path: Path,
    change: str,
    value: object,
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        configuration(tmp_path, **{change: value})


def test_operator_verifier_sends_exact_credential_and_decodes_principal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import northgate_rmm.operator_verifier as verifier_module

    body = json.dumps(principal_body(), separators=(",", ":")).encode("ascii")
    observed: dict[str, object] = {}

    class FakeResponse:
        status = 200

        def __init__(self) -> None:
            self._read = False

        def getheader(self, name: str) -> str | None:
            return {
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
            }.get(name)

        def read(self, _amount: int) -> bytes:
            if self._read:
                return b""
            self._read = True
            return body

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
            observed.update(method=method, path=path, body=body, headers=headers)

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            observed["closed"] = True

    context = object()
    monkeypatch.setattr(
        verifier_module, "_build_verifier_context", lambda _value: context
    )
    monkeypatch.setattr(
        verifier_module, "_PinnedOperatorHTTPSConnection", FakeConnection
    )
    verifier = MTLSOperatorSessionVerifier(configuration(tmp_path))

    principal = verifier.verify(AUTHORIZATION, now=NOW)

    assert principal.subject == "operator-001"
    assert principal.roles == ("viewer",)
    assert observed["method"] == "POST"
    assert observed["path"] == "/v1/operator-sessions/verify"
    assert observed["body"] == b""
    assert observed["closed"] is True
    headers = observed["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == AUTHORIZATION
    assert headers["Host"] == "idp.northgate.internal:9443"


def test_operator_verifier_uses_real_tls13_mutual_authentication(
    tmp_path: Path,
) -> None:
    paths = _write_mutual_tls_identities(tmp_path)
    response_body = json.dumps(principal_body(), separators=(",", ":")).encode("ascii")
    received: list[bytes] = []
    failures: list[BaseException] = []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(3.0)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])

    def serve() -> None:
        try:
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_3
            server_context.maximum_version = ssl.TLSVersion.TLSv1_3
            server_context.verify_mode = ssl.CERT_REQUIRED
            server_context.load_verify_locations(cafile=str(paths["root"]))
            server_context.load_cert_chain(
                certfile=str(paths["server_certificate"]),
                keyfile=str(paths["server_key"]),
            )
            raw_socket, _address = listener.accept()
            with server_context.wrap_socket(raw_socket, server_side=True) as secured:
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = secured.recv(4_096)
                    if not chunk:
                        break
                    request += chunk
                received.append(request)
                secured.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + response_body
                )
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    verifier = MTLSOperatorSessionVerifier(
        configuration(
            tmp_path,
            connect_address="127.0.0.1",
            port=port,
            authority="idp.test",
            ca_certificate=paths["root"],
            client_certificate=paths["client_certificate"],
            client_private_key=paths["client_key"],
        )
    )
    try:
        principal = verifier.verify(AUTHORIZATION, now=NOW)
    finally:
        thread.join(timeout=3.0)
        listener.close()

    assert failures == []
    assert not thread.is_alive()
    assert principal.subject == "operator-001"
    assert len(received) == 1
    assert b"POST /v1/operator-sessions/verify HTTP/1.1\r\n" in received[0]
    assert f"Authorization: {AUTHORIZATION}\r\n".encode("ascii") in received[0]


@pytest.mark.parametrize(
    "authorization",
    ["", "Basic x", "Bearer has space", "Bearer bad:token", "Bearer \N{SNOWMAN}"],
)
def test_operator_verifier_rejects_malformed_credentials_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authorization: str,
) -> None:
    import northgate_rmm.operator_verifier as verifier_module

    monkeypatch.setattr(
        verifier_module, "_build_verifier_context", lambda _value: object()
    )
    monkeypatch.setattr(
        verifier_module,
        "_PinnedOperatorHTTPSConnection",
        lambda *_args, **_kwargs: pytest.fail("network client was constructed"),
    )

    with pytest.raises(AuthorizationError, match="verification failed"):
        MTLSOperatorSessionVerifier(configuration(tmp_path)).verify(
            authorization,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("status", "content_length"),
    [(401, "0"), (500, "0"), (200, "invalid"), (200, "9" * 4_301)],
)
def test_operator_verifier_maps_rejection_and_invalid_responses_generically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    content_length: str,
) -> None:
    import northgate_rmm.operator_verifier as verifier_module

    class InvalidResponse:
        def getheader(self, name: str) -> str | None:
            if name == "Content-Length":
                return content_length
            return "application/json" if name == "Content-Type" else None

        def read(self, _amount: int) -> bytes:
            return b""

    response = InvalidResponse()
    response.status = status  # type: ignore[attr-defined]

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            pass

        def getresponse(self) -> InvalidResponse:
            return response

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        verifier_module, "_build_verifier_context", lambda _value: object()
    )
    monkeypatch.setattr(
        verifier_module, "_PinnedOperatorHTTPSConnection", FakeConnection
    )

    with pytest.raises(AuthorizationError):
        MTLSOperatorSessionVerifier(configuration(tmp_path)).verify(
            AUTHORIZATION,
            now=NOW,
        )


@pytest.mark.parametrize("declared_delta", [-1, 1])
def test_operator_verifier_requires_exact_response_length(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declared_delta: int,
) -> None:
    import northgate_rmm.operator_verifier as verifier_module

    body = json.dumps(principal_body(), separators=(",", ":")).encode("ascii")

    class InvalidResponse:
        status = 200

        def __init__(self) -> None:
            self._read = False

        def getheader(self, name: str) -> str | None:
            return {
                "Content-Length": str(len(body) + declared_delta),
                "Content-Type": "application/json",
            }.get(name)

        def read(self, _amount: int) -> bytes:
            if self._read:
                return b""
            self._read = True
            return body

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            pass

        def getresponse(self) -> InvalidResponse:
            return InvalidResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        verifier_module, "_build_verifier_context", lambda _value: object()
    )
    monkeypatch.setattr(
        verifier_module, "_PinnedOperatorHTTPSConnection", FakeConnection
    )

    with pytest.raises(AuthorizationError, match="verification failed"):
        MTLSOperatorSessionVerifier(configuration(tmp_path)).verify(
            AUTHORIZATION,
            now=NOW,
        )


@pytest.mark.parametrize(
    "value",
    [
        b"{}",
        b'{"issuer":"a","issuer":"b"}',
        json.dumps(principal_body() | {"roles": "viewer"}).encode(),
        json.dumps(
            principal_body() | {"authenticated_at": "2026-09-04T06:25:00-05:00"}
        ).encode(),
        json.dumps(principal_body() | {"mfa": "true"}).encode(),
    ],
)
def test_operator_verifier_response_requires_exact_canonical_fields(
    value: bytes,
) -> None:
    with pytest.raises(ValidationError):
        _decode_operator_principal(value)


def _write_mutual_tls_identities(tmp_path: Path) -> dict[str, Path]:
    now = datetime.now(UTC)
    root_key = Ed25519PrivateKey.generate()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, algorithm=None)
    )

    def issue_leaf(
        common_name: str,
        usage: ObjectIdentifier,
        *,
        dns_name: str | None = None,
    ) -> tuple[x509.Certificate, Ed25519PrivateKey]:
        key = Ed25519PrivateKey.generate()
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            )
            .issuer_name(root.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        )
        if dns_name is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
                critical=False,
            )
        return builder.sign(root_key, algorithm=None), key

    server, server_key = issue_leaf(
        "idp.test",
        ExtendedKeyUsageOID.SERVER_AUTH,
        dns_name="idp.test",
    )
    client, client_key = issue_leaf(
        "operator verifier client",
        ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    paths = {
        "root": tmp_path / "root.pem",
        "server_certificate": tmp_path / "server.pem",
        "server_key": tmp_path / "server-key.pem",
        "client_certificate": tmp_path / "client.pem",
        "client_key": tmp_path / "client-key.pem",
    }
    paths["root"].write_bytes(root.public_bytes(serialization.Encoding.PEM))
    paths["server_certificate"].write_bytes(
        server.public_bytes(serialization.Encoding.PEM)
    )
    paths["client_certificate"].write_bytes(
        client.public_bytes(serialization.Encoding.PEM)
    )
    for path, key in (
        (paths["server_key"], server_key),
        (paths["client_key"], client_key),
    ):
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        if os.name == "posix":
            path.chmod(0o600)
    return paths
