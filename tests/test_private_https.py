from __future__ import annotations

import os
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from northgate_rmm.errors import ValidationError
from northgate_rmm.private_https import (
    DeadlineSocket,
    PinnedHTTPSConnection,
    build_mtls_client_context,
    http_authority,
)
from northgate_rmm.tls_identity import load_tls_identity_public_key


def test_build_mtls_client_context_loads_held_identity(tmp_path: Path) -> None:
    root_path, certificate_path, key_path = _write_client_identity(tmp_path)

    context = build_mtls_client_context(
        ca_certificate=root_path,
        client_certificate=certificate_path,
        client_private_key=key_path,
        ca_label="test CA",
        certificate_label="test client certificate",
        private_key_label="test client private key",
    )

    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert load_tls_identity_public_key(
        certificate_path,
        label="test client certificate",
    )


def test_pinned_https_connection_separates_address_and_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class FakeRawSocket:
        def settimeout(self, value: float) -> None:
            observed["raw_timeout"] = value

        def close(self) -> None:
            observed["raw_closed"] = True

    class FakeTLSSocket:
        def settimeout(self, _value: float) -> None:
            pass

    class FakeContext:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def wrap_socket(
            self,
            socket_value: object,
            *,
            server_hostname: str,
        ) -> FakeTLSSocket:
            observed["wrapped"] = socket_value
            observed["server_hostname"] = server_hostname
            return FakeTLSSocket()

    raw_socket = FakeRawSocket()

    def connect(address: tuple[str, int], timeout: float) -> FakeRawSocket:
        observed["address"] = address
        observed["connect_timeout"] = timeout
        return raw_socket

    times = iter([1.0, 2.0, 3.0])
    monkeypatch.setattr(
        "northgate_rmm.private_https.time.monotonic",
        lambda: next(times),
    )
    monkeypatch.setattr(
        "northgate_rmm.private_https.socket.create_connection",
        connect,
    )
    connection = PinnedHTTPSConnection(
        connect_address="10.40.0.20",
        port=9443,
        authority="idp.northgate.internal",
        timeout_seconds=10.0,
        context=cast(ssl.SSLContext, FakeContext()),
    )

    connection.connect()

    assert observed["address"] == ("10.40.0.20", 9443)
    assert observed["connect_timeout"] == 9.0
    assert observed["raw_timeout"] == 8.0
    assert observed["server_hostname"] == "idp.northgate.internal"
    assert isinstance(connection.sock, DeadlineSocket)


def test_pinned_https_connection_closes_raw_socket_on_tls_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = False

    class FakeRawSocket:
        def settimeout(self, _value: float) -> None:
            pass

        def close(self) -> None:
            nonlocal closed
            closed = True

    class FailedContext:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True

        def wrap_socket(self, *_args: object, **_kwargs: object) -> None:
            raise ssl.SSLError("synthetic handshake failure")

    monkeypatch.setattr(
        "northgate_rmm.private_https.socket.create_connection",
        lambda *_args, **_kwargs: FakeRawSocket(),
    )
    connection = PinnedHTTPSConnection(
        connect_address="10.40.0.20",
        port=9443,
        authority="idp.northgate.internal",
        timeout_seconds=10.0,
        context=cast(ssl.SSLContext, FailedContext()),
    )

    with pytest.raises(ssl.SSLError):
        connection.connect()
    assert closed is True


def test_deadline_socket_bounds_read_write_and_file_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("northgate_rmm.private_https.time.monotonic", lambda: 1.0)

    class FakeSocket:
        def __init__(self) -> None:
            self.data = bytearray(b"response")
            self.sent: list[bytes] = []
            self.closed = False

        def settimeout(self, _value: float) -> None:
            pass

        def sendall(self, value: bytes, _flags: int = 0) -> None:
            self.sent.append(value)

        def recv_into(
            self,
            buffer: Any,
            _nbytes: int = 0,
            _flags: int = 0,
        ) -> int:
            view = memoryview(buffer)
            amount = min(len(view), len(self.data))
            view[:amount] = self.data[:amount]
            del self.data[:amount]
            return amount

        def close(self) -> None:
            self.closed = True

    wrapped = FakeSocket()
    deadline = DeadlineSocket(
        cast(ssl.SSLSocket, wrapped),
        deadline=10.0,
    )
    deadline.sendall(b"request")
    reader = deadline.makefile("rb")

    assert reader.read() == b"response"
    assert wrapped.sent == [b"request"]
    with pytest.raises(ValueError, match="response reads only"):
        deadline.makefile("wb")
    deadline.close()
    assert wrapped.closed is True


def test_tls_identity_and_http_authority_reject_invalid_material(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.pem"
    invalid.write_bytes(b"not-a-certificate")

    with pytest.raises(ValidationError, match="invalid"):
        load_tls_identity_public_key(invalid, label="test identity")
    assert http_authority("service.internal", 443) == "service.internal"
    assert http_authority("service.internal", 9443) == "service.internal:9443"


def _write_client_identity(tmp_path: Path) -> tuple[Path, Path, Path]:
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
    client_key = Ed25519PrivateKey.generate()
    client = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test client")])
        )
        .issuer_name(root.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .sign(root_key, algorithm=None)
    )
    root_path = tmp_path / "root.pem"
    certificate_path = tmp_path / "client.pem"
    key_path = tmp_path / "client-key.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(client.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        key_path.chmod(0o600)
    return root_path, certificate_path, key_path
