from __future__ import annotations

import asyncio
import json
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from northgate_rmm.enrollment import EnrollmentRequest, EnrollmentResult
from northgate_rmm.enrollment_listener import (
    EnrollmentListenerConfiguration,
    EnrollmentTLSListener,
    _read_request,
    _RequestError,
    _SourceRateLimiter,
)
from northgate_rmm.errors import ValidationError


class RecordingOperation:
    def enroll(self, *, token: str, csr_der: bytes, now: datetime) -> EnrollmentResult:
        del token, csr_der, now
        return EnrollmentResult(
            endpoint_id=UUID("11111111-1111-4111-8111-111111111111"),
            identity_id=UUID("22222222-2222-4222-8222-222222222222"),
            leaf_certificate_der=b"leaf",
            intermediate_certificates_der=(),
        )


class BlockingOperation(RecordingOperation):
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def enroll(self, *, token: str, csr_der: bytes, now: datetime) -> EnrollmentResult:
        self.entered.set()
        if not self.release.wait(timeout=3):
            raise AssertionError("test did not release enrollment")
        return super().enroll(token=token, csr_der=csr_der, now=now)


def configuration(tmp_path: Path, **changes: object) -> EnrollmentListenerConfiguration:
    values: dict[str, object] = {
        "bind_address": "127.0.0.1",
        "port": 0,
        "authority": "enroll.northgate.internal",
        "server_certificate": tmp_path / "server.crt",
        "server_private_key": tmp_path / "server.key",
        "request_timeout_seconds": 5.0,
    }
    values.update(changes)
    return EnrollmentListenerConfiguration(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("change", "value", "match"),
    [
        ("bind_address", "enroll.internal", "IP literal"),
        ("bind_address", "8.8.8.8", "allowed networks"),
        ("bind_address", "192.0.2.1", "allowed networks"),
        ("port", True, "port"),
        ("port", 65_536, "port"),
        ("authority", "Enroll.Internal", "authority"),
        ("authority", "enroll", "authority"),
        ("request_timeout_seconds", 0.5, "timeout"),
        ("server_private_key", Path("relative.key"), "paths"),
    ],
)
def test_enrollment_listener_configuration_is_exact(
    tmp_path: Path,
    change: str,
    value: object,
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        configuration(tmp_path, **{change: value})


def test_enrollment_request_parser_accepts_one_bounded_http_request() -> None:
    body = json.dumps({"grant": "g", "csr": "eA=="}).encode("ascii")
    request = asyncio.run(
        _parse_request(
            b"POST /v1/enrollment HTTP/1.1\r\n"
            b"Host: enroll.northgate.internal\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"\r\n"
            + body
        )
    )

    assert request.method == "POST"
    assert request.path == "/v1/enrollment"
    assert request.content_type == "application/json"
    assert request.body == body


@pytest.mark.parametrize(
    ("encoded", "status"),
    [
        (
            b"POST /v1/enrollment HTTP/1.1\r\n"
            b"Host: enroll.northgate.internal\r\n"
            b"Host: other.internal\r\nContent-Length: 0\r\n\r\n",
            400,
        ),
        (
            b"POST /v1/enrollment HTTP/1.1\r\n"
            b"Host: enroll.northgate.internal\r\n"
            b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
            400,
        ),
        (
            b"POST /v1/enrollment HTTP/1.1\r\n"
            b"Host: other.internal\r\nContent-Length: 0\r\n\r\n",
            421,
        ),
        (
            b"POST /v1/enrollment HTTP/1.1\r\nHost: enroll.northgate.internal\r\n\r\n",
            411,
        ),
        (
            b"POST /v1/enrollment HTTP/1.0\r\n"
            b"Host: enroll.northgate.internal\r\nContent-Length: 0\r\n\r\n",
            400,
        ),
    ],
)
def test_enrollment_request_parser_rejects_ambiguous_framing(
    encoded: bytes,
    status: int,
) -> None:
    with pytest.raises(_RequestError) as raised:
        asyncio.run(_parse_request(encoded))

    assert raised.value.status == status


def test_enrollment_rate_limiter_is_source_and_global_bounded() -> None:
    limiter = _SourceRateLimiter()
    for _index in range(8):
        assert limiter.allow("10.0.0.1", 100.0)
    assert limiter.allow("10.0.0.1", 100.0) is False
    assert limiter.allow("10.0.0.2", 100.0)
    assert limiter.allow("10.0.0.1", 161.0)


def test_enrollment_listener_accepts_only_trusted_tls(tmp_path: Path) -> None:
    root_path, certificate_path, key_path = _write_server_identity(tmp_path)
    config = configuration(
        tmp_path,
        authority="enroll.test",
        server_certificate=certificate_path,
        server_private_key=key_path,
    )

    async def scenario() -> None:
        listener = EnrollmentTLSListener(config, RecordingOperation())
        await listener.start()
        try:
            host, port = listener.addresses[0]
            context = ssl.create_default_context(cafile=str(root_path))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            reader, writer = await asyncio.open_connection(
                host,
                port,
                ssl=context,
                server_hostname="enroll.test",
            )
            body = b'{"grant":"g","csr":"eA=="}'
            writer.write(
                b"POST /v1/enrollment HTTP/1.1\r\n"
                b"Host: enroll.test\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                + body
            )
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            assert response.startswith(b"HTTP/1.1 201 Created\r\n")
            assert b"server:" not in response.lower()

            untrusted = ssl.create_default_context()
            untrusted.check_hostname = False
            with pytest.raises((ssl.SSLError, ConnectionError)):
                await asyncio.open_connection(
                    host,
                    port,
                    ssl=untrusted,
                    server_hostname="enroll.test",
                )

            plain_reader, plain_writer = await asyncio.open_connection(host, port)
            plain_writer.write(b"POST /v1/enrollment HTTP/1.1\r\n\r\n")
            await plain_writer.drain()
            assert await asyncio.wait_for(plain_reader.read(1), timeout=1.0) == b""
            plain_writer.close()
            await plain_writer.wait_closed()
        finally:
            await listener.close()

    asyncio.run(scenario())


def test_timed_out_enrollment_retains_admission_until_work_finishes(
    tmp_path: Path,
) -> None:
    root_path, certificate_path, key_path = _write_server_identity(tmp_path)
    config = configuration(
        tmp_path,
        authority="enroll.test",
        server_certificate=certificate_path,
        server_private_key=key_path,
        request_timeout_seconds=1.0,
    )
    operation = BlockingOperation()

    async def scenario() -> None:
        listener = EnrollmentTLSListener(config, operation)
        await listener.start()
        try:
            host, port = listener.addresses[0]
            context = ssl.create_default_context(cafile=str(root_path))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            first = asyncio.create_task(_send_enrollment(host, port, context))
            assert await asyncio.to_thread(operation.entered.wait, 2)
            assert (await first).startswith(b"HTTP/1.1 408 Request Timeout\r\n")
            assert (await _send_enrollment(host, port, context)).startswith(
                b"HTTP/1.1 503 Service Unavailable\r\n"
            )
            operation.release.set()
            for _index in range(20):
                await asyncio.sleep(0.01)
                if not listener._active_sources:
                    break
            assert not listener._active_sources
            assert (await _send_enrollment(host, port, context)).startswith(
                b"HTTP/1.1 201 Created\r\n"
            )
        finally:
            operation.release.set()
            await listener.close()

    asyncio.run(scenario())


async def _parse_request(encoded: bytes) -> EnrollmentRequest:
    reader = asyncio.StreamReader(limit=2_052)
    reader.feed_data(encoded)
    reader.feed_eof()
    return await _read_request(reader, authority="enroll.northgate.internal")


async def _send_enrollment(host: str, port: int, context: ssl.SSLContext) -> bytes:
    reader, writer = await asyncio.open_connection(
        host,
        port,
        ssl=context,
        server_hostname="enroll.test",
    )
    body = b'{"grant":"g","csr":"eA=="}'
    writer.write(
        b"POST /v1/enrollment HTTP/1.1\r\n"
        b"Host: enroll.test\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    return response


def _write_server_identity(tmp_path: Path) -> tuple[Path, Path, Path]:
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
    server_key = Ed25519PrivateKey.generate()
    server = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "enroll.test")])
        )
        .issuer_name(root.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("enroll.test")]),
            critical=False,
        )
        .sign(root_key, algorithm=None)
    )
    root_path = tmp_path / "root.pem"
    certificate_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(server.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return root_path, certificate_path, key_path
