from __future__ import annotations

import asyncio
import os
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Semaphore

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from northgate_rmm.errors import ValidationError
from northgate_rmm.operator_api import OperatorRequest, OperatorResponse
from northgate_rmm.operator_listener import (
    MAX_OPERATOR_HEADER_BYTES,
    OperatorListenerConfiguration,
    OperatorTLSListener,
    _OperatorSourceRateLimiter,
    _read_request,
    _RequestError,
)

AUTHORIZATION = "Bearer synthetic.session-token"  # gitleaks:allow


def configuration(tmp_path: Path, **changes: object) -> OperatorListenerConfiguration:
    values: dict[str, object] = {
        "bind_address": "127.0.0.1",
        "port": 8443,
        "authority": "operator.northgate.internal",
        "server_certificate": tmp_path / "operator.crt",
        "server_private_key": tmp_path / "operator.key",
        "request_timeout_seconds": 5.0,
    }
    values.update(changes)
    return OperatorListenerConfiguration(**values)  # type: ignore[arg-type]


def read_request(encoded: bytes, *, port: int = 8443) -> OperatorRequest:
    async def exercise() -> OperatorRequest:
        reader = asyncio.StreamReader(limit=MAX_OPERATOR_HEADER_BYTES + 4)
        reader.feed_data(encoded)
        reader.feed_eof()
        return await _read_request(
            reader,
            authority="operator.northgate.internal",
            port=port,
        )

    return asyncio.run(exercise())


@pytest.mark.parametrize(
    ("change", "value", "match"),
    [
        ("bind_address", "operator.internal", "IP literal"),
        ("bind_address", "8.8.8.8", "allowed networks"),
        ("bind_address", "10.20.0.10", "ephemeral"),
        ("port", True, "port"),
        ("authority", "Operator.Internal", "authority"),
        ("request_timeout_seconds", 31, "timeout"),
        ("server_private_key", Path("relative.key"), "paths"),
    ],
)
def test_operator_listener_configuration_rejects_ambiguous_values(
    tmp_path: Path,
    change: str,
    value: object,
    match: str,
) -> None:
    changes = {change: value}
    if change == "bind_address" and value == "10.20.0.10":
        changes["port"] = 0
    with pytest.raises(ValidationError, match=match):
        configuration(tmp_path, **changes)


def test_operator_request_parser_preserves_exact_read_contract() -> None:
    request = read_request(
        b"GET /endpoints?unexpected=1 HTTP/1.1\r\n"
        b"Host: operator.northgate.internal:8443\r\n"
        + f"Authorization: {AUTHORIZATION}\r\n".encode("ascii")
        + b"Content-Length: 0\r\n\r\n"
    )

    assert request == OperatorRequest(
        method="GET",
        path="/endpoints",
        authorization=AUTHORIZATION,
        query_string="unexpected=1",
    )


def test_operator_request_parser_accepts_browser_get_without_body_header() -> None:
    request = read_request(
        b"GET /endpoints HTTP/1.1\r\nHost: operator.northgate.internal:8443\r\n\r\n"
    )

    assert request.authorization is None
    assert request.query_string == ""


def test_operator_request_parser_accepts_default_https_host() -> None:
    request = read_request(
        b"GET /endpoints HTTP/1.1\r\nHost: operator.northgate.internal\r\n\r\n",
        port=443,
    )

    assert request.path == "/endpoints"


@pytest.mark.parametrize(
    ("encoded", "status"),
    [
        (b"GET / HTTP/1.1\r\n", 400),
        (b"GET / HTTP/1.0\r\nHost: operator.northgate.internal:8443\r\n\r\n", 400),
        (
            b"GET / HTTP/1.1\r\nHost: other.internal\r\n\r\n",
            421,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: operator.northgate.internal:8443\r\n"
            b"Host: operator.northgate.internal:8443\r\n\r\n",
            400,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: operator.northgate.internal:8443\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n",
            400,
        ),
        (
            b"GET / HTTP/1.1\r\nHost: operator.northgate.internal:8443\r\n"
            b"Content-Length: 1\r\n\r\nx",
            413,
        ),
        (
            b"GET /\xff HTTP/1.1\r\nHost: operator.northgate.internal:8443\r\n\r\n",
            400,
        ),
        (
            b"GET / HTTP/1.1\r\n"
            b"Bad Header: value\r\n"
            b"Host: operator.northgate.internal:8443\r\n\r\n",
            400,
        ),
        (
            b"GET / HTTP/1.1\r\n"
            b"X-Empty: \r\n"
            b"Host: operator.northgate.internal:8443\r\n\r\n",
            400,
        ),
        (
            b"GET / HTTP/1.1\r\n"
            + b"\r\n".join(f"X-{index}: value".encode() for index in range(25))
            + b"\r\n\r\n",
            400,
        ),
    ],
)
def test_operator_request_parser_rejects_ambiguous_framing(
    encoded: bytes,
    status: int,
) -> None:
    with pytest.raises(_RequestError) as raised:
        read_request(encoded)
    assert raised.value.status == status


def test_operator_request_parser_rejects_header_just_above_limit() -> None:
    prefix = b"GET / HTTP/1.1\r\nHost: operator.northgate.internal:8443\r\nX-Large: "
    suffix = b"\r\n\r\n"
    encoded = (
        prefix
        + b"x" * (MAX_OPERATOR_HEADER_BYTES + 1 - len(prefix) - len(suffix))
        + suffix
    )
    assert len(encoded) == MAX_OPERATOR_HEADER_BYTES + 1

    with pytest.raises(_RequestError) as raised:
        read_request(encoded)
    assert raised.value.status == 431


@dataclass
class RecordingOperation:
    response: OperatorResponse = field(
        default_factory=lambda: OperatorResponse(
            status=200,
            headers=(("content-type", "text/html; charset=utf-8"),),
            body=b"ok",
        )
    )
    calls: list[tuple[OperatorRequest, datetime]] = field(default_factory=list)

    def handle(
        self,
        request: OperatorRequest,
        *,
        received_at: datetime,
    ) -> OperatorResponse:
        self.calls.append((request, received_at))
        return self.response


def test_operator_rate_limiter_is_source_and_global_bounded() -> None:
    limiter = _OperatorSourceRateLimiter()
    for _index in range(30):
        assert limiter.allow("10.0.0.1", 100.0)
    assert limiter.allow("10.0.0.1", 100.0) is False
    assert limiter.allow("10.0.0.2", 100.0)
    assert limiter.allow("10.0.0.1", 161.0)


def test_operator_rate_limiter_enforces_global_and_source_tracking_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import northgate_rmm.operator_listener as listener_module

    limiter = _OperatorSourceRateLimiter()
    for source_index in range(4):
        for _request_index in range(30):
            assert limiter.allow(f"10.0.0.{source_index + 1}", 100.0)
    assert limiter.allow("10.0.0.99", 100.0) is False

    monkeypatch.setattr(listener_module, "MAX_TRACKED_OPERATOR_SOURCES", 2)
    tracked = _OperatorSourceRateLimiter()
    assert tracked.allow("10.0.0.1", 100.0)
    assert tracked.allow("10.0.0.2", 100.0)
    assert tracked.allow("10.0.0.3", 100.0)
    assert tuple(tracked._sources) == ("10.0.0.2", "10.0.0.3")


def test_operator_listener_accepts_only_trusted_tls(tmp_path: Path) -> None:
    root_path, certificate_path, key_path = _write_server_identity(tmp_path)
    config = configuration(
        tmp_path,
        port=0,
        authority="operator.test",
        server_certificate=certificate_path,
        server_private_key=key_path,
    )
    operation = RecordingOperation()

    async def scenario() -> None:
        listener = OperatorTLSListener(config, operation)
        assert listener.addresses == ()
        await listener.start()
        try:
            with pytest.raises(RuntimeError, match="already started"):
                await listener.start()
            addresses = listener.addresses
            assert addresses
            host, port = addresses[0]
            context = ssl.create_default_context(cafile=str(root_path))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            reader, writer = await asyncio.open_connection(
                host,
                port,
                ssl=context,
                server_hostname="operator.test",
            )
            writer.write(
                b"GET /endpoints HTTP/1.1\r\n"
                b"Host: operator.test\r\n"
                + f"Authorization: {AUTHORIZATION}\r\n\r\n".encode("ascii")
            )
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            assert response.startswith(b"HTTP/1.1 200 OK\r\n")
            assert b"strict-transport-security: max-age=31536000" in response.lower()
            assert b"server:" not in response.lower()
            assert operation.calls[0][0].authorization == AUTHORIZATION
            assert operation.calls[0][1].tzinfo is not None

            untrusted = ssl.create_default_context()
            untrusted.check_hostname = False
            with pytest.raises((ssl.SSLError, ConnectionError)):
                await asyncio.open_connection(
                    host,
                    port,
                    ssl=untrusted,
                    server_hostname="operator.test",
                )

            plain_reader, plain_writer = await asyncio.open_connection(host, port)
            plain_writer.write(b"GET /endpoints HTTP/1.1\r\n\r\n")
            await plain_writer.drain()
            assert await asyncio.wait_for(plain_reader.read(1), timeout=1.0) == b""
            plain_writer.close()
            await plain_writer.wait_closed()
        finally:
            await listener.close()
            await listener.close()

    asyncio.run(scenario())


def test_operator_listener_owns_transport_security_headers(tmp_path: Path) -> None:
    root_path, certificate_path, key_path = _write_server_identity(tmp_path)
    config = configuration(
        tmp_path,
        port=0,
        authority="operator.test",
        server_certificate=certificate_path,
        server_private_key=key_path,
    )
    operation = RecordingOperation(
        response=OperatorResponse(
            status=200,
            headers=(
                ("content-type", "text/plain\r\nx-injected: true"),
                ("content-length", "999"),
                ("connection", "keep-alive"),
                ("strict-transport-security", "max-age=0"),
                ("server", "unexpected"),
            ),
            body=b"ok",
        )
    )

    async def scenario() -> None:
        listener = OperatorTLSListener(config, operation)
        await listener.start()
        try:
            host, port = listener.addresses[0]
            context = ssl.create_default_context(cafile=str(root_path))
            response = await _send_operator(host, port, context)
            normalized = response.lower()
            assert b"content-type: application/json\r\n" in normalized
            assert b"x-injected" not in normalized
            assert b"content-length: 2\r\n" in normalized
            assert b"content-length: 999" not in normalized
            assert b"connection: close\r\n" in normalized
            assert b"keep-alive" not in normalized
            assert b"strict-transport-security: max-age=31536000\r\n" in normalized
            assert b"max-age=0" not in normalized
            assert b"server:" not in normalized
        finally:
            await listener.close()

    asyncio.run(scenario())


class BlockingOperation(RecordingOperation):
    def __init__(self) -> None:
        super().__init__()
        self.entered = Semaphore(0)
        self.release = Event()

    def handle(
        self,
        request: OperatorRequest,
        *,
        received_at: datetime,
    ) -> OperatorResponse:
        self.calls.append((request, received_at))
        self.entered.release()
        self.release.wait(5)
        return self.response


def test_timed_out_operator_requests_retain_admission_until_work_finishes(
    tmp_path: Path,
) -> None:
    root_path, certificate_path, key_path = _write_server_identity(tmp_path)
    config = configuration(
        tmp_path,
        port=0,
        authority="operator.test",
        server_certificate=certificate_path,
        server_private_key=key_path,
        request_timeout_seconds=1.0,
    )
    operation = BlockingOperation()

    async def scenario() -> None:
        listener = OperatorTLSListener(config, operation)
        await listener.start()
        try:
            host, port = listener.addresses[0]
            context = ssl.create_default_context(cafile=str(root_path))
            first = asyncio.create_task(_send_operator(host, port, context))
            second = asyncio.create_task(_send_operator(host, port, context))
            assert await asyncio.to_thread(operation.entered.acquire, True, 2)
            assert await asyncio.to_thread(operation.entered.acquire, True, 2)
            first_response, second_response = await asyncio.gather(first, second)
            assert first_response.startswith(b"HTTP/1.1 408 Request Timeout\r\n")
            assert second_response.startswith(b"HTTP/1.1 408 Request Timeout\r\n")
            assert (await _send_operator(host, port, context)).startswith(
                b"HTTP/1.1 503 Service Unavailable\r\n"
            )
            operation.release.set()
            for _index in range(50):
                await asyncio.sleep(0.01)
                if not listener._active_sources:
                    break
            assert not listener._active_sources
            assert (await _send_operator(host, port, context)).startswith(
                b"HTTP/1.1 200 OK\r\n"
            )
        finally:
            operation.release.set()
            await listener.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["oversized", "exception"])
def test_operator_listener_maps_internal_failures_generically(
    tmp_path: Path,
    failure: str,
) -> None:
    root_path, certificate_path, key_path = _write_server_identity(tmp_path)
    config = configuration(
        tmp_path,
        port=0,
        authority="operator.test",
        server_certificate=certificate_path,
        server_private_key=key_path,
    )

    class FailedOperation(RecordingOperation):
        def handle(
            self,
            request: OperatorRequest,
            *,
            received_at: datetime,
        ) -> OperatorResponse:
            if failure == "exception":
                raise RuntimeError("private internal detail")
            return OperatorResponse(200, (), b"x" * 524_289)

    async def scenario() -> None:
        listener = OperatorTLSListener(config, FailedOperation())
        await listener.start()
        try:
            host, port = listener.addresses[0]
            context = ssl.create_default_context(cafile=str(root_path))
            response = await _send_operator(host, port, context)
            assert response.startswith(b"HTTP/1.1 503 Service Unavailable\r\n")
            assert b"private internal detail" not in response
        finally:
            await listener.close()

    asyncio.run(scenario())


def test_incomplete_operator_tls_handshakes_are_bounded_per_source(
    tmp_path: Path,
) -> None:
    _root_path, certificate_path, key_path = _write_server_identity(tmp_path)
    config = configuration(
        tmp_path,
        port=0,
        authority="operator.test",
        server_certificate=certificate_path,
        server_private_key=key_path,
    )

    async def scenario() -> None:
        listener = OperatorTLSListener(config, RecordingOperation())
        await listener.start()
        writers: list[asyncio.StreamWriter] = []
        try:
            host, port = listener.addresses[0]
            _first_reader, first_writer = await asyncio.open_connection(host, port)
            _second_reader, second_writer = await asyncio.open_connection(host, port)
            third_reader, third_writer = await asyncio.open_connection(host, port)
            writers.extend((first_writer, second_writer, third_writer))
            assert await asyncio.wait_for(third_reader.read(1), timeout=0.5) == b""
            assert listener._active_handshakes == {"127.0.0.1": 2}
        finally:
            for writer in writers:
                writer.close()
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )
            await listener.close()

    asyncio.run(scenario())


async def _send_operator(
    host: str,
    port: int,
    context: ssl.SSLContext,
) -> bytes:
    reader, writer = await asyncio.open_connection(
        host,
        port,
        ssl=context,
        server_hostname="operator.test",
    )
    writer.write(
        b"GET /endpoints HTTP/1.1\r\n"
        b"Host: operator.test\r\n"
        + f"Authorization: {AUTHORIZATION}\r\n\r\n".encode("ascii")
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
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "operator.test")])
        )
        .issuer_name(root.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("operator.test")]),
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
    if os.name == "posix":
        key_path.chmod(0o600)
    return root_path, certificate_path, key_path
