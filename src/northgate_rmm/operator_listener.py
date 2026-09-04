"""Bounded server-authenticated TLS listener for read-only operator views."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
from collections import OrderedDict, deque
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Protocol

from northgate_rmm.errors import ValidationError
from northgate_rmm.operator_api import OperatorRequest, OperatorResponse
from northgate_rmm.secure_files import private_key_reference, regular_file_reference

MAX_OPERATOR_HEADER_BYTES = 6_144
MAX_OPERATOR_HEADERS = 24
MAX_OPERATOR_RESPONSE_BYTES = 524_288
MAX_CONCURRENT_OPERATOR_REQUESTS = 8
MAX_ACTIVE_OPERATOR_REQUESTS_PER_SOURCE = 2
MAX_CONCURRENT_OPERATOR_TLS_HANDSHAKES = 16
MAX_OPERATOR_TLS_HANDSHAKES_PER_SOURCE = 2
OPERATOR_RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_OPERATOR_REQUESTS_PER_SOURCE_WINDOW = 30
MAX_GLOBAL_OPERATOR_REQUESTS_PER_WINDOW = 120
MAX_TRACKED_OPERATOR_SOURCES = 4_096
_ALLOWED_LISTENER_NETWORKS = tuple(
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
_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")


class OperatorOperation(Protocol):
    def handle(
        self,
        request: OperatorRequest,
        *,
        received_at: datetime,
    ) -> OperatorResponse: ...


@dataclass(frozen=True, slots=True)
class OperatorListenerConfiguration:
    bind_address: str
    port: int
    authority: str
    server_certificate: Path
    server_private_key: Path
    request_timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.bind_address)
        except ValueError as error:
            raise ValidationError(
                "operator bind address must be an IP literal"
            ) from error
        if not any(address in network for network in _ALLOWED_LISTENER_NETWORKS):
            raise ValidationError("operator bind address is outside allowed networks")
        if type(self.port) is not int or not 0 <= self.port <= 65_535:
            raise ValidationError("operator port is outside the supported range")
        if self.port == 0 and not address.is_loopback:
            raise ValidationError("ephemeral operator ports are test-only")
        if _DNS_AUTHORITY.fullmatch(self.authority) is None:
            raise ValidationError("operator authority is invalid")
        if type(self.request_timeout_seconds) not in (int, float) or not (
            1.0 <= self.request_timeout_seconds <= 30.0
        ):
            raise ValidationError("operator timeout is outside the supported range")
        if not self.server_certificate.is_absolute() or not (
            self.server_private_key.is_absolute()
        ):
            raise ValidationError("operator TLS paths must be absolute")


class OperatorTLSListener:
    """Own the operator-only TLS socket and its bounded connection tasks."""

    def __init__(
        self,
        configuration: OperatorListenerConfiguration,
        operation: OperatorOperation,
    ) -> None:
        self._configuration = configuration
        self._operation = operation
        self._server: asyncio.Server | None = None
        self._tls_context: ssl.SSLContext | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._handshake_semaphore = asyncio.Semaphore(
            MAX_CONCURRENT_OPERATOR_TLS_HANDSHAKES
        )
        self._active_handshakes: dict[str, int] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_OPERATOR_REQUESTS)
        self._active_sources: dict[str, int] = {}
        self._rate_limiter = _OperatorSourceRateLimiter()

    @property
    def addresses(self) -> tuple[tuple[str, int], ...]:
        if self._server is None or self._server.sockets is None:
            return ()
        return tuple(
            (str(socket_value.getsockname()[0]), int(socket_value.getsockname()[1]))
            for socket_value in self._server.sockets
        )

    async def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("operator listener is already started")
        self._tls_context = _build_server_context(self._configuration)
        try:
            self._server = await asyncio.start_server(
                self._accept,
                self._configuration.bind_address,
                self._configuration.port,
                limit=MAX_OPERATOR_HEADER_BYTES + 4,
                backlog=32,
                reuse_address=True,
                reuse_port=False,
                start_serving=True,
            )
        except BaseException:
            self._tls_context = None
            raise

    async def close(self) -> None:
        server, self._server = self._server, None
        self._tls_context = None
        if server is not None:
            server.close()
            await server.wait_closed()
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(self._handle_transport(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle_transport(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        source: str | None = None
        admitted = False
        try:
            peer = writer.get_extra_info("peername")
            if not isinstance(peer, tuple) or not peer or not isinstance(peer[0], str):
                return
            source = str(ipaddress.ip_address(peer[0]))
            active = self._active_handshakes.get(source, 0)
            if (
                self._handshake_semaphore.locked()
                or active >= MAX_OPERATOR_TLS_HANDSHAKES_PER_SOURCE
            ):
                return
            await self._handshake_semaphore.acquire()
            self._active_handshakes[source] = active + 1
            admitted = True
            tls_context = self._tls_context
            if tls_context is None:
                return
            await writer.start_tls(
                tls_context,
                ssl_handshake_timeout=self._configuration.request_timeout_seconds,
            )
            await self._handle_connection(reader, writer)
        except (ConnectionError, OSError, TimeoutError, ValueError, ssl.SSLError):
            return
        finally:
            await _close_writer(writer)
            if admitted:
                self._release_handshake(source)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        source: str | None = None
        admitted = False
        operation_task: asyncio.Task[OperatorResponse] | None = None
        try:
            peer = writer.get_extra_info("peername")
            if not isinstance(peer, tuple) or not peer or not isinstance(peer[0], str):
                await _write_error(writer, 400, "invalid_request")
                return
            source = str(ipaddress.ip_address(peer[0]))
            now = asyncio.get_running_loop().time()
            if not self._rate_limiter.allow(source, now):
                await _write_error(writer, 429, "rate_limited")
                return
            active = self._active_sources.get(source, 0)
            if (
                self._semaphore.locked()
                or active >= MAX_ACTIVE_OPERATOR_REQUESTS_PER_SOURCE
            ):
                await _write_error(writer, 503, "operator_busy")
                return
            await self._semaphore.acquire()
            self._active_sources[source] = active + 1
            admitted = True
            try:
                async with asyncio.timeout(
                    float(self._configuration.request_timeout_seconds)
                ):
                    request = await _read_request(
                        reader,
                        authority=self._configuration.authority,
                        port=self._configuration.port,
                    )
                    operation_task = asyncio.create_task(
                        asyncio.to_thread(
                            self._operation.handle,
                            request,
                            received_at=datetime.now(UTC),
                        )
                    )
                    response = await asyncio.shield(operation_task)
                    if len(response.body) > MAX_OPERATOR_RESPONSE_BYTES:
                        await _write_error(writer, 503, "operator_unavailable")
                    else:
                        await _write_response(writer, response)
            except TimeoutError:
                if operation_task is not None and not operation_task.done():
                    operation_task.add_done_callback(
                        partial(self._release_after_task, source=source)
                    )
                    admitted = False
                await _write_error(writer, 408, "request_timeout")
            except _RequestError as error:
                await _write_error(writer, error.status, error.code)
            except asyncio.CancelledError:
                if operation_task is not None and not operation_task.done():
                    operation_task.add_done_callback(
                        partial(self._release_after_task, source=source)
                    )
                    admitted = False
                raise
            except Exception:
                await _write_error(writer, 503, "operator_unavailable")
        except (ConnectionError, OSError, ValueError):
            return
        finally:
            if admitted and source is not None:
                self._release(source)

    def _release_handshake(self, source: str | None) -> None:
        if source is None:
            return
        active = self._active_handshakes.get(source)
        if active is None or active < 1:
            raise AssertionError("operator TLS admission accounting is inconsistent")
        if active == 1:
            del self._active_handshakes[source]
        else:
            self._active_handshakes[source] = active - 1
        self._handshake_semaphore.release()

    def _release(self, source: str | None) -> None:
        if source is None:
            return
        active = self._active_sources.get(source)
        if active is None or active < 1:
            raise AssertionError(
                "operator request admission accounting is inconsistent"
            )
        if active == 1:
            del self._active_sources[source]
        else:
            self._active_sources[source] = active - 1
        self._semaphore.release()

    def _release_after_task(
        self,
        task: asyncio.Task[OperatorResponse],
        *,
        source: str | None,
    ) -> None:
        with suppress(asyncio.CancelledError, Exception):
            task.exception()
        self._release(source)


@dataclass(frozen=True, slots=True)
class _RequestError(Exception):
    status: int
    code: str


async def _read_request(
    reader: asyncio.StreamReader,
    *,
    authority: str,
    port: int,
) -> OperatorRequest:
    try:
        encoded_headers = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
        raise _RequestError(400, "invalid_request") from error
    if len(encoded_headers) > MAX_OPERATOR_HEADER_BYTES:
        raise _RequestError(431, "headers_too_large")
    lines = encoded_headers[:-4].split(b"\r\n")
    if not lines or len(lines) > MAX_OPERATOR_HEADERS + 1:
        raise _RequestError(400, "invalid_request")
    request_parts = lines[0].split(b" ")
    if len(request_parts) != 3 or request_parts[2] != b"HTTP/1.1":
        raise _RequestError(400, "invalid_request")
    raw_path, separator, raw_query = request_parts[1].partition(b"?")
    try:
        method = request_parts[0].decode("ascii")
        path = raw_path.decode("ascii")
        query_string = raw_query.decode("ascii") if separator else ""
    except UnicodeDecodeError as error:
        raise _RequestError(400, "invalid_request") from error
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, header_separator, raw_value = line.partition(b":")
        if not header_separator or _HEADER_NAME.fullmatch(name) is None:
            raise _RequestError(400, "invalid_request")
        normalized_name = name.decode("ascii").lower()
        if normalized_name in headers:
            raise _RequestError(400, "invalid_request")
        value = raw_value.strip(b" \t")
        if not value or any(byte < 32 or byte > 126 for byte in value):
            raise _RequestError(400, "invalid_request")
        headers[normalized_name] = value.decode("ascii")
    expected_host = authority if port in {0, 443} else f"{authority}:{port}"
    if headers.get("host") != expected_host:
        raise _RequestError(421, "misdirected_request")
    if any(
        name in headers for name in ("transfer-encoding", "expect", "content-encoding")
    ):
        raise _RequestError(400, "invalid_request")
    content_length = headers.get("content-length")
    if content_length is not None and content_length != "0":
        raise _RequestError(413, "request_body_not_allowed")
    return OperatorRequest(
        method=method,
        path=path,
        authorization=headers.get("authorization"),
        query_string=query_string,
    )


class _OperatorSourceRateLimiter:
    def __init__(self) -> None:
        self._sources: OrderedDict[str, deque[float]] = OrderedDict()
        self._global: deque[float] = deque()

    def allow(self, source: str, now: float) -> bool:
        threshold = now - OPERATOR_RATE_LIMIT_WINDOW_SECONDS
        while self._global and self._global[0] <= threshold:
            self._global.popleft()
        if len(self._global) >= MAX_GLOBAL_OPERATOR_REQUESTS_PER_WINDOW:
            return False
        events = self._sources.get(source)
        if events is None:
            if len(self._sources) >= MAX_TRACKED_OPERATOR_SOURCES:
                self._sources.popitem(last=False)
            events = deque()
            self._sources[source] = events
        else:
            self._sources.move_to_end(source)
        while events and events[0] <= threshold:
            events.popleft()
        if len(events) >= MAX_OPERATOR_REQUESTS_PER_SOURCE_WINDOW:
            return False
        events.append(now)
        self._global.append(now)
        return True


def _build_server_context(
    configuration: OperatorListenerConfiguration,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_TICKET
    context.num_tickets = 0
    with (
        regular_file_reference(
            configuration.server_certificate,
            label="operator server certificate",
            maximum_bytes=65_536,
            private=False,
        ) as certificate_path,
        private_key_reference(
            configuration.server_private_key,
            label="operator server private key",
        ) as key_path,
    ):
        context.load_cert_chain(
            certfile=str(certificate_path),
            keyfile=str(key_path),
        )
    return context


async def _write_error(
    writer: asyncio.StreamWriter,
    status: int,
    code: str,
) -> None:
    body = ('{"error":"' + code + '"}').encode("ascii")
    await _write_raw(writer, status, body, ())


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        async with asyncio.timeout(1.0):
            await writer.wait_closed()
    except (ConnectionError, OSError, TimeoutError, ssl.SSLError):
        writer.transport.abort()


async def _write_response(
    writer: asyncio.StreamWriter,
    response: OperatorResponse,
) -> None:
    await _write_raw(writer, response.status, response.body, response.headers)


async def _write_raw(
    writer: asyncio.StreamWriter,
    status: int,
    body: bytes,
    headers: tuple[tuple[str, str], ...],
) -> None:
    reason = {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        408: "Request Timeout",
        413: "Content Too Large",
        421: "Misdirected Request",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        503: "Service Unavailable",
    }.get(status, "Error")
    output_headers = {
        "content-type": "application/json",
        "cache-control": "no-store",
        "content-security-policy": (
            "default-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'"
        ),
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=31536000",
        "connection": "close",
        "content-length": str(len(body)),
    }
    for name, value in headers:
        normalized_name = name.lower()
        if (
            normalized_name == "content-type"
            and value in {"application/json", "text/html; charset=utf-8"}
        ) or (normalized_name == "www-authenticate" and value == "Bearer"):
            output_headers[normalized_name] = value
    encoded_headers = "".join(
        f"{name}: {value}\r\n" for name, value in output_headers.items()
    ).encode("ascii")
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
        + encoded_headers
        + b"\r\n"
        + body
    )
    await writer.drain()
