"""Bounded server-authenticated TLS listener for one-time endpoint enrollment."""

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

from northgate_rmm.enrollment import (
    MAX_ENROLLMENT_BODY_BYTES,
    EnrollmentApplication,
    EnrollmentOperation,
    EnrollmentRequest,
    EnrollmentResponse,
)
from northgate_rmm.errors import ValidationError

MAX_ENROLLMENT_HEADER_BYTES = 2_048
MAX_ENROLLMENT_HEADERS = 24
MAX_CONCURRENT_ENROLLMENTS = 4
MAX_ACTIVE_PER_SOURCE = 1
MAX_CONCURRENT_TLS_HANDSHAKES = 16
MAX_TLS_HANDSHAKES_PER_SOURCE = 2
RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_REQUESTS_PER_SOURCE_WINDOW = 8
MAX_GLOBAL_REQUESTS_PER_WINDOW = 64
MAX_TRACKED_SOURCES = 4_096
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


@dataclass(frozen=True, slots=True)
class EnrollmentListenerConfiguration:
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
                "enrollment bind address must be an IP literal"
            ) from error
        if not any(address in network for network in _ALLOWED_LISTENER_NETWORKS):
            raise ValidationError("enrollment bind address is outside allowed networks")
        if type(self.port) is not int or not 0 <= self.port <= 65_535:
            raise ValidationError("enrollment port is outside the supported range")
        if self.port == 0 and not address.is_loopback:
            raise ValidationError("ephemeral enrollment ports are test-only")
        if _DNS_AUTHORITY.fullmatch(self.authority) is None:
            raise ValidationError("enrollment authority is invalid")
        if type(self.request_timeout_seconds) not in (int, float) or not (
            1.0 <= self.request_timeout_seconds <= 30.0
        ):
            raise ValidationError("enrollment timeout is outside the supported range")
        if not self.server_certificate.is_absolute() or not (
            self.server_private_key.is_absolute()
        ):
            raise ValidationError("enrollment TLS paths must be absolute")


class EnrollmentTLSListener:
    """Own the enrollment-only TLS socket and its bounded connection tasks."""

    def __init__(
        self,
        configuration: EnrollmentListenerConfiguration,
        operation: EnrollmentOperation,
    ) -> None:
        self._configuration = configuration
        self._application = EnrollmentApplication(operation)
        self._server: asyncio.Server | None = None
        self._tls_context: ssl.SSLContext | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._handshake_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TLS_HANDSHAKES)
        self._active_handshakes: dict[str, int] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_ENROLLMENTS)
        self._active_sources: dict[str, int] = {}
        self._rate_limiter = _SourceRateLimiter()

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
            raise RuntimeError("enrollment listener is already started")
        tls_context = _build_server_context(self._configuration)
        self._tls_context = tls_context
        try:
            self._server = await asyncio.start_server(
                self._accept,
                self._configuration.bind_address,
                self._configuration.port,
                limit=MAX_ENROLLMENT_HEADER_BYTES + 4,
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
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
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
                or active >= MAX_TLS_HANDSHAKES_PER_SOURCE
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
            self._release_handshake(source)
            admitted = False
            await self._handle_connection(reader, writer)
        except (ConnectionError, OSError, TimeoutError, ValueError, ssl.SSLError):
            return
        finally:
            if admitted:
                self._release_handshake(source)
            writer.close()
            with suppress(ConnectionError, OSError, ssl.SSLError):
                await writer.wait_closed()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        source: str | None = None
        admitted = False
        operation_task: asyncio.Task[EnrollmentResponse] | None = None
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
            if self._semaphore.locked() or active >= MAX_ACTIVE_PER_SOURCE:
                await _write_error(writer, 503, "enrollment_busy")
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
                    )
                    operation_task = asyncio.create_task(
                        asyncio.to_thread(
                            self._application.handle,
                            request,
                            received_at=datetime.now(UTC),
                        )
                    )
                    response = await asyncio.shield(operation_task)
                    await _write_response(writer, response)
            except TimeoutError:
                if operation_task is not None and not operation_task.done():
                    operation_task.add_done_callback(
                        partial(
                            self._release_after_task,
                            source=source,
                        )
                    )
                    admitted = False
                await _write_error(writer, 408, "request_timeout")
            except _RequestError as error:
                await _write_error(writer, error.status, error.code)
            except asyncio.CancelledError:
                if operation_task is not None and not operation_task.done():
                    operation_task.add_done_callback(
                        partial(
                            self._release_after_task,
                            source=source,
                        )
                    )
                    admitted = False
                raise
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
            raise AssertionError("TLS handshake admission accounting is inconsistent")
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
            raise AssertionError("enrollment admission accounting is inconsistent")
        if active == 1:
            del self._active_sources[source]
        else:
            self._active_sources[source] = active - 1
        self._semaphore.release()

    def _release_after_task(
        self,
        task: asyncio.Task[EnrollmentResponse],
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
) -> EnrollmentRequest:
    try:
        encoded_headers = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as error:
        raise _RequestError(400, "invalid_request") from error
    if len(encoded_headers) > MAX_ENROLLMENT_HEADER_BYTES:
        raise _RequestError(431, "headers_too_large")
    lines = encoded_headers[:-4].split(b"\r\n")
    if not lines or len(lines) > MAX_ENROLLMENT_HEADERS + 1:
        raise _RequestError(400, "invalid_request")
    request_parts = lines[0].split(b" ")
    if len(request_parts) != 3 or request_parts[2] != b"HTTP/1.1":
        raise _RequestError(400, "invalid_request")
    try:
        method = request_parts[0].decode("ascii")
        path = request_parts[1].decode("ascii")
    except UnicodeDecodeError as error:
        raise _RequestError(400, "invalid_request") from error
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, raw_value = line.partition(b":")
        if not separator or _HEADER_NAME.fullmatch(name) is None:
            raise _RequestError(400, "invalid_request")
        normalized_name = name.decode("ascii").lower()
        if normalized_name in headers:
            raise _RequestError(400, "invalid_request")
        value = raw_value.strip(b" \t")
        if not value or any(byte < 32 or byte > 126 for byte in value):
            raise _RequestError(400, "invalid_request")
        headers[normalized_name] = value.decode("ascii")
    if headers.get("host") != authority:
        raise _RequestError(421, "misdirected_request")
    if "transfer-encoding" in headers or "expect" in headers:
        raise _RequestError(400, "invalid_request")
    content_length = headers.get("content-length")
    if (
        content_length is None
        or not content_length.isascii()
        or not content_length.isdigit()
    ):
        raise _RequestError(411, "length_required")
    length = int(content_length)
    if length > MAX_ENROLLMENT_BODY_BYTES:
        raise _RequestError(413, "request_too_large")
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError as error:
        raise _RequestError(400, "invalid_request") from error
    return EnrollmentRequest(
        method=method,
        path=path,
        content_type=headers.get("content-type"),
        content_encoding=headers.get("content-encoding"),
        body=body,
    )


class _SourceRateLimiter:
    def __init__(self) -> None:
        self._sources: OrderedDict[str, deque[float]] = OrderedDict()
        self._global: deque[float] = deque()

    def allow(self, source: str, now: float) -> bool:
        threshold = now - RATE_LIMIT_WINDOW_SECONDS
        while self._global and self._global[0] <= threshold:
            self._global.popleft()
        if len(self._global) >= MAX_GLOBAL_REQUESTS_PER_WINDOW:
            return False
        events = self._sources.get(source)
        if events is None:
            if len(self._sources) >= MAX_TRACKED_SOURCES:
                self._sources.popitem(last=False)
            events = deque()
            self._sources[source] = events
        else:
            self._sources.move_to_end(source)
        while events and events[0] <= threshold:
            events.popleft()
        if len(events) >= MAX_REQUESTS_PER_SOURCE_WINDOW:
            return False
        events.append(now)
        self._global.append(now)
        return True


def _build_server_context(
    configuration: EnrollmentListenerConfiguration,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_NONE
    context.options |= ssl.OP_NO_TICKET
    context.num_tickets = 0
    context.load_cert_chain(
        certfile=str(configuration.server_certificate),
        keyfile=str(configuration.server_private_key),
    )
    return context


async def _write_error(
    writer: asyncio.StreamWriter,
    status: int,
    code: str,
) -> None:
    body = ('{"error":"' + code + '"}').encode("ascii")
    await _write_raw(writer, status, body, ())


async def _write_response(
    writer: asyncio.StreamWriter,
    response: EnrollmentResponse,
) -> None:
    await _write_raw(writer, response.status, response.body, response.headers)


async def _write_raw(
    writer: asyncio.StreamWriter,
    status: int,
    body: bytes,
    headers: tuple[tuple[str, str], ...],
) -> None:
    reason = {
        201: "Created",
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        411: "Length Required",
        413: "Content Too Large",
        415: "Unsupported Media Type",
        421: "Misdirected Request",
        429: "Too Many Requests",
        431: "Request Header Fields Too Large",
        503: "Service Unavailable",
    }.get(status, "Error")
    output_headers = {
        "content-type": "application/json",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "connection": "close",
        "content-length": str(len(body)),
    }
    for name, value in headers:
        output_headers[name.lower()] = value
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
