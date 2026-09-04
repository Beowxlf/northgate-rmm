"""Private TLS listener adapter for the bounded agent message application.

The listener accepts no operator traffic and exposes no enrollment operation.
It converts only a TLS-verified endpoint certificate into the transport identity
facts consumed by :mod:`northgate_rmm.agent_api`.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import ssl
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

from aiohttp import HttpVersion11, web
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_server import Server
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from northgate_rmm.agent_api import (
    AgentMessageApplication,
    AgentMessageRequest,
    AgentMessageResponse,
    AgentMessageStore,
    VerifiedClientCertificate,
)
from northgate_rmm.codec import MAX_ENCODED_MESSAGE_BYTES
from northgate_rmm.errors import ValidationError

ENDPOINT_URI_PREFIX = "urn:northgate-rmm:endpoint:"
MAX_HEADER_COUNT = 32
MAX_HEADER_BYTES = 2_048
MAX_CONCURRENT_REQUESTS = 16
MAX_CONCURRENT_REQUESTS_PER_IDENTITY = 4
DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
RATE_LIMIT_WINDOW_SECONDS = 10.0
MAX_REQUESTS_PER_IDENTITY_WINDOW = 32
MAX_GLOBAL_REQUESTS_PER_WINDOW = 160
MAX_TRACKED_IDENTITIES = 4_096


class PeerCertificate(Protocol):
    def getpeercert(self, binary_form: bool = False) -> bytes | dict[str, object]: ...

    def version(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class AgentListenerConfiguration:
    """Non-secret listener settings plus references to runtime TLS material."""

    bind_address: str
    port: int
    authority: str
    server_certificate: Path
    server_private_key: Path
    endpoint_ca_certificate: Path
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.bind_address)
        except ValueError as error:
            raise ValidationError(
                "listener bind address must be an IP literal"
            ) from error
        if address.is_unspecified or address.is_multicast:
            raise ValidationError(
                "listener bind address cannot be wildcard or multicast"
            )
        if not address.is_private:
            raise ValidationError("listener bind address must be private")
        if not 0 <= self.port <= 65_535:
            raise ValidationError("listener port is outside the supported range")
        if self.port == 0 and not address.is_loopback:
            raise ValidationError("ephemeral listener ports are test-only")
        _validate_authority(self.authority)
        if not 1.0 <= self.request_timeout_seconds <= 30.0:
            raise ValidationError(
                "listener request timeout is outside the supported range"
            )


def build_server_ssl_context(
    configuration: AgentListenerConfiguration,
) -> ssl.SSLContext:
    """Load exact TLS files into a TLS 1.3, client-certificate-required context."""

    certificate = _real_file(configuration.server_certificate, "server certificate")
    private_key = _real_file(configuration.server_private_key, "server private key")
    endpoint_ca = _real_file(
        configuration.endpoint_ca_certificate, "endpoint CA certificate"
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    context.options |= ssl.OP_NO_TICKET
    context.num_tickets = 0
    context.load_cert_chain(certfile=certificate, keyfile=private_key)
    context.load_verify_locations(cafile=endpoint_ca)
    return context


def create_agent_web_application(
    store: AgentMessageStore,
    *,
    authority: str,
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> web.Application:
    """Create the agent-only aiohttp adapter without opening a socket."""

    _validate_authority(authority)
    if not 1.0 <= request_timeout_seconds <= 30.0:
        raise ValidationError("listener request timeout is outside the supported range")
    adapter = _AgentTLSAdapter(
        AgentMessageApplication(store),
        authority=authority,
        request_timeout_seconds=request_timeout_seconds,
    )
    application = web.Application(
        client_max_size=MAX_ENCODED_MESSAGE_BYTES + 1,
        handler_args={
            "auto_decompress": False,
            "max_headers": MAX_HEADER_COUNT,
            "max_line_size": MAX_HEADER_BYTES,
            "max_field_size": MAX_HEADER_BYTES,
            "read_bufsize": MAX_ENCODED_MESSAGE_BYTES + 1,
            "header_timeout_seconds": request_timeout_seconds,
        },
    )
    application.router.add_route("*", "/{path:.*}", adapter.handle)
    application.on_response_prepare.append(_prepare_response)
    return application


class _BoundedTLSSite(web.TCPSite):
    """Create TLS sockets with an explicit pre-HTTP handshake deadline."""

    __slots__ = ("_handshake_timeout_seconds",)

    def __init__(
        self,
        runner: web.BaseRunner,
        *,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext,
        backlog: int,
        reuse_address: bool,
        reuse_port: bool,
        handshake_timeout_seconds: float,
    ) -> None:
        super().__init__(
            runner,
            host=host,
            port=port,
            ssl_context=ssl_context,
            backlog=backlog,
            reuse_address=reuse_address,
            reuse_port=reuse_port,
        )
        self._handshake_timeout_seconds = handshake_timeout_seconds

    async def start(self) -> None:
        await web.BaseSite.start(self)
        loop = asyncio.get_running_loop()
        server = self._runner.server
        if server is None:
            raise RuntimeError("listener runner has no server")
        self._server = await loop.create_server(
            server,
            self._host,
            self._port,
            ssl=self._ssl_context,
            ssl_handshake_timeout=self._handshake_timeout_seconds,
            backlog=self._backlog,
            reuse_address=self._reuse_address,
            reuse_port=self._reuse_port,
        )
        if self._server.sockets:
            self._bound_port = self._server.sockets[0].getsockname()[1]
        else:
            self._bound_port = self._port


class AgentTLSListener:
    """Lifecycle wrapper used by a service entry point and loopback tests."""

    def __init__(
        self,
        configuration: AgentListenerConfiguration,
        store: AgentMessageStore,
    ) -> None:
        self._configuration = configuration
        self._application = create_agent_web_application(
            store,
            authority=configuration.authority,
            request_timeout_seconds=configuration.request_timeout_seconds,
        )
        self._runner: web.AppRunner | None = None

    @property
    def addresses(self) -> tuple[tuple[str, int], ...]:
        if self._runner is None:
            return ()
        return tuple((str(host), int(port)) for host, port in self._runner.addresses)

    async def start(self) -> None:
        if self._runner is not None:
            raise RuntimeError("agent listener is already started")
        runner = _HardenedAppRunner(
            self._application,
            access_log=None,
            keepalive_timeout=1.0,
            handler_cancellation=True,
            shutdown_timeout=5.0,
        )
        await runner.setup()
        try:
            site = _BoundedTLSSite(
                runner,
                host=self._configuration.bind_address,
                port=self._configuration.port,
                ssl_context=build_server_ssl_context(self._configuration),
                backlog=32,
                reuse_address=True,
                reuse_port=False,
                handshake_timeout_seconds=(self._configuration.request_timeout_seconds),
            )
            await site.start()
        except BaseException:
            await runner.cleanup()
            raise
        self._runner = runner

    async def close(self) -> None:
        runner, self._runner = self._runner, None
        if runner is not None:
            await runner.cleanup()


class _AgentTLSAdapter:
    def __init__(
        self,
        application: AgentMessageApplication,
        *,
        authority: str,
        request_timeout_seconds: float,
    ) -> None:
        self._application = application
        self._authority = authority
        self._request_timeout_seconds = request_timeout_seconds
        self._request_slots = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self._active_identity_requests: dict[UUID, int] = {}
        self._rate_limiter = _AgentRateLimiter()

    async def handle(self, request: web.Request) -> web.Response:
        received_at = datetime.now(UTC)
        if request.version != HttpVersion11:
            return _response(505, b'{"error":"http_version_not_supported"}')
        if _single_header(request, "Host") != self._authority:
            return _response(421, b'{"error":"misdirected_request"}')
        operation_task: asyncio.Task[AgentMessageResponse] | None = None
        admitted_endpoint_id: UUID | None = None
        try:
            async with asyncio.timeout(self._request_timeout_seconds):
                ssl_object = (
                    request.transport.get_extra_info("ssl_object")
                    if request.transport
                    else None
                )
                try:
                    peer = extract_verified_client_certificate(ssl_object)
                except ValidationError:
                    return _response(403, b'{"error":"unauthorized"}')
                if not self._rate_limiter.allow(
                    peer.endpoint_id, asyncio.get_running_loop().time()
                ):
                    return _response(429, b'{"error":"rate_limited"}')
                content_type = _single_header(request, "Content-Type")
                content_encoding = _single_optional_header(request, "Content-Encoding")
                if content_type is None or content_encoding is _DUPLICATE_HEADER:
                    return _response(400, b'{"error":"invalid_headers"}')
                active_for_identity = self._active_identity_requests.get(
                    peer.endpoint_id, 0
                )
                if (
                    self._request_slots.locked()
                    or active_for_identity >= MAX_CONCURRENT_REQUESTS_PER_IDENTITY
                ):
                    return _response(503, b'{"error":"listener_busy"}')
                await self._request_slots.acquire()
                self._active_identity_requests[peer.endpoint_id] = (
                    active_for_identity + 1
                )
                admitted_endpoint_id = peer.endpoint_id
                body = await request.read()
                operation_task = asyncio.create_task(
                    asyncio.to_thread(
                        self._application.handle,
                        AgentMessageRequest(
                            method=request.method,
                            path=request.raw_path,
                            content_type=content_type,
                            content_encoding=(
                                None
                                if content_encoding is None
                                else str(content_encoding)
                            ),
                            body=body,
                        ),
                        peer=peer,
                        received_at=received_at,
                    )
                )
                result = await asyncio.shield(operation_task)
        except web.HTTPRequestEntityTooLarge:
            return _response(413, b'{"error":"request_too_large"}')
        except TimeoutError:
            if (
                operation_task is not None
                and not operation_task.done()
                and admitted_endpoint_id is not None
            ):
                operation_task.add_done_callback(
                    partial(
                        self._release_request_slot_after_task,
                        endpoint_id=admitted_endpoint_id,
                    )
                )
                admitted_endpoint_id = None
            return _response(408, b'{"error":"request_timeout"}')
        except (ConnectionError, asyncio.CancelledError):
            if (
                operation_task is not None
                and not operation_task.done()
                and admitted_endpoint_id is not None
            ):
                operation_task.add_done_callback(
                    partial(
                        self._release_request_slot_after_task,
                        endpoint_id=admitted_endpoint_id,
                    )
                )
                admitted_endpoint_id = None
            raise
        finally:
            if admitted_endpoint_id is not None:
                self._release_request_slot(admitted_endpoint_id)

        return _application_response(result)

    def _release_request_slot(self, endpoint_id: UUID) -> None:
        active = self._active_identity_requests.get(endpoint_id)
        if active is None or active < 1:
            raise AssertionError("request admission accounting is inconsistent")
        if active == 1:
            del self._active_identity_requests[endpoint_id]
        else:
            self._active_identity_requests[endpoint_id] = active - 1
        self._request_slots.release()

    def _release_request_slot_after_task(
        self,
        _task: asyncio.Task[AgentMessageResponse],
        *,
        endpoint_id: UUID,
    ) -> None:
        self._release_request_slot(endpoint_id)


class _AgentRateLimiter:
    """Bound valid-certificate request rate without trusting database state."""

    def __init__(self) -> None:
        self._global: deque[float] = deque()
        self._identities: OrderedDict[UUID, deque[float]] = OrderedDict()

    def allow(self, endpoint_id: UUID, now: float) -> bool:
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        _discard_before(self._global, cutoff)
        identity = self._identities.get(endpoint_id)
        if identity is None:
            if len(self._identities) >= MAX_TRACKED_IDENTITIES:
                self._identities.popitem(last=False)
            identity = deque()
            self._identities[endpoint_id] = identity
        else:
            self._identities.move_to_end(endpoint_id)
        _discard_before(identity, cutoff)
        if (
            len(self._global) >= MAX_GLOBAL_REQUESTS_PER_WINDOW
            or len(identity) >= MAX_REQUESTS_PER_IDENTITY_WINDOW
        ):
            return False
        self._global.append(now)
        identity.append(now)
        return True


def _discard_before(values: deque[float], cutoff: float) -> None:
    while values and values[0] <= cutoff:
        values.popleft()


class _ConnectionAdmission:
    """Bound post-handshake connections before the HTTP parser receives bytes."""

    def __init__(self) -> None:
        self._active = 0
        self._active_by_identity: dict[UUID, int] = {}

    def acquire(self, endpoint_id: UUID) -> bool:
        active_for_identity = self._active_by_identity.get(endpoint_id, 0)
        if (
            self._active >= MAX_CONCURRENT_REQUESTS
            or active_for_identity >= MAX_CONCURRENT_REQUESTS_PER_IDENTITY
        ):
            return False
        self._active += 1
        self._active_by_identity[endpoint_id] = active_for_identity + 1
        return True

    def release(self, endpoint_id: UUID) -> None:
        active_for_identity = self._active_by_identity.get(endpoint_id)
        if self._active < 1 or active_for_identity is None:
            raise AssertionError("connection admission accounting is inconsistent")
        self._active -= 1
        if active_for_identity == 1:
            del self._active_by_identity[endpoint_id]
        else:
            self._active_by_identity[endpoint_id] = active_for_identity - 1


def extract_verified_client_certificate(
    ssl_object: PeerCertificate | None,
) -> VerifiedClientCertificate:
    """Extract exact endpoint identity facts from a TLS-verified leaf certificate."""

    if ssl_object is None or ssl_object.version() != "TLSv1.3":
        raise ValidationError("verified TLS 1.3 client certificate is required")
    encoded = ssl_object.getpeercert(binary_form=True)
    if not isinstance(encoded, bytes) or not encoded:
        raise ValidationError("verified client certificate is required")
    try:
        certificate = x509.load_der_x509_certificate(encoded)
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except (ValueError, x509.ExtensionNotFound, x509.DuplicateExtension) as error:
        raise ValidationError("client certificate profile is invalid") from error
    if constraints.ca or not usage.digital_signature:
        raise ValidationError("client certificate purpose is invalid")
    if tuple(extended) != (ExtendedKeyUsageOID.CLIENT_AUTH,):
        raise ValidationError("client certificate extended purpose is invalid")
    general_names = list(names)
    if len(general_names) != 1 or not isinstance(
        general_names[0], x509.UniformResourceIdentifier
    ):
        raise ValidationError("client certificate endpoint identity is invalid")
    endpoint_value = general_names[0].value
    if not endpoint_value.startswith(ENDPOINT_URI_PREFIX):
        raise ValidationError("client certificate endpoint identity is invalid")
    endpoint_text = endpoint_value.removeprefix(ENDPOINT_URI_PREFIX)
    try:
        endpoint_id = UUID(endpoint_text)
    except ValueError as error:
        raise ValidationError(
            "client certificate endpoint identity is invalid"
        ) from error
    if str(endpoint_id) != endpoint_text:
        raise ValidationError("client certificate endpoint identity is not canonical")
    for extension in certificate.extensions:
        if extension.critical and isinstance(
            extension.value, x509.UnrecognizedExtension
        ):
            raise ValidationError(
                "client certificate has an unknown critical extension"
            )
    public_key = certificate.public_key()
    if not _supported_public_key(public_key):
        raise ValidationError("client certificate public key is unsupported")
    subject_public_key = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return VerifiedClientCertificate(
        endpoint_id=endpoint_id,
        public_key_fingerprint="sha256:"
        + hashlib.sha256(subject_public_key).hexdigest(),
    )


def _supported_public_key(key: object) -> bool:
    if isinstance(key, ed25519.Ed25519PublicKey):
        return True
    if isinstance(key, ec.EllipticCurvePublicKey):
        return isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1))
    return isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2_048


def _real_file(path: Path, label: str) -> str:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValidationError(f"{label} must be an absolute real file")
    return str(path.resolve(strict=True))


def _validate_authority(authority: str) -> None:
    if (
        not authority
        or not authority.isascii()
        or authority != authority.lower()
        or any(character.isspace() or character in "/?#@" for character in authority)
    ):
        raise ValidationError("listener authority is invalid")
    try:
        parsed = urlsplit("//" + authority)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValidationError("listener authority is invalid") from error
    if hostname is None or parsed.username is not None or parsed.password is not None:
        raise ValidationError("listener authority is invalid")
    if port is not None and not 1 <= port <= 65_535:
        raise ValidationError("listener authority is invalid")
    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass
    if len(hostname) > 253 or hostname.endswith("."):
        raise ValidationError("listener authority is invalid")
    for label in hostname.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(
                not (character.isascii() and character.isalnum()) and character != "-"
                for character in label
            )
        ):
            raise ValidationError("listener authority is invalid")


class _DuplicateHeader:
    pass


_DUPLICATE_HEADER = _DuplicateHeader()


def _header_values(request: web.Request, name: str) -> list[str]:
    return list(request.headers.getall(name, []))


def _single_header(request: web.Request, name: str) -> str | None:
    values = _header_values(request, name)
    return values[0] if len(values) == 1 else None


def _single_optional_header(
    request: web.Request, name: str
) -> str | _DuplicateHeader | None:
    values = _header_values(request, name)
    if not values:
        return None
    if len(values) != 1:
        return _DUPLICATE_HEADER
    return values[0]


def _application_response(result: AgentMessageResponse) -> web.Response:
    return _response(result.status, result.body, headers=result.headers)


def _response(
    status: int,
    body: bytes,
    *,
    headers: Iterable[tuple[str, str]] = (),
) -> web.Response:
    response = web.Response(status=status, body=body, headers=headers)
    response.headers.setdefault("Content-Type", "application/json")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.force_close()
    return response


async def _prepare_response(
    _request: web.Request, response: web.StreamResponse
) -> None:
    response.headers.pop("Server", None)
    response.headers["X-Content-Type-Options"] = "nosniff"


class _NoServerResponse(web.Response):
    async def _prepare_headers(self) -> None:
        await super()._prepare_headers()
        self.headers.pop("Server", None)


class _HardenedRequestHandler(RequestHandler):
    """Return bounded generic parser errors without framework version headers."""

    def __init__(
        self,
        *args: object,
        header_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        connection_admission: _ConnectionAdmission,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._header_timeout_seconds = header_timeout_seconds
        self._header_timeout_handle: asyncio.TimerHandle | None = None
        self._connection_admission = connection_admission
        self._admitted_endpoint_id: UUID | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        super().connection_made(transport)
        ssl_object = cast(asyncio.Transport, transport).get_extra_info("ssl_object")
        try:
            peer = extract_verified_client_certificate(ssl_object)
        except ValidationError:
            self.force_close()
            return
        if not self._connection_admission.acquire(peer.endpoint_id):
            self.force_close()
            return
        self._admitted_endpoint_id = peer.endpoint_id
        self._header_timeout_handle = self._loop.call_later(
            self._header_timeout_seconds, self._expire_incomplete_headers
        )

    def data_received(self, data: bytes) -> None:
        super().data_received(data)
        if self._messages:
            self._cancel_header_timeout()

    def connection_lost(self, exc: BaseException | None) -> None:
        self._cancel_header_timeout()
        if self._admitted_endpoint_id is not None:
            self._connection_admission.release(self._admitted_endpoint_id)
            self._admitted_endpoint_id = None
        super().connection_lost(exc)

    def _expire_incomplete_headers(self) -> None:
        self._header_timeout_handle = None
        if not self._messages and self.transport is not None:
            self.force_close()

    def _cancel_header_timeout(self) -> None:
        if self._header_timeout_handle is not None:
            self._header_timeout_handle.cancel()
            self._header_timeout_handle = None

    def handle_error(
        self,
        request: web.BaseRequest,
        status: int = 500,
        exc: BaseException | None = None,
        message: str | None = None,
    ) -> web.StreamResponse:
        del request, exc, message
        response = _NoServerResponse(
            status=status,
            body=b'{"error":"invalid_request"}',
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )
        response.force_close()
        return response


class _HardenedServer(Server):
    """Fail closed instead of falling back to aiohttp's default protocol."""

    def __init__(
        self,
        handler: Callable[[web.BaseRequest], Awaitable[web.StreamResponse]],
        **kwargs: object,
    ) -> None:
        super().__init__(handler, **kwargs)  # type: ignore[arg-type]
        self._connection_admission = _ConnectionAdmission()

    def __call__(self) -> RequestHandler:
        return _HardenedRequestHandler(
            self,
            loop=self._loop,
            connection_admission=self._connection_admission,
            **self._kwargs,
        )


class _HardenedAppRunner(web.AppRunner):
    """Pin parser errors to the hardened protocol response.

    aiohttp does not route parser-generated responses through application hooks.
    The exact dependency version is pinned, and loopback tests exercise this
    small integration seam so an upstream API change fails closed on upgrade.
    """

    async def _make_server(self) -> Server:
        loop = asyncio.get_running_loop()
        application = self.app
        application._set_loop(loop)
        application.on_startup.freeze()
        await application.startup()
        application.freeze()
        handler = cast(
            Callable[[web.BaseRequest], Awaitable[web.StreamResponse]],
            application._handle,
        )
        options = dict(self._kwargs)
        options["debug"] = application._debug
        if application._handler_args:
            options.update(application._handler_args)
        return _HardenedServer(
            handler,
            request_factory=application._make_request,
            loop=loop,
            **options,
        )
