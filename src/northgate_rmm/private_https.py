"""Pinned private-network HTTPS transport for separated workload clients."""

from __future__ import annotations

import http.client
import io
import socket
import ssl
import time
from pathlib import Path
from typing import Any, BinaryIO, cast

from northgate_rmm.secure_files import private_key_reference, regular_file_reference

MAX_TLS_CERTIFICATE_FILE_BYTES = 65_536


def build_mtls_client_context(
    *,
    ca_certificate: Path,
    client_certificate: Path,
    client_private_key: Path,
    ca_label: str,
    certificate_label: str,
    private_key_label: str,
) -> ssl.SSLContext:
    """Build a TLS 1.3 workload context from held, no-follow file references."""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.options |= ssl.OP_NO_TICKET
    with regular_file_reference(
        ca_certificate,
        label=ca_label,
        maximum_bytes=MAX_TLS_CERTIFICATE_FILE_BYTES,
        private=False,
    ) as ca_path:
        context.load_verify_locations(cafile=str(ca_path))
    with (
        regular_file_reference(
            client_certificate,
            label=certificate_label,
            maximum_bytes=MAX_TLS_CERTIFICATE_FILE_BYTES,
            private=False,
        ) as certificate_path,
        private_key_reference(
            client_private_key,
            label=private_key_label,
        ) as key_path,
    ):
        context.load_cert_chain(
            certfile=str(certificate_path),
            keyfile=str(key_path),
        )
    return context


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to one IP while validating an independent DNS TLS authority."""

    def __init__(
        self,
        *,
        connect_address: str,
        port: int,
        authority: str,
        timeout_seconds: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            authority,
            port=port,
            timeout=float(timeout_seconds),
            context=context,
        )
        self._connect_address = connect_address
        self._ssl_context = context
        self._deadline = time.monotonic() + float(timeout_seconds)

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._connect_address, self.port),
            _remaining(self._deadline),
        )
        try:
            raw_socket.settimeout(_remaining(self._deadline))
            secured_socket = self._ssl_context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
            self.sock = cast(
                socket.socket,
                DeadlineSocket(secured_socket, deadline=self._deadline),
            )
        except BaseException:
            raw_socket.close()
            raise


class DeadlineSocket:
    """Re-arm each socket operation with the remaining whole-request budget."""

    def __init__(self, wrapped: ssl.SSLSocket, *, deadline: float) -> None:
        self._wrapped = wrapped
        self._deadline = deadline

    def sendall(self, data: bytes, flags: int = 0) -> None:
        self._arm()
        self._wrapped.sendall(data, flags)

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        self._arm()
        return self._wrapped.recv_into(buffer, nbytes, flags)

    def makefile(
        self,
        mode: str,
        buffering: int | None = None,
    ) -> BinaryIO:
        if mode != "rb":
            raise ValueError("private HTTPS socket supports response reads only")
        size = io.DEFAULT_BUFFER_SIZE if buffering in (None, -1) else buffering
        return io.BufferedReader(_DeadlineReader(self), buffer_size=size)

    def close(self) -> None:
        self._wrapped.close()

    def _arm(self) -> None:
        self._wrapped.settimeout(_remaining(self._deadline))


class _DeadlineReader(io.RawIOBase):
    def __init__(self, deadline_socket: DeadlineSocket) -> None:
        super().__init__()
        self._deadline_socket = deadline_socket

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        return self._deadline_socket.recv_into(buffer)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("private HTTPS request deadline expired")
    return remaining


def http_authority(authority: str, port: int) -> str:
    return authority if port == 443 else f"{authority}:{port}"
