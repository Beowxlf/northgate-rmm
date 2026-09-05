"""Bounded private TLS service shared by isolated trust-plane workloads."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import signal
import ssl
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from aiohttp import web

from northgate_rmm.agent_service import (
    _read_regular_file,
    _require_unprivileged_process,
)
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.listener import _BoundedTLSSite, _HardenedAppRunner
from northgate_rmm.secure_files import private_key_reference, regular_file_reference

Operation = Callable[[str, bytes, str | None], tuple[int, dict[str, Any]]]


def strict_object(raw: bytes, *, maximum: int = 65536) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError("duplicate JSON field")
            result[key] = value
        return result

    def reject(_value: str) -> None:
        raise ValidationError("non-finite JSON number")

    if not 0 < len(raw) <= maximum:
        raise ValidationError("JSON size is invalid")
    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject
    )
    if type(value) is not dict:
        raise ValidationError("JSON object required")
    return value


def load_configuration(path: Path) -> dict[str, Any]:
    return strict_object(
        _read_regular_file(
            path, label="workload configuration", maximum_bytes=65536, private=False
        )
    )


def read_private(path: str, maximum: int = 65536) -> bytes:
    return _read_regular_file(
        Path(path), label="workload credential", maximum_bytes=maximum, private=True
    )


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


async def serve(
    configuration: dict[str, Any], operation: Operation, paths: frozenset[str]
) -> None:
    _require_unprivileged_process()
    bind = ipaddress.ip_address(configuration["bind_address"])
    permitted = (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
    )
    if not any(bind in ipaddress.ip_network(network) for network in permitted):
        raise ValidationError("workload bind must be private")
    port = configuration["port"]
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValidationError("workload port invalid")
    allowed = configuration["allowed_client_sha256"]
    if (
        type(allowed) is not list
        or not 1 <= len(allowed) <= 16
        or any(
            type(item) is not str
            or len(item) != 64
            or any(char not in "0123456789abcdef" for char in item)
            for item in allowed
        )
    ):
        raise ValidationError("exact workload certificate pins required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_TICKET
    with regular_file_reference(
        Path(configuration["client_ca_certificate"]),
        label="workload client root",
        maximum_bytes=65536,
        private=False,
    ) as ca:
        context.load_verify_locations(cafile=str(ca))
    with (
        regular_file_reference(
            Path(configuration["server_certificate"]),
            label="workload server certificate",
            maximum_bytes=65536,
            private=False,
        ) as certificate,
        private_key_reference(
            Path(configuration["server_private_key"]), label="workload server key"
        ) as key,
    ):
        context.load_cert_chain(str(certificate), str(key))
    slots = asyncio.Semaphore(8)

    async def handle(request: web.Request) -> web.Response:
        response: dict[str, Any] = {"error": "request_rejected"}
        status = 403
        task: asyncio.Task[tuple[int, dict[str, Any]]] | None = None
        acquired = False
        try:
            async with asyncio.timeout(10):
                if (
                    request.method != "POST"
                    or request.path not in paths
                    or request.query_string
                ):
                    raise ValidationError("route rejected")
                if request.headers.getall("Host", []) != [configuration["authority"]]:
                    raise ValidationError("authority rejected")
                if request.headers.getall("Content-Type", []) not in (
                    [],
                    ["application/json"],
                ):
                    raise ValidationError("content type rejected")
                if request.headers.get("Content-Encoding") or request.headers.get(
                    "Transfer-Encoding"
                ):
                    raise ValidationError("encoding rejected")
                credentials = request.headers.getall("Authorization", [])
                if len(credentials) > 1 or (credentials and len(credentials[0]) > 4096):
                    raise ValidationError("authorization rejected")
                tls = (
                    request.transport.get_extra_info("ssl_object")
                    if request.transport
                    else None
                )
                certificate = tls.getpeercert(binary_form=True) if tls else None
                if (
                    not certificate
                    or hashlib.sha256(certificate).hexdigest() not in allowed
                ):
                    raise AuthorizationError("workload rejected")
                if slots.locked():
                    raise ValidationError("workload busy")
                await slots.acquire()
                acquired = True
                body = await request.read()
                task = asyncio.create_task(
                    asyncio.to_thread(
                        operation,
                        request.path,
                        body,
                        credentials[0] if credentials else None,
                    )
                )
                status, response = await asyncio.shield(task)
        except Exception:
            print("workload request rejected", file=sys.stderr)
        finally:
            if acquired:
                if task is not None and not task.done():

                    def release(
                        completed: asyncio.Task[tuple[int, dict[str, Any]]],
                    ) -> None:
                        if not completed.cancelled():
                            completed.exception()
                        slots.release()

                    task.add_done_callback(release)
                else:
                    slots.release()
        encoded = canonical(response)
        if len(encoded) > 65536:
            status, encoded = 503, b'{"error":"response_unavailable"}'
        result = web.Response(
            status=status,
            body=encoded,
            content_type="application/json",
            headers={"Cache-Control": "no-store"},
        )
        result.force_close()
        return result

    app = web.Application(
        client_max_size=65536,
        handler_args={
            "auto_decompress": False,
            "max_headers": 32,
            "max_line_size": 8192,
            "max_field_size": 8192,
            "read_bufsize": 65536,
            "header_timeout_seconds": 5,
        },
    )
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = _HardenedAppRunner(
        app,
        access_log=None,
        keepalive_timeout=1,
        shutdown_timeout=15,
        handler_cancellation=True,
    )
    await runner.setup()
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stopped.set)
            installed.append(sig)
        site = _BoundedTLSSite(
            runner,
            host=str(bind),
            port=port,
            ssl_context=context,
            backlog=32,
            reuse_address=True,
            reuse_port=False,
            handshake_timeout_seconds=5,
        )
        await site.start()
        await stopped.wait()
    finally:
        await runner.cleanup()
        for sig in installed:
            loop.remove_signal_handler(sig)


def service_main(
    factory: Callable[[dict[str, Any]], tuple[Operation, frozenset[str]]],
    argv: Sequence[str] | None = None,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _require_unprivileged_process()
        configuration = load_configuration(args.config)
        operation, paths = factory(configuration)
        asyncio.run(serve(configuration, operation, paths))
    except Exception:
        print(
            "workload stopped: configuration or dependency unavailable", file=sys.stderr
        )
        return 1
    return 0
