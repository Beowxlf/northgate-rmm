from __future__ import annotations

import asyncio
import os
import struct
from collections.abc import Callable, Coroutine
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec
from uuid import UUID

import pytest

from northgate_rmm import credential_rdp as module
from northgate_rmm.credential_rdp import FreeRDPNLAVerifier
from northgate_rmm.remote_policy import RemoteTarget

TARGET = RemoteTarget(UUID(int=1), UUID(int=2), "10.10.150.24", "rdp", 3389)
PARAMETERS = {"security": "nla", "cert-fingerprints": "sha256:" + ":".join(["ab"] * 32)}
FIELDS = {
    "username": "rmmremote",
    "domain": "NG-RMM-WIN01",
    "password": "Synthetic-Only!9",
}
SUCCESS = (
    b"[INFO][com.freerdp.core] - [freerdp_connect]: "
    b"Authentication only, exit status 0\n"
)
P = ParamSpec("P")


def async_test(function: Callable[P, Coroutine[Any, Any, None]]) -> Callable[P, None]:
    @wraps(function)
    def run(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(function(*args, **kwargs))

    return run


def test_only_fixed_nla_arguments_and_password_stdin() -> None:
    arguments, stdin = FreeRDPNLAVerifier._arguments(TARGET, PARAMETERS, FIELDS)
    assert stdin == b"Synthetic-Only!9\n"
    assert FIELDS["password"] not in repr(arguments)
    assert "/sec:nla" in arguments and "+auth-only" in arguments
    assert "/from-stdin:force" in arguments
    assert "/cert:fingerprint:" + PARAMETERS["cert-fingerprints"] in arguments
    assert not any(
        "ignore" in item or "tofu" in item or item.startswith("/p:")
        for item in arguments
    )
    extra = {
        **PARAMETERS,
        "hostname": "203.0.113.1",
        "password": "not-the-candidate",
        "drive-path": "/",
    }
    assert FreeRDPNLAVerifier._arguments(TARGET, extra, FIELDS) == (arguments, stdin)


@pytest.mark.parametrize(
    "change",
    [
        {"security": "tls"},
        {"security": "nla-ext"},
        {"cert-fingerprints": ""},
        {"cert-fingerprints": PARAMETERS["cert-fingerprints"] + ",sha256:other"},
        {"ignore-cert": "true"},
        {"cert-tofu": "true"},
        {"disable-auth": "true"},
    ],
)
def test_rejects_unpinned_or_fallback_authentication(change: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        FreeRDPNLAVerifier._arguments(TARGET, dict(PARAMETERS, **change), FIELDS)


@pytest.mark.parametrize(
    "change",
    [
        {"username": "user\n+auth-only"},
        {"domain": ""},
        {"domain": "DOMAIN\\user"},
        {"password": ""},
        {"password": "candidate\nsecond"},
        {"password": "x" * 129},
        {"password": "contains\x00nul"},
        {"password": "contains space"},
    ],
)
def test_rejects_ambiguous_or_truncated_credentials(change: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        FreeRDPNLAVerifier._arguments(TARGET, PARAMETERS, dict(FIELDS, **change))


class Stdin:
    def __init__(self) -> None:
        self.value = b""
        self.closed = False

    def write(self, value: bytes) -> None:
        self.value += value

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class Process:
    def __init__(self, output: bytes, status: int, *, running: bool = False) -> None:
        self.stdin = Stdin()
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(output)
        if not running:
            self.stdout.feed_eof()
        self.returncode = None if running else status
        self.status = status
        self.pid = 87654321
        self.stopped = asyncio.Event()
        if not running:
            self.stopped.set()

    async def wait(self) -> int:
        await self.stopped.wait()
        self.returncode = self.status
        return self.status


@pytest.mark.parametrize(
    ("output", "status", "expected"),
    [
        (SUCCESS, 0, True),
        (SUCCESS, 1, False),
        (b"ready\nimg\nsync\n", 0, False),
        (b"[com.freerdp.client.x11] Authentication only, exit status 0\n", 0, False),
        (SUCCESS + b"Authentication only, exit status 1\n", 0, False),
        (b"[com.freerdp.core] Authentication only, exit status 1\n", 1, False),
        (b"[com.freerdp.core] Authentication only, exit status 01\n", 0, False),
        (SUCCESS + b"x" * module._OUTPUT_LIMIT, 0, False),
    ],
    ids=[
        "success",
        "bad-exit",
        "display-only",
        "frontend-only",
        "conflicting-status",
        "failed-auth",
        "ambiguous-status",
        "output-budget",
    ],
)
@async_test
async def test_fresh_authentication_witness_and_no_secret_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    output: bytes,
    status: int,
    expected: bool,
) -> None:
    binary = tmp_path / "qualified"
    binary.write_bytes(b"synthetic fixture")
    verifier = FreeRDPNLAVerifier(binary, "a" * 64)
    monkeypatch.setattr(
        verifier, "_open_executable", lambda: os.open(binary, os.O_RDONLY)
    )
    process = Process(output, status)
    calls = []

    async def spawn(*args: object, **kwargs: object) -> Process:
        calls.append((args, kwargs))
        assert FIELDS["password"] not in repr(args) + repr(kwargs)
        assert kwargs["start_new_session"] is True
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert "DISPLAY" not in environment and "LD_PRELOAD" not in environment
        assert environment["KRB5CCNAME"].startswith("FILE:")
        return process

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    assert (
        await verifier.verify(target=TARGET, parameters=PARAMETERS, fields=FIELDS)
        is expected
    )
    assert len(calls) == 1
    assert process.stdin.value == (FIELDS["password"] + "\n").encode()
    assert process.stdin.closed
    assert capsys.readouterr() == ("", "")


@async_test
async def test_unavailable_binary_fails_before_credentials_leave_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = FreeRDPNLAVerifier(tmp_path / "absent", "a" * 64)

    async def forbidden_spawn(*args: object, **kwargs: object) -> None:
        raise AssertionError("unqualified executable launched")

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", forbidden_spawn)
    assert not await verifier.verify(
        target=TARGET, parameters=PARAMETERS, fields=FIELDS
    )


@async_test
async def test_deadline_kills_process_and_discards_possible_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "qualified"
    binary.write_bytes(b"synthetic fixture")
    verifier = FreeRDPNLAVerifier(binary, "a" * 64, timeout_seconds=1)
    monkeypatch.setattr(
        verifier, "_open_executable", lambda: os.open(binary, os.O_RDONLY)
    )
    process = Process(SUCCESS, 0, running=True)
    killed = []

    async def spawn(*args: object, **kwargs: object) -> Process:
        return process

    def kill(pid: int, sig: int) -> None:
        killed.append(pid)
        process.status = -9
        process.stopped.set()
        process.stdout.feed_eof()

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(module.os, "killpg", kill, raising=False)
    monkeypatch.setattr(module.signal, "SIGKILL", 9, raising=False)
    assert not await verifier.verify(
        target=TARGET, parameters=PARAMETERS, fields=FIELDS
    )
    assert killed == [process.pid]
    assert process.returncode == -9


def test_verifier_configuration_must_be_bounded_and_pinned(tmp_path: Path) -> None:
    for path, digest, timeout in [
        (Path("relative"), "a" * 64, 10),
        (tmp_path, "unknown", 10),
        (tmp_path, "a" * 64, 31),
    ]:
        with pytest.raises(ValueError):
            FreeRDPNLAVerifier(path, digest, timeout_seconds=timeout)


def test_xauthority_contains_private_cookie_and_exact_display(tmp_path: Path) -> None:
    path = tmp_path / "authority"
    cookie = bytes(range(32))
    FreeRDPNLAVerifier._authority(path, cookie, "271")
    raw = path.read_bytes()
    assert struct.unpack("!H", raw[:2])[0] == 65535
    fields = []
    offset = 2
    for _ in range(4):
        size = struct.unpack("!H", raw[offset : offset + 2])[0]
        offset += 2
        fields.append(raw[offset : offset + size])
        offset += size
    assert fields == [b"", b"271", b"MIT-MAGIC-COOKIE-1", cookie]
    assert offset == len(raw)
    with pytest.raises(FileExistsError):
        FreeRDPNLAVerifier._authority(path, b"replacement")


@pytest.mark.parametrize(
    "invalid",
    [
        (None, "a" * 64),
        ("/qualified/Xvfb", None),
        ("relative", "a" * 64),
        ("/qualified/Xvfb", "bad"),
    ],
)
def test_xvfb_configuration_is_explicit_and_qualified(
    tmp_path: Path, invalid: tuple[str | None, str | None]
) -> None:
    with pytest.raises(ValueError):
        FreeRDPNLAVerifier(
            tmp_path / "client",
            "a" * 64,
            xvfb_executable=invalid[0],
            xvfb_sha256=invalid[1],
        )


@pytest.mark.parametrize(
    "behavior", ["success", "client-failed", "server-exit", "output-overflow", "cancel"]
)
@async_test
async def test_optional_xvfb_is_private_bounded_and_always_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
) -> None:
    binary, xvfb = tmp_path / "client", tmp_path / "Xvfb"
    binary.write_bytes(b"synthetic client")
    xvfb.write_bytes(b"synthetic display server")
    verifier = FreeRDPNLAVerifier(
        binary, "a" * 64, xvfb_executable=xvfb, xvfb_sha256="b" * 64, timeout_seconds=1
    )
    monkeypatch.setattr(
        verifier, "_open_executable", lambda: os.open(binary, os.O_RDONLY)
    )
    monkeypatch.setattr(
        verifier, "_open_binary", lambda path, digest: os.open(path, os.O_RDONLY)
    )
    process = Process(b"", 1, running=True)
    spawned, killed, auth_paths = [], [], []
    client_started = asyncio.Event()

    async def spawn(*args: object, **kwargs: object) -> Process:
        spawned.append(args)
        assert "-ac" not in args
        assert args[args.index("-nolisten") + 1] == "tcp"
        assert "-displayfd" in args and kwargs["start_new_session"] is True
        authority = Path(str(args[args.index("-auth") + 1]))
        auth_paths.append(authority)
        cookie = authority.read_bytes()[-16:]
        assert cookie.hex() not in repr(args) + repr(kwargs)
        assert FIELDS["password"] not in repr(args) + repr(kwargs)
        return process

    async def display_number(descriptor: int) -> str:
        os.close(descriptor)
        return "271"

    async def client(
        descriptor: int,
        arguments: list[str],
        password: bytes,
        display: dict[str, str] | None = None,
    ) -> bool:
        assert display is not None and display["DISPLAY"] == ":271"
        authority = Path(display["XAUTHORITY"])
        auth_paths.append(authority)
        assert authority.read_bytes()[-16:] == auth_paths[0].read_bytes()[-16:]
        assert password == (FIELDS["password"] + "\n").encode()
        client_started.set()
        if behavior == "server-exit":
            process.stopped.set()
            process.stdout.feed_eof()
            await asyncio.Event().wait()
        if behavior == "output-overflow":
            process.stdout.feed_data(b"x" * (module._OUTPUT_LIMIT + 1))
            await asyncio.Event().wait()
        if behavior == "cancel":
            await asyncio.Event().wait()
        return behavior == "success"

    def kill(pid: int, sig: int) -> None:
        killed.append(pid)
        process.status = -9
        process.stopped.set()
        process.stdout.feed_eof()

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(verifier, "_display_number", display_number)
    monkeypatch.setattr(verifier, "_run", client)
    monkeypatch.setattr(module.os, "killpg", kill, raising=False)
    monkeypatch.setattr(module.signal, "SIGKILL", 9, raising=False)
    task = asyncio.create_task(
        verifier.verify(target=TARGET, parameters=PARAMETERS, fields=FIELDS)
    )
    if behavior == "cancel":
        await client_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        assert await task is (behavior == "success")
    assert len(spawned) == 1
    assert killed or process.returncode is not None
    assert all(not path.exists() for path in auth_paths)


@pytest.mark.parametrize("bad_runtime", [False, True])
@async_test
async def test_preflight_checks_both_runtimes_without_sending_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_runtime: bool
) -> None:
    binary, xvfb = tmp_path / "client", tmp_path / "Xvfb"
    binary.write_bytes(b"synthetic client")
    xvfb.write_bytes(b"synthetic server")
    verifier = FreeRDPNLAVerifier(
        binary, "a" * 64, xvfb_executable=xvfb, xvfb_sha256="b" * 64
    )
    descriptors = []

    def open_binary(path: Path, digest: str) -> int:
        if path == xvfb and bad_runtime:
            raise OSError("synthetic runtime integrity failure")
        descriptor = os.open(path, os.O_RDONLY)
        descriptors.append(descriptor)
        return descriptor

    async def forbidden_spawn(*args: object, **kwargs: object) -> None:
        raise AssertionError("preflight sent credentials or launched a process")

    monkeypatch.setattr(verifier, "_open_binary", open_binary)
    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", forbidden_spawn)
    assert (
        await verifier.preflight(target=TARGET, parameters=PARAMETERS, fields=FIELDS)
        is not bad_runtime
    )
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert not await verifier.preflight(
        target=TARGET, parameters={"security": "tls"}, fields=FIELDS
    )
