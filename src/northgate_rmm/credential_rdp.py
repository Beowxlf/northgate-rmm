"""Fresh, pinned NLA password verification using an established FreeRDP client.

Guacd's ready/display messages can precede authentication. They are deliberately
not accepted as a password-rotation witness. Deployment must qualify the exact
FreeRDP executable with positive, wrong-password and wrong-pin controls before
constructing this optional verifier. This module never installs or enables it.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import secrets
import signal
import stat
import struct
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from northgate_rmm.remote_policy import RemoteTarget

_PIN = re.compile(r"sha256:(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}\Z")
_ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_DOMAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}\Z")
# Require the core connection result, not a frontend's ready/connected message.
# FreeRDP 2/3 package builds must be qualified for this exact witness format.
_SUCCESS = re.compile(
    rb"\[com\.freerdp\.core\][^\r\n]*Authentication only, exit status 0\r?$",
    re.MULTILINE,
)
_AUTH_RESULT = re.compile(rb"Authentication only, exit status (-?[0-9]+)")
_OUTPUT_LIMIT = 64 * 1024
_EXECUTABLE_LIMIT = 64 * 1024 * 1024


class FreeRDPNLAVerifier:
    """Linux server adapter; all configuration is deployment-owned.

    ``executable_sha256`` binds the positively and negatively qualified binary.
    Its resolved path and all parents must be root-owned and non-writable by
    group/others. A retained descriptor binds validation to the executed ELF.
    No arbitrary Guacamole parameters or caller command flags are forwarded.
    """

    def __init__(
        self,
        executable: str | Path,
        executable_sha256: str,
        *,
        timeout_seconds: float = 20,
        xvfb_executable: str | Path | None = None,
        xvfb_sha256: str | None = None,
    ) -> None:
        self.executable = Path(executable)
        if not self.executable.is_absolute() or not re.fullmatch(
            r"[0-9a-f]{64}", executable_sha256
        ):
            raise ValueError(
                "Verifier requires an absolute executable and qualified SHA256"
            )
        if not 1 <= timeout_seconds <= 30:
            raise ValueError("Verifier deadline must be between 1 and 30 seconds")
        self.executable_sha256 = executable_sha256
        self.timeout_seconds = timeout_seconds
        self.xvfb_executable = (
            Path(xvfb_executable) if xvfb_executable is not None else None
        )
        self.xvfb_sha256 = xvfb_sha256
        if (self.xvfb_executable is None) != (xvfb_sha256 is None) or (
            self.xvfb_executable is not None
            and (
                not self.xvfb_executable.is_absolute()
                or not re.fullmatch(r"[0-9a-f]{64}", xvfb_sha256 or "")
            )
        ):
            raise ValueError(
                "Optional Xvfb requires a qualified absolute path and SHA256"
            )
        self._slot = asyncio.Semaphore(1)

    def _open_executable(self) -> int:
        return self._open_binary(self.executable, self.executable_sha256)

    @staticmethod
    def _open_binary(executable: Path, expected_sha256: str) -> int:
        if os.name != "posix" or not Path("/proc/self/fd").is_dir():
            raise OSError("Verifier requires the Linux server runtime")
        if executable.resolve(strict=True) != executable:
            raise OSError("Verifier path must be resolved")
        for parent in executable.parents:
            info = parent.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise OSError("Verifier directory is not deployment-owned")
        descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o6022
                or not info.st_mode & 0o111
                or not 4 <= info.st_size <= _EXECUTABLE_LIMIT
            ):
                raise OSError("Verifier executable is not protected")
            digest = hashlib.sha256()
            size = 0
            while block := os.read(descriptor, 64 * 1024):
                if size == 0 and not block.startswith(b"\x7fELF"):
                    raise OSError("Verifier must be the qualified ELF client")
                size += len(block)
                if size > _EXECUTABLE_LIMIT:
                    raise OSError("Verifier executable exceeds budget")
                digest.update(block)
            after = os.fstat(descriptor)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or not hmac.compare_digest(digest.hexdigest(), expected_sha256):
                raise OSError("Verifier executable changed or is not qualified")
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @staticmethod
    def _arguments(
        target: RemoteTarget, parameters: dict[str, str], fields: dict[str, str]
    ) -> tuple[list[str], bytes]:
        if target.protocol != "rdp" or target.port != 3389:
            raise ValueError("Only enrolled RDP targets are supported")
        # Reconstruct to enforce real domain validation even at adapter boundaries.
        RemoteTarget(
            target.endpoint_id, target.identity_id, target.address, "rdp", 3389
        )
        pin = parameters.get("cert-fingerprints", "")
        if (
            not _PIN.fullmatch(pin)
            or parameters.get("security", "nla") != "nla"
            or any(
                parameters.get(key, "false").lower() != "false"
                for key in ("ignore-cert", "cert-tofu", "disable-auth")
            )
        ):
            raise ValueError("Verifier requires a single exact SHA256 pin and NLA")
        username, domain, password = (
            fields.get("username", ""),
            fields.get("domain", ""),
            fields.get("password", ""),
        )
        if not _ACCOUNT.fullmatch(username) or not _DOMAIN.fullmatch(domain):
            raise ValueError(
                "Verifier requires an explicit local account and machine domain"
            )
        # The rotation worker generates printable ASCII candidates. Do not admit
        # stdin line/control injection or FreeRDP's 512-byte passphrase truncation.
        if not 1 <= len(password) <= 128 or any(
            not 33 <= ord(c) <= 126 for c in password
        ):
            raise ValueError("Candidate password is outside the rotation contract")
        arguments = [
            f"/v:{target.address}:{target.port}",
            f"/u:{username}",
            f"/d:{domain}",
            "+auth-only",
            "/sec:nla",
            "/cert:fingerprint:" + pin.lower(),
            "/from-stdin:force",
            "/log-level:INFO",
            "-auto-reconnect",
            "-clipboard",
        ]
        return arguments, (password + "\n").encode("ascii")

    @staticmethod
    async def _output(stream: asyncio.StreamReader) -> bytes:
        result = bytearray()
        while chunk := await stream.read(4096):
            result.extend(chunk)
            if len(result) > _OUTPUT_LIMIT:
                raise ValueError("Verifier output exceeds budget")
        return bytes(result)

    async def _run(
        self,
        descriptor: int,
        arguments: list[str],
        password: bytes,
        display: dict[str, str] | None = None,
    ) -> bool:
        # Fresh home prevents cached Kerberos, config, certificates or reconnect
        # files from supplying a different authentication path. No inherited env.
        with TemporaryDirectory(prefix="northgate-rdp-verify-") as scratch:
            environment = {
                "HOME": scratch,
                "XDG_CONFIG_HOME": scratch,
                "XDG_CACHE_HOME": scratch,
                "KRB5CCNAME": "FILE:" + str(Path(scratch) / "absent-krb5cc"),
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                **(display or {}),
            }
            process = await asyncio.create_subprocess_exec(
                f"/proc/self/fd/{descriptor}",
                *arguments,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=environment,
                cwd=scratch,
                pass_fds=(descriptor,),
                start_new_session=True,
                limit=_OUTPUT_LIMIT + 1,
            )
            reader: asyncio.Task[bytes] | None = None
            try:
                if process.stdin is None or process.stdout is None:
                    raise OSError("Verifier pipes unavailable")
                reader = asyncio.create_task(self._output(process.stdout))
                process.stdin.write(password)
                await process.stdin.drain()
                process.stdin.close()
                output, status = await asyncio.gather(reader, process.wait())
                results = _AUTH_RESULT.findall(output)
                return (
                    status == 0
                    and bool(_SUCCESS.search(output))
                    and bool(results)
                    and all(value == b"0" for value in results)
                )
            finally:
                # This is authentication-only: leave neither a desktop session
                # nor a background verifier running on cancellation or timeout.
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                with suppress(TimeoutError):
                    await asyncio.wait_for(process.wait(), timeout=2)
                if reader is not None:
                    if not reader.done():
                        reader.cancel()
                    with suppress(asyncio.CancelledError, ValueError):
                        await reader

    @staticmethod
    def _authority(path: Path, cookie: bytes, display: str = "") -> None:
        # Xauthority's network-byte-order record format; FamilyWild permits the
        # private local display without a hostname/DNS dependency. The random
        # cookie is required by the X server and never passed in argv or env.
        fields = (b"", display.encode("ascii"), b"MIT-MAGIC-COOKIE-1", cookie)
        record = struct.pack("!H", 65535) + b"".join(
            struct.pack("!H", len(v)) + v for v in fields
        )
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(record)

    @staticmethod
    async def _display_number(descriptor: int) -> str:
        stream = os.fdopen(descriptor, "rb", buffering=0)
        reader = asyncio.StreamReader(limit=32)
        transport = None
        try:
            transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(reader), stream
            )
            raw = await reader.readline()
            if not re.fullmatch(rb"[0-9]{1,5}\n", raw) or int(raw) > 65535:
                raise ValueError("Xvfb did not provide a bounded display number")
            return raw[:-1].decode("ascii")
        finally:
            if transport is not None:
                transport.close()
            stream.close()

    async def _run_with_display(
        self, descriptor: int, arguments: list[str], password: bytes, xvfb: int
    ) -> bool:
        with TemporaryDirectory(prefix="northgate-xvfb-verify-") as scratch:
            folder = Path(scratch)
            cookie = secrets.token_bytes(16)
            server_auth, client_auth = (
                folder / "server.authority",
                folder / "client.authority",
            )
            self._authority(server_auth, cookie)
            read_fd, write_fd = os.pipe()
            process = None
            pending: list[asyncio.Task[Any]] = []
            try:
                process = await asyncio.create_subprocess_exec(
                    f"/proc/self/fd/{xvfb}",
                    "-displayfd",
                    str(write_fd),
                    "-screen",
                    "0",
                    "800x600x24",
                    "-nolisten",
                    "tcp",
                    "-auth",
                    str(server_auth),
                    "-noreset",
                    "-audit",
                    "0",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    cwd=scratch,
                    env={
                        "HOME": scratch,
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C",
                        "LC_ALL": "C",
                    },
                    pass_fds=(xvfb, write_fd),
                    start_new_session=True,
                    limit=_OUTPUT_LIMIT + 1,
                )
                os.close(write_fd)
                write_fd = -1
                if process.stdout is None:
                    raise OSError("Display server output pipe unavailable")
                number = asyncio.create_task(self._display_number(read_fd))
                read_fd = -1  # the display reader owns this descriptor
                output = asyncio.create_task(self._output(process.stdout))
                stopped = asyncio.create_task(process.wait())
                pending.extend((number, output, stopped))
                ready, _ = await asyncio.wait(
                    (number, output, stopped), return_when=asyncio.FIRST_COMPLETED
                )
                if number not in ready or stopped in ready or output in ready:
                    return False
                display = number.result()
                self._authority(client_auth, cookie, display)
                client = asyncio.create_task(
                    self._run(
                        descriptor,
                        arguments,
                        password,
                        {
                            "DISPLAY": ":" + display,
                            "XAUTHORITY": str(client_auth),
                        },
                    )
                )
                pending.append(client)
                completed, _ = await asyncio.wait(
                    (client, output, stopped), return_when=asyncio.FIRST_COMPLETED
                )
                return (
                    client in completed
                    and stopped not in completed
                    and output not in completed
                    and client.result()
                )
            finally:
                if write_fd >= 0:
                    os.close(write_fd)
                if read_fd >= 0:
                    os.close(read_fd)
                for task in pending:
                    if not task.done():
                        task.cancel()
                if process is not None:
                    if process.returncode is None:
                        with suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                    with suppress(TimeoutError):
                        await asyncio.wait_for(process.wait(), timeout=2)
                for task in pending:
                    with suppress(asyncio.CancelledError, ValueError, OSError):
                        await task

    async def preflight(
        self,
        *,
        target: RemoteTarget,
        parameters: dict[str, str],
        fields: dict[str, str],
    ) -> bool:
        """Check trusted runtime and arguments before the caller changes an account.

        No connection is made and no secret leaves this process. Verification
        repeats these checks after the worker change; preflight is not a promise
        that the network or authentication will succeed later.
        """
        descriptors: list[int] = []
        try:
            self._arguments(target, parameters, fields)
            descriptors.append(self._open_executable())
            if self.xvfb_executable is not None and self.xvfb_sha256 is not None:
                descriptors.append(
                    self._open_binary(self.xvfb_executable, self.xvfb_sha256)
                )
            return True
        except (OSError, ValueError):
            return False
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    async def verify(
        self,
        *,
        target: RemoteTarget,
        parameters: dict[str, str],
        fields: dict[str, str],
    ) -> bool:
        """Return only a boolean; exceptions and raw client output stay private."""
        descriptor: int | None = None
        xvfb: int | None = None
        try:
            arguments, password = self._arguments(target, parameters, fields)
            async with asyncio.timeout(self.timeout_seconds):
                async with self._slot:
                    descriptor = self._open_executable()
                    if (
                        self.xvfb_executable is not None
                        and self.xvfb_sha256 is not None
                    ):
                        xvfb = self._open_binary(self.xvfb_executable, self.xvfb_sha256)
                        return await self._run_with_display(
                            descriptor, arguments, password, xvfb
                        )
                    return await self._run(descriptor, arguments, password)
        except (OSError, ValueError, TimeoutError):
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if xvfb is not None:
                os.close(xvfb)
