"""Signed Wxlfgar RPC over the existing pinned endpoint SSH connection."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import tempfile
from pathlib import Path

MAX_ARTIFACT = 33 * 1024 * 1024
ARTIFACTS = {"capture.pcap", "report.json", "summary.txt", "manifest.json"}


async def request_tool(
    target, parameters, platform, envelope, destination: Path | None = None
):
    username = parameters.get("username", "")
    pin = parameters.get("host-key", "")
    private = parameters.get("private-key", "")
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username)
        or not private
        or len(pin.splitlines()) != 1
    ):
        raise ValueError("Capture SSH configuration unavailable")
    parts = pin.split()
    if len(parts) != 3 or parts[1] not in {
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ssh-rsa",
    }:
        raise ValueError("Capture SSH host pin unavailable")
    if platform == "windows":
        script = (
            "& 'C:\\Program Files\\NorthGate RMM\\northgate-rmm-agent.exe' "
            "--capture-request; exit $LASTEXITCODE"
        )
        command = (
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
            + base64.b64encode(script.encode("utf-16-le")).decode()
        )
    elif platform == "linux":
        command = "/usr/libexec/northgate-rmm/northgate-rmm-agent --capture-request"
    else:
        raise ValueError("Platform not supported")
    with tempfile.TemporaryDirectory(prefix="rmm-capture-ssh-") as directory:
        root = Path(directory)
        for name, content in [("key", private), ("known_hosts", pin + "\n")]:
            path = root / name
            path.write_text(content)
            path.chmod(0o600)
        args = ["/usr/bin/ssh", "-T", "-F", "/dev/null", "-i", str(root / "key")]
        for option in [
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=" + str(root / "known_hosts"),
            "HostKeyAlgorithms=" + parts[1],
            "ConnectTimeout=8",
            "ServerAliveInterval=5",
            "ServerAliveCountMax=2",
        ]:
            args += ["-o", option]
        args += [username + "@" + target.address, command]
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=2 * 1024 * 1024,
        )
        try:
            async with asyncio.timeout(180 if destination else 20):
                proc.stdin.write(json.dumps(envelope).encode() + b"\n")
                await proc.stdin.drain()
                proc.stdin.close()
                line = await proc.stdout.readline()
                if len(line) > 2 * 1024 * 1024:
                    raise ValueError("Tool response too large")
                result = json.loads(line.decode("utf-8-sig"))
                if not isinstance(result, dict) or "error" in result:
                    raise ValueError(
                        "Capture tool rejected request or is not installed"
                    )
                if destination:
                    artifact = result.get("artifact", {})
                    if (
                        not isinstance(artifact, dict)
                        or artifact.get("name") not in ARTIFACTS
                        or type(artifact.get("size")) is not int
                        or not 0 <= artifact["size"] <= MAX_ARTIFACT
                        or not re.fullmatch(r"[a-f0-9]{64}", artifact.get("sha256", ""))
                    ):
                        raise ValueError("Invalid artifact manifest")
                    total = 0
                    digest = hashlib.sha256()
                    with destination.open("xb") as output:
                        destination.chmod(0o600)
                        while True:
                            chunk = await proc.stdout.readline()
                            if not chunk or len(chunk) > 65536:
                                raise ValueError("Incomplete artifact stream")
                            item = json.loads(chunk)
                            if not isinstance(item, dict):
                                raise ValueError("Invalid artifact chunk")
                            if item.get("done") is True:
                                if item.get("size") != total:
                                    raise ValueError("Artifact trailer mismatch")
                                break
                            data = base64.b64decode(item["data"], validate=True)
                            if not data or len(data) > 32768:
                                raise ValueError("Invalid artifact chunk size")
                            total += len(data)
                            if total > artifact["size"]:
                                raise ValueError("Artifact size exceeded")
                            digest.update(data)
                            output.write(data)
                    if (
                        total != artifact["size"]
                        or digest.hexdigest() != artifact["sha256"]
                    ):
                        raise ValueError("Artifact integrity check failed")
                    result = artifact
                extra = await proc.stdout.read(1024)
                if extra.strip() or await proc.wait() != 0:
                    raise ValueError("Capture tool failed")
                return result
        except (
            KeyError,
            TypeError,
            UnicodeError,
            RecursionError,
            json.JSONDecodeError,
        ) as error:
            raise ValueError("Invalid capture response") from error
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()
