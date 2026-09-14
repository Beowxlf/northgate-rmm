"""Versioned, bounded privileged-operation contracts and separate crypto purposes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MAX_RESULT = 32 * 1024 * 1024
# A 15 MiB upload encodes to 20 MiB, leaving envelope room below the
# existing 21 MiB authentication-subrequest limit. Downloads allow 16 MiB.
MAX_FILE = 15 * 1024 * 1024
MAX_OUTPUT = 512 * 1024
TERMINAL = frozenset({"completed", "failed", "cancelled", "expired", "result_unknown"})
ACTIONS = {
    "tool.list": (),
    "tool.verify": ("tool_id",),
    "tool.install": ("manifest", "signature"),
    "tool.update": ("manifest", "signature"),
    "tool.run": ("tool_id", "profile", "inputs", "case_id"),
    "tool.remove": ("tool_id",),
    "tool.artifact.read": ("artifact_id", "offset", "size", "case_id"),
    "capture.install": ("url", "sha256", "signature", "version", "public_key"),
    "capabilities": (),
    "prerequisites.install": (),
    "posture": (),
    "services.list": (),
    "service.control": ("name", "operation"),
    "processes.list": (),
    "process.stop": ("pid", "start_token"),
    "files.list": ("path",),
    "files.read": ("path",),
    "files.write": ("path", "data", "sha256", "overwrite"),
    "logs.read": ("channel", "since", "limit"),
    "reboot.status": (),
    "reboot": ("delay",),
    "packages.list": (),
    "package.install": ("name",),
    "package.remove": ("name",),
    "patches.scan": (),
    "patches.install": (),
    "encryption.status": (),
    "bitlocker.escrow": (),
    "recovery.rotate": ("hours",),
    "credential.rotate": (
        "rotation_id",
        "phase",
        "username",
        "account_sid",
        "protocol",
        "expected_version",
        "candidate",
    ),
    "isolation.start": ("seconds",),
    "isolation.release": (),
    "script.run": ("script_id", "version", "inputs"),
    "shell.start": ("columns", "rows"),
    "update.install": ("component", "url", "sha256", "signature", "version"),
}
SECRET_ACTIONS = frozenset({"bitlocker.escrow", "recovery.rotate", "credential.rotate"})


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def derive(key: bytes, purpose: str) -> bytes:
    return hmac.digest(key, b"northgate-management-v1/" + purpose.encode(), "sha256")


def public_configuration(key: bytes) -> dict[str, str]:
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(derive(key, "signing"))
    escrow = x25519.X25519PrivateKey.from_private_bytes(derive(key, "escrow"))
    keys: list[tuple[str, ed25519.Ed25519PrivateKey | x25519.X25519PrivateKey]] = [
        ("signing_key", signer),
        ("escrow_key", escrow),
    ]
    return {
        name: base64.b64encode(
            obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        for name, obj in keys
    }


def sign(key: bytes, value: Any) -> dict[str, str]:
    payload = canonical(value)
    signature = ed25519.Ed25519PrivateKey.from_private_bytes(
        derive(key, "signing")
    ).sign(b"NorthGate-Management-v1\0" + payload)
    return {
        "payload": base64.b64encode(payload).decode(),
        "signature": base64.b64encode(signature).decode(),
    }


def seal(key: bytes, value: Any, context: str) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(derive(key, "storage")).encrypt(
        nonce, canonical(value), context.encode()
    )


def unseal(key: bytes, value: Any, context: str) -> Any:
    return json.loads(
        AESGCM(derive(key, ("storage"))).decrypt(
            value[:12], value[12:], context.encode()
        )
    )


def open_worker_result(key: bytes, value: Any, job_id: str) -> Any:
    """Only the control plane can decrypt persisted worker receipts."""
    if not isinstance(value, dict) or set(value) != {"ephemeral", "nonce", "body"}:
        raise ValueError("Invalid encrypted receipt")
    ephemeral = base64.b64decode(value["ephemeral"], validate=True)
    nonce = base64.b64decode(value["nonce"], validate=True)
    body = base64.b64decode(value["body"], validate=True)
    if len(ephemeral) != 32 or len(nonce) != 12 or len(body) > MAX_RESULT:
        raise ValueError("Receipt bounds exceeded")
    private = x25519.X25519PrivateKey.from_private_bytes(derive(key, "escrow"))
    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(ephemeral))
    result_key = hmac.digest(shared, b"NorthGate-Receipt-v1", "sha256")
    return json.loads(AESGCM(result_key).decrypt(nonce, body, str(job_id).encode()))


def validate_action(action: Any, params: Any, platform: str) -> dict[str, Any]:
    if (
        not isinstance(action, str)
        or action not in ACTIONS
        or not isinstance(params, dict)
        or set(params) != set(ACTIONS[action])
    ):
        raise ValueError("Unsupported operation or parameters")
    if platform not in {"windows", "linux"}:
        raise ValueError("Unsupported platform")
    if action.startswith("tool."):
        from northgate_rmm.tool_catalog_models import validate_tool_action

        validate_tool_action(action, params, platform)
    if action == "bitlocker.escrow" and platform != "windows":
        raise ValueError("BitLocker requires Windows")
    if len(canonical(params)) > MAX_RESULT:
        raise ValueError("Operation parameters too large")
    if action == "capture.install":
        if any(not isinstance(params[k], str) or len(params[k]) > 2048 for k in params):
            raise ValueError("Invalid capture installation parameters")
        if len(base64.b64decode(params["public_key"], validate=True)) != 32:
            raise ValueError("Invalid capture signing key")
        if not re.fullmatch(r"[a-f0-9]{64}", params["sha256"]):
            raise ValueError("Invalid capture package digest")

    def integer(name: str, low: int, high: int) -> None:
        if type(params.get(name)) is not int or not low <= params[name] <= high:
            raise ValueError("Invalid " + name)

    if action == "credential.rotate":
        if (
            platform != "windows"
            or str(UUID(params["rotation_id"])) != params["rotation_id"]
            or params["phase"] not in {"apply", "check"}
            or params["username"] != "rmmremote"
            or params["protocol"] != "rdp"
            or not isinstance(params["account_sid"], str)
            or not re.fullmatch(
                r"S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[1-9][0-9]{3,9}",
                params["account_sid"],
            )
        ):
            raise ValueError("Unsupported managed credential account")
        integer("expected_version", 1, 2147483647)
        if (
            not isinstance(params["candidate"], str)
            or not 60
            <= len(base64.b64decode(params["candidate"], validate=True))
            <= 2048
        ):
            raise ValueError("Invalid encrypted candidate")

    if action.startswith("files."):
        path = params["path"]
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 1024
            or any(c in path for c in "\0\r\n")
        ):
            raise ValueError("Invalid file path")
    if action == "files.write":
        data = base64.b64decode(params["data"], validate=True)
        if (
            len(data) > MAX_FILE
            or hashlib.sha256(data).hexdigest() != params["sha256"]
            or type(params["overwrite"]) is not bool
        ):
            raise ValueError("Upload integrity or size invalid")
    if action == "service.control" and (
        not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", params["name"])
        or params["operation"] not in {"start", "stop", "restart"}
    ):
        raise ValueError("Invalid service operation")
    if action == "process.stop":
        integer("pid", 5, 2147483647)
        if not isinstance(params["start_token"], str) or not re.fullmatch(
            r"[0-9]{1,24}", params["start_token"]
        ):
            raise ValueError("Select the start token from the process inventory")
    if action == "logs.read":
        if params["channel"] not in {
            "System",
            "Application",
            "Security",
            "Sysmon",
            "Defender",
            "journal",
            "auth",
        }:
            raise ValueError("Unsupported log channel")
        integer("since", 1, 1440)
        integer("limit", 1, 500)
    if action == "reboot":
        integer("delay", 30, 300)
    if action == "recovery.rotate":
        integer("hours", 1, 168)
    if action == "isolation.start":
        integer("seconds", 30, 300)
    if action == "shell.start":
        integer("columns", 20, 240)
        integer("rows", 5, 100)
    if action.startswith("package.") and not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.+:-]{0,127}", params["name"]
    ):
        raise ValueError("Invalid package identifier")
    if action == "script.run":
        UUID(params["script_id"])
        if not re.fullmatch(r"[a-f0-9]{64}", params["version"]) or not isinstance(
            params["inputs"], dict
        ):
            raise ValueError("Invalid script reference")
        if any(
            not isinstance(name, str) or not isinstance(value, str) or len(value) > 4096
            for name, value in params["inputs"].items()
        ):
            raise ValueError("Invalid script input")
    if action == "update.install":
        if params["component"] not in {
            "agent",
            "worker",
            "wxlfgar",
        } or not re.fullmatch(r"[a-f0-9]{64}", params["sha256"]):
            raise ValueError("Invalid release metadata")
        if not isinstance(params["url"], str) or not params["url"].startswith(
            "https://"
        ):
            raise ValueError("Updates require HTTPS")
        if len(base64.b64decode(params["signature"], validate=True)) != 64:
            raise ValueError("Release signature required")
    return params
