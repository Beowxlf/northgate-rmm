"""Strict, versioned metadata for the optional executable catalog."""

from __future__ import annotations

import base64
import json
import re
import unicodedata
from typing import Any
from uuid import UUID

TOOLS = {
    "health": {"windows": "", "linux": ""},
    "connectivity": {"windows": "", "linux": ""},
    "evidence": {"windows": "", "linux": ""},
    "wxlfgar": {"windows": "", "linux": ""},
    "osquery": {"windows": "osqueryi.exe", "linux": "osqueryi"},
    "sysinternals": {"windows": "autorunsc.exe"},
    "yara-x": {"windows": "yr.exe", "linux": "yr"},
    "velociraptor": {"windows": "velociraptor.exe", "linux": "velociraptor"},
    "iperf2": {"windows": "iperf.exe", "linux": "iperf"},
    "openscap": {"linux": "oscap"},
    "nmap": {"windows": "nmap.exe", "linux": "nmap"},
}
BUILTIN = frozenset({"health", "connectivity", "evidence", "wxlfgar"})
PROFILES = {
    "health": {"snapshot", "history", "changes"},
    "connectivity": {"dns", "tcp", "tls"},
    "evidence": {"it", "soc"},
    "wxlfgar": {"readiness"},
    "osquery": {"system", "processes", "users", "listening", "startup"},
    "sysinternals": {"startup", "trust"},
    "yara-x": {"scan"},
    "velociraptor": {"collect"},
    "iperf2": {"client"},
    "openscap": {"assess"},
    "nmap": {"connect"},
}

TOOL_GUIDANCE = {
    "health": (
        "Summarizes endpoint health, recent history, or observed changes "
        "without remediation.",
        "Use first to establish device state and preserve a lightweight "
        "case-linked diagnostic.",
        "Structured health observations",
        "Read-only collection as the endpoint worker identity.",
    ),
    "connectivity": (
        "Checks DNS resolution, one TCP connection, or a TLS handshake from "
        "the selected endpoint.",
        "Use to confirm the endpoint's actual network path to an approved destination.",
        "Bounded connection and certificate observations",
        "Makes only the selected diagnostic network request.",
    ),
    "evidence": (
        "Collects a curated IT or SOC evidence snapshot using approved collectors.",
        "Use when a case needs repeatable endpoint context before deeper "
        "investigation.",
        "Structured, case-retainable collection results",
        "Read-only collection; output may contain sensitive operational context.",
    ),
    "wxlfgar": (
        "Checks whether the endpoint is ready for the WxlfGar workflow.",
        "Use before a governed WxlfGar operation to identify missing prerequisites.",
        "Readiness findings",
        "Read-only prerequisite inspection.",
    ),
    "osquery": (
        "Queries approved system, process, user, listener, and startup inventory.",
        "Use for rapid endpoint triage without opening an unrestricted shell.",
        "Structured query rows",
        "Read-only queries run with the managed worker's system privilege.",
    ),
    "sysinternals": (
        "Inspects logon startup entries or the offline trust metadata of one "
        "Windows executable.",
        "Use to review persistence indicators or an individual executable's "
        "signature and hash context.",
        "Autoruns or trust inspection results",
        "Read-only; trust inspection does not check certificate revocation.",
    ),
    "yara-x": (
        "Scans the selected local path with the approved YARA-X ruleset.",
        "Use only when a reviewed ruleset and a precise endpoint path are "
        "appropriate for the case.",
        "Rule matches and bounded scan status",
        "Reads files in the selected path; it does not quarantine or delete them.",
    ),
    "velociraptor": (
        "Runs an approved, bounded Velociraptor collection profile.",
        "Use for deeper case evidence after basic triage establishes the "
        "collection need.",
        "Collector results and artifacts",
        "Read-only collection can be resource intensive within enforced limits.",
    ),
    "iperf2": (
        "Measures client-side throughput to one approved private iperf endpoint.",
        "Use to diagnose a suspected lab network performance issue.",
        "Throughput and connection measurements",
        "Generates bounded test traffic; no listener is started.",
    ),
    "openscap": (
        "Evaluates the Linux endpoint against the approved OpenSCAP assessment "
        "profile.",
        "Use for configuration and compliance investigation, not incident containment.",
        "Assessment findings",
        "Read-only assessment may briefly increase CPU and disk activity.",
    ),
    "nmap": (
        "Tests up to 16 explicit ports on one private IP from the selected endpoint.",
        "Use for scoped connectivity validation when DNS/TCP checks are insufficient.",
        "Port reachability observations",
        "Generates bounded probe traffic; it is not a broad network scan.",
    ),
}

ACTION_GUIDANCE = {
    "tool.run": (
        "Run",
        "Queues the selected profile on this endpoint. It does not automatically "
        "remediate, isolate, or delete anything. Add a case ID so the audited "
        "result is linked to the investigation.",
    ),
    "tool.verify": (
        "Check readiness",
        "Checks whether the adapter and its dependencies are ready. It does not "
        "run the investigation profile or change the endpoint.",
    ),
    "tool.install": (
        "Install approved version",
        "Installs the signed, approved catalog release with endpoint patch "
        "permission. This changes the endpoint and remains fully audited.",
    ),
    "tool.update": (
        "Update approved version",
        "Updates to the selected signed catalog release with endpoint patch "
        "permission. This changes the endpoint and remains fully audited.",
    ),
    "tool.remove": (
        "Remove tool",
        "Removes the optional approved tool from this endpoint with patch "
        "permission. Built-in adapters cannot be removed.",
    ),
}

PROFILE_GUIDANCE = {
    "snapshot": "Current endpoint health snapshot.",
    "history": "Recent health observations.",
    "changes": "Recently observed state changes.",
    "dns": "Resolve one hostname from this endpoint.",
    "tcp": "Attempt one TCP connection.",
    "tls": "Inspect one TLS handshake and certificate.",
    "it": "General IT troubleshooting evidence.",
    "soc": "Security-triage evidence with analyst context.",
    "readiness": "Prerequisite check only.",
    "system": "Operating-system and hardware inventory.",
    "processes": "Current process inventory.",
    "users": "Local user and session context.",
    "listening": "Listening sockets and owning processes.",
    "startup": "Configured startup entries.",
    "trust": "Hash and offline signature context for one Windows executable.",
    "scan": "Approved YARA-X scan of the selected path.",
    "collect": "Approved Velociraptor collection.",
    "client": "Client-side throughput test.",
    "assess": "Approved OpenSCAP assessment.",
    "connect": "Explicit private-IP port connectivity check.",
}


def manifest_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def validate_manifest(value: Any) -> dict[str, Any]:
    required = {
        "schema",
        "id",
        "revision",
        "version",
        "platform",
        "arch",
        "sha256",
        "size",
        "entrypoint",
        "license",
        "source",
        "privilege",
        "budget",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or type(value["schema"]) is not int
        or value["schema"] != 1
    ):
        raise ValueError("Unsupported tool manifest")
    tool, platform = value.get("id"), value.get("platform")
    if (
        not isinstance(tool, str)
        or not isinstance(platform, str)
        or tool not in TOOLS
        or tool in BUILTIN
        or platform not in TOOLS[tool]
    ):
        raise ValueError("Tool/platform is unsupported")
    if (
        value["entrypoint"] != TOOLS[tool][platform]
        or not isinstance(value["arch"], str)
        or value["arch"]
        not in {
            "amd64",
            "arm64",
        }
    ):
        raise ValueError("Unsupported tool entrypoint or architecture")
    if type(value["revision"]) is not int or not 1 <= value["revision"] <= 1000000:
        raise ValueError("Monotonic package revision required")
    if not isinstance(value["version"], str) or not re.fullmatch(
        r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", value["version"]
    ):
        raise ValueError("Invalid tool version")
    if not isinstance(value["sha256"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", value["sha256"]
    ):
        raise ValueError("Invalid tool digest")
    if type(value["size"]) is not int or not 1 <= value["size"] <= 64 * 1024 * 1024:
        raise ValueError("Tool archive must be at most 64 MiB")
    for name in ("license", "source"):
        if (
            not isinstance(value[name], str)
            or not 1 <= len(value[name]) <= 2048
            or any(ord(c) < 32 for c in value[name])
        ):
            raise ValueError("License and provenance are required")
    if not value["source"].startswith("https://") or value["privilege"] != "system":
        raise ValueError(
            "HTTPS provenance and explicit system-worker privilege required"
        )
    budget = value["budget"]
    limits = {
        "seconds": (5, 900),
        "memory_mib": (64, 1024),
        "cpu_percent": (1, 50),
        "output_kib": (4, 512),
        "disk_mib": (16, 128),
    }
    if not isinstance(budget, dict) or set(budget) != set(limits):
        raise ValueError("Complete execution budget required")
    for key, (low, high) in limits.items():
        if type(budget[key]) is not int or not low <= budget[key] <= high:
            raise ValueError("Invalid tool budget: " + key)
    return value


def validate_tool_action(action: str, params: dict[str, Any], platform: str) -> None:
    if action in {"tool.install", "tool.update"}:
        try:
            raw = base64.b64decode(params["manifest"], validate=True)
            signature = base64.b64decode(params["signature"], validate=True)
            if len(raw) > 8192 or len(signature) != 64:
                raise ValueError()
            value = validate_manifest(json.loads(raw))
            if value["platform"] != platform or raw != manifest_bytes(value):
                raise ValueError()
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError("Invalid signed tool manifest") from exc
        return
    if action == "tool.artifact.read":
        if not isinstance(params["artifact_id"], str):
            raise ValueError("Invalid artifact identifier")
        UUID(params["artifact_id"])
        if not isinstance(params["case_id"], str):
            raise ValueError("Invalid artifact case")
        if params["case_id"]:
            UUID(params["case_id"])
        if (
            type(params["offset"]) is not int
            or not 0 <= params["offset"] <= 32 * 1024 * 1024
        ):
            raise ValueError("Invalid artifact offset")
        if type(params["size"]) is not int or not 1 <= params["size"] <= 256 * 1024:
            raise ValueError("Invalid artifact chunk size")
        return
    if action == "tool.list":
        return
    tool = params["tool_id"]
    if not isinstance(tool, str) or tool not in TOOLS or platform not in TOOLS[tool]:
        raise ValueError("Tool is unsupported on this platform")
    if action == "tool.remove" and tool in BUILTIN:
        raise ValueError("Built-in adapters cannot be removed")
    if action != "tool.run":
        return
    if (
        not isinstance(params["profile"], str)
        or params["profile"] not in PROFILES[tool]
        or not isinstance(params["inputs"], dict)
    ):
        raise ValueError("Unsupported tool profile")
    case_id = params["case_id"]
    if not isinstance(case_id, str):
        raise ValueError("Invalid tool case")
    if case_id:
        UUID(case_id)
    expected = {
        "connectivity": {"host", "port"},
        "yara-x": {"path"},
        "iperf2": {"host", "port"},
        "nmap": {"host", "ports"},
    }
    trust = tool == "sysinternals" and params["profile"] == "trust"
    allowed_inputs = [set(), {"path"}] if trust else [expected.get(tool, set())]
    if set(params["inputs"]) not in allowed_inputs:
        raise ValueError("Inputs do not match tool profile")
    if len(manifest_bytes(params["inputs"])) > 2048:
        raise ValueError("Tool inputs exceed bounds")
    if any(
        not isinstance(value, str)
        for key, value in params["inputs"].items()
        if key != "port"
    ):
        raise ValueError("Host, path and port-list inputs must be text")
    for value in params["inputs"].values():
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise ValueError("Invalid tool input type")
        if isinstance(value, str) and (
            not value or value.startswith("-") or any(ord(c) < 32 for c in value)
        ):
            raise ValueError("Invalid tool input")
    if trust and "path" in params["inputs"]:
        validate_windows_trust_path(params["inputs"]["path"])
    if "port" in params["inputs"] and (
        type(params["inputs"]["port"]) is not int
        or not 1 <= params["inputs"]["port"] <= 65535
    ):
        raise ValueError("Invalid port")
    if "ports" in params["inputs"]:
        ports = params["inputs"]["ports"]
        if (
            not isinstance(ports, str)
            or not re.fullmatch(r"\d{1,5}(,\d{1,5}){0,15}", ports)
            or any(not 1 <= int(p) <= 65535 for p in ports.split(","))
        ):
            raise ValueError("Select at most 16 explicit ports")


def validate_windows_trust_path(path: str) -> None:
    """Validate a remote Windows path without interpreting it as a server path.

    The worker additionally pins the existing regular file and enforces its size,
    fixed-drive location and exclusion from private worker/identity directories.
    """
    if (
        len(path.encode("utf-8")) > 1024
        or not re.match(r"^[A-Za-z]:\\", path)
        or any(unicodedata.category(char) == "Cc" for char in path)
        or any(char in path[2:] for char in ':/*?"<>|')
    ):
        raise ValueError("Select one absolute local Windows file")
    for part in path[3:].split("\\"):
        if (
            not part
            or part in {".", ".."}
            or part.endswith((".", " "))
            or re.fullmatch(
                r"(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])",
                part.split(".", 1)[0],
            )
        ):
            raise ValueError("Select one ordinary local Windows file")
