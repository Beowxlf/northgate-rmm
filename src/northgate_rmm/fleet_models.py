"""Bounded fleet contracts. Policies describe intent; a preview binds targets."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from northgate_rmm.management_protocol import canonical, validate_action

FLEET_ACTIONS = {
    "posture": "Collect security posture",
    "services.list": "List services",
    "processes.list": "List processes",
    "reboot.status": "Check restart readiness",
    "packages.list": "Inventory software",
    "encryption.status": "Check encryption",
    "patches.scan": "Scan for updates",
    "patches.install": "Install available updates",
    "prerequisites.install": "Install tool prerequisites",
    "package.install": "Install a package",
    "package.remove": "Remove a package",
    "service.control": "Manage a service",
    "reboot": "Restart devices",
    "script.run": "Run a reviewed script",
    "update.install": "Install a signed agent release",
}
READ_ACTIONS = frozenset(
    {
        "posture",
        "services.list",
        "processes.list",
        "reboot.status",
        "packages.list",
        "encryption.status",
        "patches.scan",
    }
)
KINDS = frozenset(
    {
        "asset",
        "group",
        "policy",
        "automation",
        "rule",
        "alert",
        "baseline",
        "exercise",
        "view",
        "rollout",
        "preview",
    }
)
EDITABLE = frozenset(
    {"asset", "group", "policy", "automation", "rule", "exercise", "view"}
)
RUN_TERMINAL = frozenset({"completed", "failed", "cancelled", "expired"})


def identifier(value: Any) -> str:
    if type(value) is not str:
        raise ValueError("An identifier is required")
    return str(UUID(value))


def text(value: Any, maximum: int = 128, *, empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or (not value.strip() and not empty)
    ):
        raise ValueError("Text is missing or too long")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError("Control characters are not allowed")
    return value.strip()


def integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"Enter a whole number between {low} and {high}")
    return value


def boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise ValueError("Expected true or false")
    return value


def window(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"days", "start", "end"}:
        raise ValueError("Maintenance window requires days, start and end in UTC")
    if not isinstance(value["days"], list) or not 1 <= len(value["days"]) <= 7:
        raise ValueError("Choose maintenance days")
    days = sorted({integer(day, 0, 6) for day in value["days"]})
    for field in ("start", "end"):
        if type(value[field]) is not str or not re.fullmatch(
            r"(?:[01]\d|2[0-3]):[0-5]\d", value[field]
        ):
            raise ValueError("Use HH:MM UTC")
    return {"days": days, "start": value["start"], "end": value["end"]}


def window_open(value: dict[str, Any], now: float) -> bool:
    current = datetime.fromtimestamp(now, UTC)
    clock = current.strftime("%H:%M")
    start, end = value["start"], value["end"]
    if start == end:
        return current.weekday() in value["days"]
    if start < end:
        return current.weekday() in value["days"] and start <= clock < end
    # An overnight interval belongs to the day on which it starts.
    return (current.weekday() in value["days"] and clock >= start) or (
        (current.weekday() - 1) % 7 in value["days"] and clock < end
    )


def validate_record(kind: str, value: Any) -> dict[str, Any]:
    if (
        kind not in EDITABLE
        or not isinstance(value, dict)
        or len(canonical(value)) > 65536
    ):
        raise ValueError("Unsupported or oversized record")
    if kind == "asset":
        if (
            not isinstance(value.get("tags", []), list)
            or len(value.get("tags", [])) > 20
        ):
            raise ValueError("Use at most 20 tags")
        return {
            "name": text(value.get("name", ""), empty=True),
            "group": identifier(value["group"]) if value.get("group") else "",
            "site": text(value.get("site", ""), empty=True),
            "owner": text(value.get("owner", ""), empty=True),
            "criticality": value["criticality"]
            if value.get("criticality") in {"standard", "important", "critical"}
            else "standard",
            "tags": sorted({text(tag, 32) for tag in value.get("tags", [])}),
            "notes": text(value.get("notes", ""), 4096, empty=True),
        }
    result: dict[str, Any] = {"name": text(value.get("name"))}
    if kind == "group":
        result.update(
            parent=identifier(value["parent"]) if value.get("parent") else "",
            description=text(value.get("description", ""), 1024, empty=True),
        )
    elif kind == "policy":
        action = value.get("action")
        if action not in FLEET_ACTIONS:
            raise ValueError("This operation is only available on an individual device")
        platform = value.get("platform", "all")
        if platform not in {"all", "windows", "linux"}:
            raise ValueError("Choose a supported platform")
        params = value.get("params", {})
        for target in ["windows", "linux"] if platform == "all" else [platform]:
            validate_action(action, params, target)
        result.update(
            action=action,
            params=params,
            platform=platform,
            group=identifier(value["group"]) if value.get("group") else "",
            window=window(
                value.get(
                    "window", {"days": list(range(7)), "start": "00:00", "end": "00:00"}
                )
            ),
            concurrency=integer(value.get("concurrency", 3), 1, 16),
            canary=integer(value.get("canary", 1), 1, 10),
            failure_limit=integer(value.get("failure_limit", 1), 1, 100),
            review_canary=boolean(value.get("review_canary", True)),
        )
    elif kind == "automation":
        result.update(
            policy=identifier(value.get("policy")),
            group=identifier(value["group"]) if value.get("group") else "",
            interval=integer(value.get("interval", 3600), 300, 604800),
            enabled=boolean(value.get("enabled", False)),
        )
    elif kind == "rule":
        condition = value.get("condition")
        if condition not in {
            "offline",
            "worker_missing",
            "capture_dependency",
            "package_dependency",
            "recovery_missing",
            "job_failed",
            "baseline_drift",
        }:
            raise ValueError("Unknown alert condition")
        severity = value.get("severity", "warning")
        if severity not in {"info", "warning", "critical"}:
            raise ValueError("Invalid alert severity")
        result.update(
            condition=condition,
            severity=severity,
            enabled=boolean(value.get("enabled", True)),
            group=identifier(value["group"]) if value.get("group") else "",
            delay=integer(value.get("delay", 120), 0, 86400),
            escalate=integer(value.get("escalate", 3600), 60, 604800),
        )
    elif kind == "exercise":
        result.update(
            description=text(value.get("description", ""), 4096, empty=True),
            status=value.get("status", "planned"),
            technique=text(value.get("technique", ""), 128, empty=True),
            outcome=text(value.get("outcome", ""), 4096, empty=True),
        )
        if result["status"] not in {"planned", "running", "review", "closed"}:
            raise ValueError("Invalid exercise status")
    elif kind == "view":
        result.update(
            query=text(value.get("query", ""), 256, empty=True),
            group=identifier(value["group"]) if value.get("group") else "",
            platform=value.get("platform", ""),
            health=value.get("health", ""),
        )
        if result["platform"] not in {"", "windows", "linux"} or result[
            "health"
        ] not in {"", "online", "offline", "stale"}:
            raise ValueError("Invalid saved view filter")
    return result
