"""Bounded contracts for cases, infrastructure context and retained evidence."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any
from uuid import UUID

KINDS = frozenset(
    {
        "case",
        "asset",
        "service",
        "network",
        "relationship",
        "document",
        "change",
        "exercise",
        "alert",
    }
)
EDITABLE = KINDS - {"alert"}
STATES = frozenset({"new", "triage", "in_progress", "waiting", "resolved", "closed"})
TRANSITIONS = {
    "new": {"triage", "in_progress", "waiting"},
    "triage": {"in_progress", "waiting", "resolved"},
    "in_progress": {"waiting", "resolved"},
    "waiting": {"triage", "in_progress", "resolved"},
    "resolved": {"in_progress", "closed"},
    "closed": {"in_progress"},
}
MAX_CHUNK = 1024 * 1024
MAX_ARTIFACT = 128 * MAX_CHUNK
SECRET_NAMES = frozenset(
    {
        "password",
        "passphrase",
        "recovery_password",
        "private_key",
        "access_token",
        "refresh_token",
        "authorization",
        "client_secret",
        "secret_value",
    }
)
SECRET_PATTERN = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----|\b\d{6}(?:-\d{6}){7}\b|"
    r"(?i:bearer\s+[a-z0-9._~-]{24,})|"
    r"(?i:(?:password|passphrase|client_secret|access_token|refresh_token)"
    r"\s*[:=]\s*[^\s,;}]{4,})"
)


def identifier(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("A UUID identifier is required")
    return str(UUID(value))


def text(value: Any, maximum: int = 256, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or (not value.strip() and not empty)
    ):
        raise ValueError("Text is missing or too long")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError("Control characters are not permitted")
    check_secrets(value)
    return value.strip()


def check_secrets(value: Any) -> None:
    if isinstance(value, dict):
        for name, item in value.items():
            if str(name).lower().replace("-", "_") in SECRET_NAMES:
                raise ValueError(
                    "Secret fields belong in the protected secrets workflow"
                )
            check_secrets(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            check_secrets(item)
    elif isinstance(value, str) and SECRET_PATTERN.search(value):
        raise ValueError(
            "Possible credential or recovery secret; redact before attaching"
        )


def bounded_json(value: Any, maximum: int = 256 * 1024) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)
    if len(encoded.encode()) > maximum:
        raise ValueError("Record exceeds size limit")
    check_secrets(value)
    return encoded


def identifiers(value: Any, maximum: int = 128) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("Invalid identifier list")
    return sorted({identifier(v) for v in value})


def stamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("Timestamp must be ISO 8601")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp requires timezone")
    return parsed.isoformat()


def validate(kind: str, value: Any) -> dict[str, Any]:
    if kind not in EDITABLE or not isinstance(value, dict):
        raise ValueError("Unsupported record kind")
    bounded_json(value)
    common = {
        "name",
        "description",
        "endpoints",
        "assets",
        "services",
        "networks",
        "owner",
        "team",
        "tags",
    }
    fields = {
        "case": {"type", "priority", "assignee", "response_due", "resolve_due"},
        "asset": {
            "asset_type",
            "site",
            "environment",
            "criticality",
            "intended",
            "observed",
            "provenance",
            "external_id",
        },
        "service": {"criticality", "intended", "observed", "provenance"},
        "network": {"cidr", "vlan", "intended", "observed", "provenance"},
        "relationship": {
            "source",
            "target",
            "relation",
            "confidence",
            "verified_at",
            "source_ref",
        },
        "document": {"document_type", "content", "review_due", "source_ref"},
        "change": {
            "planned_at",
            "implementation",
            "rollback",
            "verification",
            "status",
            "case_id",
        },
        "exercise": {
            "techniques",
            "allowed_activities",
            "expected_detections",
            "cleanup_verification",
            "status",
            "case_id",
        },
    }
    if set(value) - common - fields[kind]:
        raise ValueError("Unsupported fields")
    result: dict[str, Any] = {
        "name": text(value.get("name")),
        "description": text(value.get("description", ""), 8192, True),
        "endpoints": identifiers(value.get("endpoints", [])),
        "owner": text(value.get("owner", ""), 256, True),
        "team": text(value.get("team", ""), 128, True),
    }
    for name in ("assets", "services", "networks"):
        result[name] = identifiers(value.get(name, []))
    tags = value.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 32:
        raise ValueError("Use at most 32 tags")
    result["tags"] = sorted({text(v, 64) for v in tags})
    for name in fields[kind]:
        if name not in value:
            continue
        item = value[name]
        if name in {
            "response_due",
            "resolve_due",
            "planned_at",
            "review_due",
            "verified_at",
        }:
            result[name] = stamp(item)
        elif name in {"intended", "observed", "provenance"}:
            if not isinstance(item, dict):
                raise ValueError(name + " must be an object")
            bounded_json(item, 32768)
            result[name] = item
        elif name in {"techniques", "allowed_activities", "expected_detections"}:
            if not isinstance(item, list) or len(item) > 100:
                raise ValueError("Invalid exercise list")
            result[name] = [text(v, 1024) for v in item]
        elif name in {"source", "target"}:
            if (
                not isinstance(item, dict)
                or set(item) != {"kind", "id"}
                or item["kind"] not in {"asset", "service", "network"}
            ):
                raise ValueError("Invalid relationship endpoint")
            result[name] = {"kind": item["kind"], "id": identifier(item["id"])}
        elif name == "case_id":
            result[name] = identifier(item) if item else ""
        elif name == "vlan":
            if type(item) is not int or not 1 <= item <= 4094:
                raise ValueError("Invalid VLAN")
            result[name] = item
        else:
            result[name] = text(
                item,
                32768
                if name in {"content", "implementation", "rollback", "verification"}
                else 4096,
                True,
            )
    if kind == "case":
        if result.get("type", "it") not in {
            "it",
            "soc",
            "problem",
            "request",
        } or result.get("priority", "normal") not in {
            "low",
            "normal",
            "high",
            "critical",
        }:
            raise ValueError("Invalid case type or priority")
        result.setdefault("type", "it")
        result.setdefault("priority", "normal")
        result.setdefault("assignee", "")
    if kind == "relationship":
        if (
            not {"source", "target", "relation"} <= set(result)
            or result["source"] == result["target"]
        ):
            raise ValueError("A relationship requires two distinct records")
        if result["relation"] not in {
            "hosted_on",
            "depends_on",
            "connected_to",
            "member_of",
            "protected_by",
            "backs_up_to",
        }:
            raise ValueError("Invalid relationship type")
        if result.get("confidence", "candidate") not in {
            "candidate",
            "observed",
            "verified",
        }:
            raise ValueError("Invalid confidence")
    if kind == "network" and result.get("cidr"):
        import ipaddress

        result["cidr"] = str(ipaddress.ip_network(result["cidr"], strict=True))
    if kind == "document" and result.get("document_type", "article") not in {
        "article",
        "runbook",
        "design",
        "procedure",
    }:
        raise ValueError("Invalid document type")
    if kind in {"change", "exercise"}:
        if result.get("status", "planned") not in {
            "planned",
            "approved",
            "running",
            "review",
            "closed",
            "cancelled",
        }:
            raise ValueError("Invalid workflow status")
        if result.get("status") == "closed" and not result.get(
            "verification" if kind == "change" else "cleanup_verification"
        ):
            raise ValueError("Closure requires recorded verification")
    return result
