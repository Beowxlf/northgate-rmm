"""Deployment-owned operator grants; the browser cannot grant itself access."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

PERMISSIONS = frozenset(
    {"view", "remote", "manage", "patch", "recovery", "fleet_admin"}
)


@dataclass(frozen=True, slots=True)
class OperatorGrant:
    subject: str
    endpoints: tuple[str, ...]
    permissions: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not self.subject
            or len(self.subject) > 256
            or not self.subject.isprintable()
        ):
            raise ValueError("Invalid operator subject")
        if not self.endpoints or len(self.endpoints) > 4096:
            raise ValueError("Operator requires an explicit endpoint scope")
        for endpoint in self.endpoints:
            if endpoint != "*" and str(UUID(endpoint)) != endpoint:
                raise ValueError("Invalid operator endpoint scope")
        if not self.permissions or not set(self.permissions) <= PERMISSIONS:
            raise ValueError("Invalid operator permissions")

    def permits(self, endpoint: str, permission: str) -> bool:
        return permission in self.permissions and (
            "*" in self.endpoints or endpoint in self.endpoints
        )


def load_grants(value: Any) -> tuple[OperatorGrant, ...]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("Operator grants must be a list of at most 64 entries")
    result = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {
            "subject",
            "endpoints",
            "permissions",
        }:
            raise ValueError("Operator grant fields are not exact")
        if type(entry["subject"]) is not str or any(
            not isinstance(entry[field], list)
            or any(type(v) is not str for v in entry[field])
            for field in ("endpoints", "permissions")
        ):
            raise ValueError("Invalid operator grant types")
        result.append(
            OperatorGrant(
                entry["subject"], tuple(entry["endpoints"]), tuple(entry["permissions"])
            )
        )
    if len({grant.subject for grant in result}) != len(result):
        raise ValueError("Duplicate operator subject")
    if sum(len(grant.endpoints) for grant in result) > 4096:
        raise ValueError("Operator grants exceed 4096 total endpoint scope entries")
    return tuple(result)


def action_permission(action: str) -> str:
    if action in {"recovery.rotate", "bitlocker.escrow"}:
        return "recovery"
    if (
        action.startswith(("patches.", "package.", "update."))
        or action == "prerequisites.install"
    ):
        return "patch"
    return "manage"
