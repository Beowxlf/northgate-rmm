"""Explicit endpoint-bound authorization for interactive lab remote access.

Protocol gateways consume this policy; monitoring viewer access never grants
desktop control. No endpoint destination is accepted from a browser request.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from northgate_rmm.domain import EndpointStatus, require_aware
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.operator_api import OperatorAuthorizationPolicy, OperatorPrincipal


class RemoteTargets(dict):
    """Primary targets remain compatible; methods hold explicitly enrolled services."""

    def __init__(self, methods):
        self.methods = methods
        super().__init__(
            (endpoint, choices.get("ssh", next(iter(choices.values()))))
            for endpoint, choices in methods.items()
        )


def parse_remote_targets(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 8192:
        raise ValueError("invalid remote targets")
    methods = {}
    allowed = {
        "username",
        "password",
        "domain",
        "security",
        "cert-fingerprints",
        "server-layout",
        "resize-method",
        "color-depth",
        "private-key",
        "host-key",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "endpoint_id",
            "identity_id",
            "address",
            "protocol",
            "port",
            "parameters",
        }:
            raise ValueError("invalid remote target fields")
        target = RemoteTarget(
            UUID(item["endpoint_id"]),
            UUID(item["identity_id"]),
            item["address"],
            item["protocol"],
            item["port"],
        )
        parameters = item["parameters"]
        if (
            not isinstance(parameters, dict)
            or not set(parameters) <= allowed
            or any(type(v) is not str or len(v) > 8192 for v in parameters.values())
        ):
            raise ValueError("invalid remote parameters")
        if target.protocol == "rdp" and parameters.get("security", "nla") not in {
            "nla",
            "nla-ext",
        }:
            raise ValueError("browser RDP requires Network Level Authentication")
        choices = methods.setdefault(target.endpoint_id, {})
        if target.protocol in choices:
            raise ValueError("duplicate remote method")
        if any(
            (other.identity_id, other.address) != (target.identity_id, target.address)
            for other, _ in choices.values()
        ):
            raise ValueError(
                "remote methods must belong to the same enrollment and host"
            )
        choices[target.protocol] = (target, dict(parameters))
    return RemoteTargets(methods)


@dataclass(frozen=True, slots=True)
class RemoteTarget:
    endpoint_id: UUID
    identity_id: UUID
    address: str
    protocol: str = "rdp"
    port: int = 3389

    def __post_init__(self) -> None:
        if type(self.endpoint_id) is not UUID or type(self.identity_id) is not UUID:
            raise ValidationError("remote target requires exact endpoint and identity")
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise ValidationError("remote target must be an IP literal") from error
        networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        if not any(address in ipaddress.ip_network(item) for item in networks):
            raise ValidationError("remote target must use a private lab address")
        if (self.protocol, self.port) not in {("rdp", 3389), ("ssh", 22)}:
            raise ValidationError("remote protocol and port are not supported")
        if type(self.port) is not int:
            raise ValidationError("remote port must be an integer")


def authorize_remote(
    principal: OperatorPrincipal,
    policy: OperatorAuthorizationPolicy,
    target: RemoteTarget,
    status: EndpointStatus,
    current_identity_id: UUID,
    *,
    now: datetime,
    require_online: bool = True,
    permission: str = "remote",
) -> None:
    """Recheck current human, MFA, remote role and enrolled identity together."""
    require_aware(now, "remote authorization time")
    if (
        principal.issuer != policy.issuer
        or principal.tenant != policy.tenant
        or not policy.permits(principal.subject, target.endpoint_id, permission)
        or principal.client_id != policy.client_id
        or not principal.mfa
        or "remote_operator" not in principal.roles
        or not principal.authenticated_at <= now < principal.expires_at
        or now - principal.authenticated_at > policy.maximum_session_age
    ):
        raise AuthorizationError("remote operator authorization denied")
    if (
        current_identity_id != target.identity_id
        or status.endpoint_id != target.endpoint_id
        or status.lifecycle.value != "active"
        or (require_online and status.health.value != "online")
    ):
        raise AuthorizationError("remote endpoint authorization denied")


@dataclass(frozen=True, slots=True)
class RemoteLease:
    """A bounded authorization lease, independent of the gateway's login token."""

    session_id: UUID
    endpoint_id: UUID
    identity_id: UUID
    subject: str
    idp_session_id: str
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        require_aware(self.created_at, "remote lease creation")
        require_aware(self.expires_at, "remote lease expiry")
        if not timedelta(0) < self.expires_at - self.created_at <= timedelta(hours=1):
            raise ValidationError("remote lease must expire within one hour")

    def check(
        self, principal: OperatorPrincipal, target: RemoteTarget, *, now: datetime
    ) -> None:
        require_aware(now, "remote lease check")
        if (
            not self.created_at <= now < self.expires_at
            or principal.subject != self.subject
            or principal.session_id != self.idp_session_id
            or target.endpoint_id != self.endpoint_id
            or target.identity_id != self.identity_id
        ):
            raise AuthorizationError("remote lease is not valid for this session")
