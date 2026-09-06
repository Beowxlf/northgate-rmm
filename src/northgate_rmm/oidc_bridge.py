"""Online OIDC introspection adapter for a separately configured private IdP."""

from __future__ import annotations

import base64
import ipaddress
import re
import ssl
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.private_https import PinnedHTTPSConnection
from northgate_rmm.workload_service import (
    Operation,
    read_private,
    service_main,
    strict_object,
)


class OIDCBridge:
    def __init__(self, configuration: dict[str, Any]) -> None:
        self.config = configuration
        self.url = urlsplit(configuration["introspection_url"])
        if (
            self.url.scheme != "https"
            or not self.url.hostname
            or self.url.username
            or self.url.query
            or self.url.fragment
        ):
            raise ValidationError("introspection URL invalid")
        address = ipaddress.ip_address(configuration["idp_connect_address"])
        if not address.is_private or address.is_unspecified or address.is_multicast:
            raise ValidationError("private IdP address required")
        self.address = str(address)
        self.context = ssl.create_default_context(
            cafile=str(Path(configuration["idp_ca_certificate"]))
        )
        self.context.minimum_version = self.context.maximum_version = (
            ssl.TLSVersion.TLSv1_3
        )
        self.context.options |= ssl.OP_NO_TICKET
        secret = (
            read_private(configuration["client_secret_file"], 4096)
            .decode("utf-8")
            .strip()
        )
        if not secret or ":" in configuration["client_id"]:
            raise ValidationError("introspection credentials invalid")
        self.basic = "Basic " + base64.b64encode(
            (configuration["client_id"] + ":" + secret).encode()
        ).decode("ascii")

    def handle(
        self, _path: str, body: bytes, authorization: str | None
    ) -> tuple[int, dict[str, Any]]:
        if (
            body
            or authorization is None
            or len(authorization) > 4096
            or re.fullmatch(r"Bearer [A-Za-z0-9\-._~+/]+=*", authorization) is None
        ):
            raise AuthorizationError("session unavailable")
        request = urlencode(
            {"token": authorization[7:], "token_type_hint": "access_token"}
        ).encode("ascii")
        connection = PinnedHTTPSConnection(
            connect_address=self.address,
            authority=self.url.hostname or "",
            port=self.url.port or 443,
            context=self.context,
            timeout_seconds=5,
        )
        try:
            connection.request(
                "POST",
                self.url.path,
                body=request,
                headers={
                    "Authorization": self.basic,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if (
                response.status != 200
                or response.getheader("Content-Encoding") is not None
            ):
                raise AuthorizationError("session unavailable")
            value = strict_object(response.read(32769), maximum=32768)
        finally:
            connection.close()
        audience = value.get("aud")
        if type(audience) is str:
            audience = [audience]
        if (
            value.get("active") is not True
            or value.get("iss") != self.config["issuer"]
            or value.get("sub") != self.config["subject"]
            or type(audience) is not list
            or self.config["client_id"] not in audience
            or value.get("client_id", value.get("azp")) != self.config["client_id"]
            or value.get("acr") != self.config["required_acr"]
        ):
            raise AuthorizationError(
                "session scope or authentication strength unavailable"
            )
        methods = value.get("amr")
        if type(methods) is not list or self.config["required_amr"] not in methods:
            raise AuthorizationError("required MFA method absent")
        for field in ("auth_time", "exp"):
            if type(value.get(field)) is not int:
                raise AuthorizationError("session times unavailable")
        now = datetime.now(UTC)
        authenticated, expires = (
            datetime.fromtimestamp(value["auth_time"], UTC),
            datetime.fromtimestamp(value["exp"], UTC),
        )
        if (
            not authenticated <= now < expires
            or (now - authenticated).total_seconds() > 43200
        ):
            raise AuthorizationError("session expired")
        client_roles = (
            value.get("resource_access", {})
            .get(self.config["client_id"], {})
            .get("roles", [])
        )
        if type(client_roles) is not list or "viewer" not in client_roles:
            raise AuthorizationError("viewer role absent")
        principal = OperatorPrincipal(
            issuer=self.config["issuer"],
            tenant=self.config["tenant"],
            subject=value["sub"],
            session_id=value["sid"],
            client_id=self.config["client_id"],
            roles=tuple(
                role
                for role in ("viewer", "remote_operator", "recovery_operator")
                if role in client_roles
            ),
            authenticated_at=authenticated,
            expires_at=expires,
            mfa=True,
        )
        return 200, {
            "issuer": principal.issuer,
            "tenant": principal.tenant,
            "subject": principal.subject,
            "session_id": principal.session_id,
            "client_id": principal.client_id,
            "roles": list(principal.roles),
            "authenticated_at": principal.authenticated_at.isoformat(),
            "expires_at": principal.expires_at.isoformat(),
            "mfa": principal.mfa,
        }


def factory(configuration: dict[str, Any]) -> tuple[Operation, frozenset[str]]:
    return OIDCBridge(configuration).handle, frozenset({"/v1/operator-sessions/verify"})


def main(argv: Sequence[str] | None = None) -> int:
    return service_main(factory, argv)


if __name__ == "__main__":
    raise SystemExit(main())
