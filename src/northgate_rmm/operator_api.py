"""Authenticated, read-only operator application for the V1B endpoint views.

The application accepts identity facts only from an external verifier, pins the
expected identity-provider tuple, revalidates on every request, and records the
authorization decision before returning endpoint data. It opens no listener and
contains no mutation, job, shell, or remote-access operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import UUID, uuid4

from northgate_rmm.errors import AuthorizationError, NotFoundError, ValidationError
from northgate_rmm.views import (
    EndpointReader,
    render_endpoint_detail,
    render_endpoint_list,
)

MAX_AUTHORIZATION_HEADER_BYTES = 4_096
MAX_OPERATOR_VALUE_LENGTH = 512
MAX_OPERATOR_PATH_LENGTH = 256
MAX_OPERATOR_SESSION_AGE = timedelta(hours=12)


@dataclass(frozen=True, slots=True)
class OperatorPrincipal:
    """Current identity facts returned by the external IdP session verifier."""

    issuer: str
    tenant: str
    subject: str
    session_id: str
    client_id: str
    roles: tuple[str, ...]
    authenticated_at: datetime
    expires_at: datetime
    mfa: bool

    def __post_init__(self) -> None:
        for name, value in (
            ("issuer", self.issuer),
            ("tenant", self.tenant),
            ("subject", self.subject),
            ("session_id", self.session_id),
            ("client_id", self.client_id),
        ):
            if (
                not value
                or len(value) > MAX_OPERATOR_VALUE_LENGTH
                or not value.isprintable()
            ):
                raise ValidationError(f"operator {name} is invalid")
        if not self.roles or len(self.roles) > 8:
            raise ValidationError("operator roles are invalid")
        if any(not role or len(role) > 64 for role in self.roles):
            raise ValidationError("operator role is invalid")
        if len(set(self.roles)) != len(self.roles):
            raise ValidationError("operator roles contain a duplicate")
        if self.authenticated_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValidationError("operator session times must be timezone-aware")
        if self.expires_at <= self.authenticated_at:
            raise ValidationError("operator session lifetime is invalid")


@dataclass(frozen=True, slots=True)
class OperatorAuthorizationPolicy:
    """Pinned single-operator identity scope supplied by deployment config."""

    issuer: str
    tenant: str
    subject: str
    client_id: str
    required_role: str = "viewer"
    maximum_session_age: timedelta = MAX_OPERATOR_SESSION_AGE

    def __post_init__(self) -> None:
        for name, value in (
            ("issuer", self.issuer),
            ("tenant", self.tenant),
            ("subject", self.subject),
            ("client_id", self.client_id),
            ("required_role", self.required_role),
        ):
            if (
                not value
                or len(value) > MAX_OPERATOR_VALUE_LENGTH
                or not value.isprintable()
            ):
                raise ValidationError(f"operator policy {name} is invalid")
        if not timedelta(minutes=5) <= self.maximum_session_age <= timedelta(hours=24):
            raise ValidationError("operator maximum session age is invalid")


@dataclass(frozen=True, slots=True)
class OperatorRequest:
    method: str
    path: str
    authorization: str | None
    query_string: str = ""


@dataclass(frozen=True, slots=True)
class OperatorResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class OperatorSessionVerifier(Protocol):
    def verify(self, authorization: str, *, now: datetime) -> OperatorPrincipal: ...


class OperatorStore(EndpointReader, Protocol):
    def record_operator_access(
        self,
        *,
        actor_id: str,
        subject: str,
        action: str,
        decision: str,
        reason: str,
        correlation_id: UUID,
        now: datetime,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> None: ...


class OperatorApplication:
    """Authenticate, authorize, audit, and render the two V1B read routes."""

    def __init__(
        self,
        store: OperatorStore,
        verifier: OperatorSessionVerifier,
        policy: OperatorAuthorizationPolicy,
    ) -> None:
        self._store = store
        self._verifier = verifier
        self._policy = policy

    def handle(
        self, request: OperatorRequest, *, received_at: datetime
    ) -> OperatorResponse:
        if received_at.tzinfo is None:
            raise ValidationError("received_at must be timezone-aware")
        now = received_at.astimezone(UTC)
        correlation_id = uuid4()
        try:
            principal = self._authenticate(
                request.authorization,
                now=now,
                correlation_id=correlation_id,
            )
        except AuthorizationError:
            return _error(401, "unauthorized")
        self._audit(
            principal,
            subject="operator:endpoint-views",
            action="operator.authenticate",
            decision="accepted",
            reason="external session verified",
            correlation_id=correlation_id,
            now=now,
        )
        denial = self._authorization_denial(principal, now=now)
        if denial is not None:
            self._audit(
                principal,
                subject="operator:endpoint-views",
                action="operator.authorize",
                decision="rejected",
                reason=denial,
                correlation_id=correlation_id,
                now=now,
            )
            return _error(403, "forbidden")
        if (
            request.method != "GET"
            or request.query_string
            or not 1 <= len(request.path) <= MAX_OPERATOR_PATH_LENGTH
        ):
            self._audit(
                principal,
                subject="operator:endpoint-views",
                action="operator.request",
                decision="rejected",
                reason="operator route contract rejected",
                correlation_id=correlation_id,
                now=now,
            )
            return _error(404, "not_found")
        if request.path == "/endpoints":
            body = render_endpoint_list(self._store, now=now).encode("utf-8")
            self._audit(
                principal,
                subject="endpoint:collection",
                action="endpoint.list.read",
                decision="accepted",
                reason="authenticated viewer read",
                correlation_id=correlation_id,
                now=now,
            )
            return _html(body)
        endpoint_id = _endpoint_id_from_path(request.path)
        if endpoint_id is None:
            self._audit(
                principal,
                subject="operator:endpoint-views",
                action="operator.request",
                decision="rejected",
                reason="operator route not found",
                correlation_id=correlation_id,
                now=now,
            )
            return _error(404, "not_found")
        try:
            body = render_endpoint_detail(self._store, endpoint_id, now=now).encode(
                "utf-8"
            )
        except NotFoundError:
            self._audit(
                principal,
                subject=f"endpoint:{endpoint_id}",
                action="endpoint.detail.read",
                decision="rejected",
                reason="endpoint was not found",
                correlation_id=correlation_id,
                now=now,
            )
            return _error(404, "not_found")
        self._audit(
            principal,
            subject=f"endpoint:{endpoint_id}",
            action="endpoint.detail.read",
            decision="accepted",
            reason="authenticated viewer read",
            correlation_id=correlation_id,
            now=now,
        )
        return _html(body)

    def _authenticate(
        self,
        authorization: str | None,
        *,
        now: datetime,
        correlation_id: UUID,
    ) -> OperatorPrincipal:
        try:
            encoded_authorization = (
                authorization.encode("utf-8") if authorization is not None else b""
            )
        except UnicodeEncodeError:
            encoded_authorization = b""
        if not 1 <= len(encoded_authorization) <= MAX_AUTHORIZATION_HEADER_BYTES:
            self._store.record_operator_access(
                actor_id="unauthenticated",
                subject="operator:endpoint-views",
                action="operator.authenticate",
                decision="rejected",
                reason="operator credential missing or oversized",
                correlation_id=correlation_id,
                now=now,
            )
            raise AuthorizationError("operator authentication failed")
        try:
            return self._verifier.verify(cast(str, authorization), now=now)
        except (AuthorizationError, ValidationError):
            self._store.record_operator_access(
                actor_id="unauthenticated",
                subject="operator:endpoint-views",
                action="operator.authenticate",
                decision="rejected",
                reason="external session verification failed",
                correlation_id=correlation_id,
                now=now,
            )
            raise AuthorizationError("operator authentication failed") from None

    def _authorization_denial(
        self,
        principal: OperatorPrincipal,
        *,
        now: datetime,
    ) -> str | None:
        if (
            principal.issuer != self._policy.issuer
            or principal.tenant != self._policy.tenant
            or principal.subject != self._policy.subject
            or principal.client_id != self._policy.client_id
        ):
            return "operator identity scope did not match policy"
        if self._policy.required_role not in principal.roles or not principal.mfa:
            return "operator assurance or role was insufficient"
        authenticated_at = principal.authenticated_at.astimezone(UTC)
        expires_at = principal.expires_at.astimezone(UTC)
        if authenticated_at > now or not now < expires_at:
            return "operator session was not current"
        if now - authenticated_at > self._policy.maximum_session_age:
            return "operator session exceeded maximum age"
        return None

    def _audit(
        self,
        principal: OperatorPrincipal,
        *,
        subject: str,
        action: str,
        decision: str,
        reason: str,
        correlation_id: UUID,
        now: datetime,
    ) -> None:
        self._store.record_operator_access(
            actor_id=principal.subject,
            subject=subject,
            action=action,
            decision=decision,
            reason=reason,
            correlation_id=correlation_id,
            now=now,
            metadata=(
                ("client_id", principal.client_id),
                ("issuer", principal.issuer),
                ("session_id", principal.session_id),
                ("tenant", principal.tenant),
            ),
        )


def _endpoint_id_from_path(path: str) -> UUID | None:
    prefix = "/endpoints/"
    if not path.startswith(prefix):
        return None
    value = path.removeprefix(prefix)
    try:
        endpoint_id = UUID(value)
    except ValueError:
        return None
    if str(endpoint_id) != value:
        return None
    return endpoint_id


def _html(body: bytes) -> OperatorResponse:
    return OperatorResponse(
        status=200, headers=_headers("text/html; charset=utf-8"), body=body
    )


def _error(status: int, code: str) -> OperatorResponse:
    body = (f'{{"error":"{code}"}}').encode("ascii")
    headers = list(_headers("application/json"))
    if status == 401:
        headers.append(("www-authenticate", "Bearer"))
    return OperatorResponse(status=status, headers=tuple(headers), body=body)


def _headers(content_type: str) -> tuple[tuple[str, str], ...]:
    return (
        ("content-type", content_type),
        ("cache-control", "no-store"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'",
        ),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
    )
