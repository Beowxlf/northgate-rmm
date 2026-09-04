from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from northgate_rmm.control_plane import ControlPlane
from northgate_rmm.domain import Platform
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.operator_api import (
    OperatorApplication,
    OperatorAuthorizationPolicy,
    OperatorPrincipal,
    OperatorRequest,
)
from northgate_rmm.simulator import SyntheticAgent

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
AUTHORIZATION = "Bearer synthetic-operator-session"  # gitleaks:allow


@dataclass
class RecordingVerifier:
    principal: OperatorPrincipal
    rejection: bool = False
    calls: list[tuple[str, datetime]] = field(default_factory=list)

    def verify(self, authorization: str, *, now: datetime) -> OperatorPrincipal:
        self.calls.append((authorization, now))
        if self.rejection:
            raise AuthorizationError("external session is not current")
        return self.principal


class FailingAuditPlane(ControlPlane):
    def __init__(self) -> None:
        super().__init__()
        self.list_called = False

    def list_endpoints(self):  # type: ignore[no-untyped-def]
        self.list_called = True
        return super().list_endpoints()

    def record_operator_access(self, **_kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("audit sink unavailable")


def principal() -> OperatorPrincipal:
    return OperatorPrincipal(
        issuer="https://idp.test/issuer",
        tenant="northgate-test",
        subject="operator-001",
        session_id="session-001",
        client_id="northgate-rmm-test",
        roles=("viewer",),
        authenticated_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=30),
        mfa=True,
    )


def policy() -> OperatorAuthorizationPolicy:
    current = principal()
    return OperatorAuthorizationPolicy(
        issuer=current.issuer,
        tenant=current.tenant,
        subject=current.subject,
        client_id=current.client_id,
    )


def application(
    *, principal_value: OperatorPrincipal | None = None
) -> tuple[OperatorApplication, ControlPlane, RecordingVerifier, SyntheticAgent]:
    plane = ControlPlane()
    agent = SyntheticAgent.enroll(
        plane,
        display_name="<script>endpoint</script>",
        platform=Platform.LINUX,
        architecture='amd64"><img src=x>',
        now=NOW - timedelta(minutes=10),
    )
    heartbeat = agent.heartbeat(now=NOW - timedelta(minutes=2))
    plane.ingest_heartbeat(
        authenticated_identity_id=agent.identity_id,
        message=heartbeat,
        received_at=NOW - timedelta(minutes=2),
    )
    verifier = RecordingVerifier(principal_value or principal())
    return OperatorApplication(plane, verifier, policy()), plane, verifier, agent


def test_operator_list_revalidates_renders_server_freshness_and_audits() -> None:
    app, plane, verifier, agent = application()

    response = app.handle(
        OperatorRequest("GET", "/endpoints", AUTHORIZATION),
        received_at=NOW,
    )

    assert response.status == 200
    assert b"&lt;script&gt;endpoint&lt;/script&gt;" in response.body
    assert b"<script>endpoint</script>" not in response.body
    assert b"<img" not in response.body
    assert b"stale" in response.body
    assert str(agent.endpoint_id).encode() in response.body
    assert verifier.calls == [(AUTHORIZATION, NOW)]
    assert ("cache-control", "no-store") in response.headers
    assert any(name == "content-security-policy" for name, _value in response.headers)
    audit = plane.audit_events[-1]
    assert audit.action == "endpoint.list.read"
    assert audit.actor_id == "operator-001"
    assert audit.decision == "accepted"
    assert ("session_id", "session-001") in audit.metadata
    authentication = plane.audit_events[-2]
    assert authentication.action == "operator.authenticate"
    assert authentication.decision == "accepted"


def test_operator_detail_is_read_only_escaped_and_audited() -> None:
    app, plane, _verifier, agent = application()

    response = app.handle(
        OperatorRequest("GET", f"/endpoints/{agent.endpoint_id}", AUTHORIZATION),
        received_at=NOW,
    )

    assert response.status == 200
    assert b"&lt;script&gt;endpoint&lt;/script&gt;" in response.body
    assert plane.audit_events[-1].action == "endpoint.detail.read"
    assert plane.audit_events[-1].subject == f"endpoint:{agent.endpoint_id}"


@pytest.mark.parametrize("authorization", [None, "", "x" * 4_097, "\ud800"])
def test_operator_authentication_failures_are_generic_and_audited(
    authorization: str | None,
) -> None:
    app, plane, verifier, _agent = application()

    response = app.handle(
        OperatorRequest("GET", "/endpoints", authorization),
        received_at=NOW,
    )

    assert response.status == 401
    assert response.body == b'{"error":"unauthorized"}'
    assert ("www-authenticate", "Bearer") in response.headers
    assert verifier.calls == []
    audit = plane.audit_events[-1]
    assert audit.action == "operator.authenticate"
    assert audit.decision == "rejected"
    assert AUTHORIZATION not in repr(audit)


def test_external_verifier_rejection_is_generic_and_does_not_log_credential() -> None:
    app, plane, verifier, _agent = application()
    verifier.rejection = True

    response = app.handle(
        OperatorRequest("GET", "/endpoints", AUTHORIZATION),
        received_at=NOW,
    )

    assert response.status == 401
    assert verifier.calls == [(AUTHORIZATION, NOW)]
    assert AUTHORIZATION not in repr(plane.audit_events[-1])


def test_operator_session_is_revalidated_on_every_request() -> None:
    app, _plane, verifier, _agent = application()

    accepted = app.handle(
        OperatorRequest("GET", "/endpoints", AUTHORIZATION),
        received_at=NOW,
    )
    verifier.rejection = True
    rejected = app.handle(
        OperatorRequest("GET", "/endpoints", AUTHORIZATION),
        received_at=NOW + timedelta(seconds=1),
    )

    assert accepted.status == 200
    assert rejected.status == 401
    assert verifier.calls == [
        (AUTHORIZATION, NOW),
        (AUTHORIZATION, NOW + timedelta(seconds=1)),
    ]


def test_operator_data_is_not_read_when_authentication_audit_fails() -> None:
    store = FailingAuditPlane()
    verifier = RecordingVerifier(principal())
    app = OperatorApplication(store, verifier, policy())

    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        app.handle(
            OperatorRequest("GET", "/endpoints", AUTHORIZATION),
            received_at=NOW,
        )

    assert not store.list_called


@pytest.mark.parametrize(
    "changed",
    [
        {"issuer": "https://other.test/issuer"},
        {"tenant": "other"},
        {"subject": "other"},
        {"client_id": "other"},
        {"roles": ("operator",)},
        {"mfa": False},
        {"authenticated_at": NOW + timedelta(seconds=1)},
        {"authenticated_at": NOW - timedelta(hours=13)},
        {"expires_at": NOW},
    ],
)
def test_operator_identity_scope_assurance_and_time_fail_closed(
    changed: dict[str, object],
) -> None:
    changed_principal = replace(principal(), **changed)  # type: ignore[arg-type]
    app, plane, _verifier, _agent = application(principal_value=changed_principal)

    response = app.handle(
        OperatorRequest("GET", "/endpoints", AUTHORIZATION),
        received_at=NOW,
    )

    assert response.status == 403
    assert response.body == b'{"error":"forbidden"}'
    assert plane.audit_events[-1].action == "operator.authorize"
    assert plane.audit_events[-1].decision == "rejected"


@pytest.mark.parametrize(
    "request_value",
    [
        OperatorRequest("POST", "/endpoints", AUTHORIZATION),
        OperatorRequest("GET", "/endpoints", AUTHORIZATION, "page=1"),
        OperatorRequest("GET", "/unknown", AUTHORIZATION),
        OperatorRequest("GET", "/endpoints/NOT-A-UUID", AUTHORIZATION),
        OperatorRequest(
            "GET",
            "/endpoints/AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
            AUTHORIZATION,
        ),
    ],
)
def test_operator_route_contract_has_no_mutation_or_ambiguous_route(
    request_value: OperatorRequest,
) -> None:
    app, plane, verifier, _agent = application()

    response = app.handle(request_value, received_at=NOW)

    assert response.status == 404
    assert verifier.calls == [(AUTHORIZATION, NOW)]
    assert plane.audit_events[-1].decision == "rejected"


def test_unknown_endpoint_is_generic_and_audited() -> None:
    app, plane, _verifier, _agent = application()

    response = app.handle(
        OperatorRequest(
            "GET",
            "/endpoints/00000000-0000-0000-0000-000000000000",
            AUTHORIZATION,
        ),
        received_at=NOW,
    )

    assert response.status == 404
    assert response.body == b'{"error":"not_found"}'
    assert plane.audit_events[-1].action == "endpoint.detail.read"
    assert plane.audit_events[-1].decision == "rejected"


def test_operator_models_reject_invalid_sessions_and_policy() -> None:
    with pytest.raises(ValidationError, match="roles"):
        replace(principal(), roles=("viewer", "viewer"))
    with pytest.raises(ValidationError, match="lifetime"):
        replace(principal(), expires_at=principal().authenticated_at)
    with pytest.raises(ValidationError, match="maximum session age"):
        replace(policy(), maximum_session_age=timedelta(days=2))
    with pytest.raises(ValidationError, match="required_role"):
        replace(policy(), required_role="r" * 65)
    with pytest.raises(ValidationError, match="subject"):
        replace(principal(), subject="operator\n001")
    with pytest.raises(ValidationError, match="subject"):
        replace(principal(), subject="x" * 257)
    with pytest.raises(ValidationError, match="subject"):
        replace(policy(), subject="x" * 257)
    with pytest.raises(ValidationError, match="mfa"):
        replace(principal(), mfa=cast(bool, "false"))
