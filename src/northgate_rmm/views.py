"""Escaped, server-rendered Phase 1 endpoint read models.

These functions return HTML fragments only. They do not open a listener or
provide a mutation, job, shell, or remote-access route.
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Protocol
from uuid import UUID

from northgate_rmm.domain import Endpoint, EndpointIdentity, EndpointStatus


class EndpointReader(Protocol):
    def list_endpoints(self) -> tuple[Endpoint, ...]: ...

    def get_endpoint(self, endpoint_id: UUID) -> Endpoint: ...

    def get_identity(self, identity_id: UUID) -> EndpointIdentity: ...

    def endpoint_status(
        self, endpoint_id: UUID, *, now: datetime
    ) -> EndpointStatus: ...


def render_endpoint_list(reader: EndpointReader, *, now: datetime) -> str:
    """Render an escaped endpoint table from the read-only control-plane API."""

    return render_endpoint_page(
        reader,
        reader.list_endpoints(),
        next_after=None,
        now=now,
    )


def render_endpoint_page(
    reader: EndpointReader,
    endpoints: tuple[Endpoint, ...],
    *,
    next_after: UUID | None,
    now: datetime,
) -> str:
    """Render one already-bounded endpoint page and an opaque next cursor."""

    rows = []
    for endpoint in endpoints:
        status = reader.endpoint_status(endpoint.endpoint_id, now=now)
        rows.append(
            "<tr>"
            f'<td><a href="/endpoints/{endpoint.endpoint_id}">'
            f"{escape(endpoint.display_name)}</a></td>"
            f"<td>{escape(endpoint.platform.value)}</td>"
            f"<td>{escape(endpoint.architecture)}</td>"
            f"<td>{escape(status.lifecycle.value)}</td>"
            f"<td>{escape(status.health.value)}</td>"
            f"<td>{_time(status.last_heartbeat_at)}</td>"
            "</tr>"
        )
    body = "".join(rows) or '<tr><td colspan="6">No endpoints</td></tr>'
    next_link = (
        f'<nav><a href="/endpoints?after={next_after}">Next page</a></nav>'
        if next_after is not None
        else ""
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>NorthGate RMM endpoints</title></head><body>"
        "<main><h1>Endpoints</h1><table><thead><tr>"
        "<th>Name</th><th>Platform</th><th>Architecture</th>"
        "<th>Lifecycle</th><th>Health</th><th>Last heartbeat</th>"
        f"</tr></thead><tbody>{body}</tbody></table>{next_link}</main></body></html>"
    )


def render_endpoint_detail(
    reader: EndpointReader,
    endpoint_id: UUID,
    *,
    now: datetime,
) -> str:
    """Render one endpoint and its separate identity/freshness states."""

    endpoint = reader.get_endpoint(endpoint_id)
    identity = reader.get_identity(endpoint.identity_id)
    status = reader.endpoint_status(endpoint_id, now=now)
    values = (
        ("Endpoint ID", str(endpoint.endpoint_id)),
        ("Display name", endpoint.display_name),
        ("Platform", endpoint.platform.value),
        ("Architecture", endpoint.architecture),
        ("Identity ID", str(identity.identity_id)),
        ("Fingerprint", identity.public_key_fingerprint),
        ("Lifecycle", status.lifecycle.value),
        ("Health", status.health.value),
        ("Enrolled", _time(endpoint.enrolled_at)),
        ("Last receipt", _time(endpoint.last_receipt_at)),
        ("Last heartbeat", _time(endpoint.last_heartbeat_at)),
        ("Revoked", _time(identity.revoked_at)),
        ("Revocation reason", identity.revocation_reason or ""),
    )
    items = "".join(
        f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>" for label, value in values
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>{escape(endpoint.display_name)} — NorthGate RMM</title>"
        '</head><body><main><a href="/endpoints">Endpoints</a>'
        f"<h1>{escape(endpoint.display_name)}</h1><dl>{items}</dl>"
        "</main></body></html>"
    )


def _time(value: datetime | None) -> str:
    if value is None:
        return "Never"
    return value.isoformat()
