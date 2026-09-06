"""Escaped, server-rendered Phase 1 endpoint read models.

These functions return HTML fragments only. They do not open a listener or
provide a mutation, job, shell, or remote-access route.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from typing import Protocol
from uuid import UUID

from northgate_rmm.domain import Endpoint, EndpointIdentity, EndpointStatus
from northgate_rmm.presentation import document


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
    history_rows = []
    counts = {"online": 0, "stale": 0, "offline": 0}
    for endpoint in endpoints:
        status = reader.endpoint_status(endpoint.endpoint_id, now=now)
        active = status.lifecycle.value == "active"
        if active:
            counts[status.health.value] += 1
        target_rows = rows if active else history_rows
        target_rows.append(
            "<tr>"
            '<td><div class="device"><span class="device-icon" '
            'aria-hidden="true">▣</span><div>'
            f'<a href="/endpoints/{endpoint.endpoint_id}">'
            f"{escape(endpoint.display_name)}</a><small>"
            f"{str(endpoint.endpoint_id)[:8]}</small></div></div></td>"
            f"<td>{escape(endpoint.platform.value)}</td>"
            f'<td class="secondary">{escape(endpoint.architecture)}</td>'
            f"<td>{_badge(status.lifecycle.value)}</td>"
            f"<td>{_badge(status.health.value)}</td>"
            f'<td class="secondary">{_heartbeat(status.last_heartbeat_at, now)}</td>'
            "</tr>"
        )
    active_count = len(rows)
    history_count = len(history_rows)
    body = "".join(rows) or (
        '<tr><td colspan="6" class="empty"><strong>'
        "No active endpoints on this page</strong>"
        "Enrolled devices will appear here with their latest monitoring "
        "status.</td></tr>"
    )
    table_header = (
        '<thead><tr><th scope="col">Device name</th>'
        '<th scope="col">Platform</th><th scope="col">Architecture</th>'
        '<th scope="col">Lifecycle</th><th scope="col">Health</th>'
        '<th scope="col">Last heartbeat</th></tr></thead>'
    )
    history = (
        '<details class="panel history"><summary>Enrollment history · '
        f"{history_count} inactive records on this page</summary>"
        '<p class="note">Retained for audit. These identities are excluded from '
        'active device health totals.</p><div class="table-scroll">'
        f'<table aria-label="Enrollment history">{table_header}<tbody>'
        + "".join(history_rows)
        + "</tbody></table></div></details>"
        if history_count
        else ""
    )
    next_link = (
        f'<nav aria-label="Pagination"><a class="button" '
        f'href="/endpoints?after={next_after}">Next page →</a></nav>'
        if next_after is not None
        else "<span>End of results</span>"
    )
    metrics = _metric(
        "Active devices", active_count, "On this page · history excluded", "", "▦"
    )
    for health, label, note in (
        ("online", "Online", "Reporting normally"),
        ("stale", "Stale", "Heartbeat delayed"),
        ("offline", "Offline", "No recent heartbeat"),
    ):
        metrics += _metric(label, counts[health], note, health, "●")
    return document(
        "Endpoints",
        '<section class="page-heading"><div><div class="eyebrow">Device '
        "management</div>"
        '<h1>Endpoints</h1><p class="description">An overview of your '
        "active devices and their latest health. Open a device for details.</p>"
        '</div><a class="button" href="/endpoints">↻ Refresh overview</a></section>'
        f'<section class="metrics" aria-label="Status totals for this '
        f'page">{metrics}</section>'
        '<section class="panel" aria-labelledby="inventory-heading"><div '
        'class="panel-heading">'
        f'<div><h2 id="inventory-heading">Active inventory <span '
        f'class="count">{active_count} devices</span></h2>'
        "<p>Select a device to view its health, activity and identity.</p></div>"
        '<span class="secondary">Current page</span></div><div class="table-scroll">'
        '<table aria-label="Endpoint inventory"><thead><tr>'
        '<th scope="col">Device name</th><th scope="col">Platform</th><th '
        'scope="col">Architecture</th>'
        '<th scope="col">Lifecycle</th><th scope="col">Health</th><th '
        'scope="col">Last heartbeat</th>'
        f'</tr></thead><tbody>{body}</tbody></table></div><div class="table-footer">'
        f"<span>{active_count} active · {history_count} historical on this page "
        f"· Times in UTC</span>{next_link}</div></section>{history}",
        updated=_time(now),
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

    def panel(title: str, selected: tuple[str, ...]) -> str:
        items = "".join(
            f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>"
            for label, value in values
            if label in selected
        )
        return (
            f'<section class="panel"><div class="panel-heading"><h2>{title}</h2></div>'
            f'<dl class="facts">{items}</dl></section>'
        )

    return document(
        endpoint.display_name,
        '<a class="back" href="/endpoints">← All endpoints</a>'
        '<section class="page-heading"><div><div class="eyebrow">Device profile</div>'
        f'<h1>{escape(endpoint.display_name)}</h1><p class="description">'
        f"{escape(endpoint.platform.value)} · {escape(endpoint.architecture)}</p>"
        f'<div class="status-strip">'
        f"{_badge(status.health.value)}{_badge(status.lifecycle.value)}</div></div>"
        f'<a class="button" href="/endpoints/{endpoint.endpoint_id}">↻ '
        f"Refresh device</a></section>"
        '<div class="detail-grid"><div>'
        + panel(
            "Device overview",
            (
                "Endpoint ID",
                "Display name",
                "Platform",
                "Architecture",
                "Lifecycle",
                "Health",
            ),
        )
        + panel(
            "Identity &amp; trust",
            ("Identity ID", "Fingerprint", "Revoked", "Revocation reason"),
        )
        + "</div><div>"
        + panel("Activity", ("Enrolled", "Last receipt", "Last heartbeat"))
        + (
            '<section class="panel"><div class="panel-heading"><div>'
            "<h2>Inspection and diagnostics</h2>"
            "<p>View system data, run read-only checks and compare saved baselines.</p>"
            f'<a class="button" href="/remote/{endpoint_id}/inspect">'
            "Open inspection toolbox</a></div></div></section>"
        )
        + (
            '<section class="panel"><div class="panel-heading"><div>'
            "<h2>Remote access</h2><p>Open Remote Desktop or a browser terminal.</p>"
            f'<a class="button" href="/remote/{endpoint_id}/desktop.rdp">'
            "Open Remote Desktop</a> "
            f'<a class="button" href="/remote/{endpoint_id}">Connect SSH Terminal</a>'
            "</div></div></section>"
            if status.lifecycle.value == "active" and status.health.value == "online"
            else '<section class="panel"><p class="note">Remote access is unavailable '
            "while this device is offline or its enrollment is inactive.</p></section>"
        )
        + '<section class="panel"><div class="panel-heading"><h2>About '
        "device health</h2></div>"
        '<p class="note">Health reflects the most recent agent heartbeat. '
        "Lifecycle shows whether the device identity is active or "
        "revoked.</p>"
        "</section></div></div>",
        updated=_time(now),
    )


def _badge(value: str) -> str:
    return (
        f'<span class="badge {escape(value, quote=True)}"><span '
        f'class="dot" aria-hidden="true"></span>{escape(value)}</span>'
    )


def _metric(label: str, total: int, note: str, state: str, icon: str) -> str:
    return (
        f'<div class="metric {state}"><div class="metric-top"><span>{label}</span>'
        f'<span class="metric-icon" aria-hidden="true">{icon}</span></div>'
        f"<strong>{total}</strong><small>{note}</small></div>"
    )


def _time(value: datetime | None) -> str:
    if value is None:
        return "Never"
    return value.astimezone(UTC).strftime("%d %b %Y, %H:%M:%S UTC")


def _heartbeat(value: datetime | None, now: datetime) -> str:
    if value is None:
        return "Never received"
    seconds = max(0, int((now - value).total_seconds()))
    if seconds < 60:
        age = f"{seconds}s ago"
    elif seconds < 3600:
        age = f"{seconds // 60}m ago"
    elif seconds < 86400:
        age = f"{seconds // 3600}h ago"
    else:
        age = f"{seconds // 86400}d ago"
    return (
        f'<time datetime="{value.isoformat()}">{age}</time>'
        f'<small class="heartbeat-time">{_time(value)}</small>'
    )
