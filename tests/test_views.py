from datetime import UTC, datetime

from northgate_rmm.control_plane import ControlPlane
from northgate_rmm.domain import Platform
from northgate_rmm.simulator import SyntheticAgent
from northgate_rmm.views import (
    render_endpoint_detail,
    render_endpoint_list,
    render_endpoint_page,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def test_list_view_escapes_endpoint_controlled_values() -> None:
    plane = ControlPlane()
    agent = SyntheticAgent.enroll(
        plane,
        display_name="<script>alert(1)</script>",
        platform=Platform.LINUX,
        architecture='x86_64"><img src=x>',
        now=NOW,
    )

    rendered = render_endpoint_list(plane, now=NOW)

    assert "<script>" not in rendered
    assert "<img" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert str(agent.endpoint_id) in rendered


def test_list_page_emits_only_the_canonical_next_cursor() -> None:
    plane = ControlPlane()
    agent = SyntheticAgent.enroll(
        plane,
        display_name="linux-page-01",
        platform=Platform.LINUX,
        architecture="amd64",
        now=NOW,
    )

    rendered = render_endpoint_page(
        plane,
        plane.list_endpoints(),
        next_after=agent.endpoint_id,
        now=NOW,
    )

    assert f'href="/endpoints?after={agent.endpoint_id}"' in rendered


def test_detail_view_keeps_lifecycle_and_health_separate() -> None:
    plane = ControlPlane()
    agent = SyntheticAgent.enroll(
        plane,
        display_name="linux-sim-01",
        platform=Platform.LINUX,
        architecture="x86_64",
        now=NOW,
    )
    plane.revoke_identity(
        agent.identity_id,
        reason="<revoked & retained>",
        actor_id="security-admin",
        now=NOW,
    )

    rendered = render_endpoint_detail(plane, agent.endpoint_id, now=NOW)

    assert "<dt>Lifecycle</dt><dd>revoked</dd>" in rendered
    assert "<dt>Health</dt><dd>offline</dd>" in rendered
    assert "&lt;revoked &amp; retained&gt;" in rendered
