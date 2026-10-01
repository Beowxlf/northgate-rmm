"""Receipt validation and heartbeat age presentation boundary tests."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from northgate_rmm.remote_sessions import RemoteSessionStore
from northgate_rmm.views import _heartbeat


def test_remote_receipt_store_rejects_invalid_state_and_symlinks(
    tmp_path: Path,
) -> None:
    store = RemoteSessionStore()
    with pytest.raises(ValueError, match="state"):
        store.update(uuid4(), status="invented", outcome="transport_closed")
    with pytest.raises(ValueError, match="outcome"):
        store.update(uuid4(), status="closed", outcome="invented")
    linked = tmp_path / "sessions.sqlite3"
    linked.symlink_to(tmp_path / "outside.sqlite3")
    with pytest.raises(ValueError, match="symbolic link"):
        RemoteSessionStore(linked)


@pytest.mark.parametrize(
    "seconds,label",
    [(-1, "0s ago"), (60, "1m ago"), (3600, "1h ago"), (86400, "1d ago")],
)
def test_heartbeat_age_is_bounded_and_uses_explicit_units(
    seconds: int, label: str
) -> None:
    now = datetime(2026, 10, 1, tzinfo=UTC)
    heartbeat = now - timedelta(seconds=seconds)
    rendered = _heartbeat(heartbeat, now)
    assert label in rendered
    assert heartbeat.isoformat() in rendered
    assert "UTC" in rendered
