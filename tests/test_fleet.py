"""Source-stage qualification suite; execute during the requested testing phase."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from northgate_rmm.fleet_access import load_grants
from northgate_rmm.fleet_admin import export_events
from northgate_rmm.fleet_models import validate_record, window_open
from northgate_rmm.fleet_store import Conflict, FleetStore
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.operator_api import OperatorAuthorizationPolicy, OperatorPrincipal


def principal() -> OperatorPrincipal:
    now = datetime.now(UTC)
    return OperatorPrincipal(
        "https://identity.example",
        "lab",
        "owner",
        "session",
        "rmm",
        ("viewer", "remote_operator"),
        now,
        now + timedelta(hours=1),
        True,
    )


def test_scoped_technician_does_not_inherit_owner_permissions() -> None:
    endpoint, other = str(uuid4()), str(uuid4())
    grants = load_grants(
        [
            {
                "subject": "technician",
                "endpoints": [endpoint],
                "permissions": ["view", "manage"],
            }
        ]
    )
    policy = OperatorAuthorizationPolicy(
        "https://identity.example", "lab", "owner", "rmm", grants=grants
    )
    assert policy.admits("technician")
    assert policy.permits("technician", endpoint, "manage")
    assert not policy.permits("technician", endpoint, "recovery")
    assert not policy.permits("technician", other, "view")
    assert not policy.permits("unknown", endpoint, "view")


def test_overnight_maintenance_window_belongs_to_start_day() -> None:
    window = {"days": [0], "start": "23:00", "end": "02:00"}
    assert window_open(window, datetime(2026, 9, 7, 23, 30, tzinfo=UTC).timestamp())
    assert window_open(window, datetime(2026, 9, 8, 1, 30, tzinfo=UTC).timestamp())
    assert not window_open(window, datetime(2026, 9, 8, 2, 0, tzinfo=UTC).timestamp())
    assert not window_open(window, datetime(2026, 9, 8, 23, 30, tzinfo=UTC).timestamp())


def test_fleet_policy_rejects_unbounded_or_secret_bulk_actions() -> None:
    for action in ("shell.start", "bitlocker.escrow", "recovery.rotate", "files.write"):
        with pytest.raises(ValueError):
            validate_record(
                "policy", {"name": "Invalid", "action": action, "params": {}}
            )
    with pytest.raises(ValueError):
        validate_record(
            "policy", {"name": "Too wide", "action": "posture", "concurrency": 17}
        )


def test_record_revision_conflict_preserves_newer_editor(tmp_path: Path) -> None:
    store = FleetStore(ManagementStore(tmp_path, b"x" * 16))
    key = str(uuid4())
    record = store.put("group", key, {"name": "Original", "parent": ""}, "owner")
    store.put(
        "group", key, {"name": "Updated", "parent": ""}, "owner", record["revision"]
    )
    with pytest.raises(Conflict):
        store.put(
            "group", key, {"name": "Stale", "parent": ""}, "owner", record["revision"]
        )
    assert store.get("group", key)["value"]["name"] == "Updated"
    assert b"Updated" not in store.management.path.read_bytes()


def test_durable_dispatch_key_does_not_duplicate_jobs(tmp_path: Path) -> None:
    store = ManagementStore(tmp_path, b"x" * 16)
    endpoint, identity, key = uuid4(), uuid4(), str(uuid4())
    p = principal()
    first = store.add(
        endpoint, identity, p, "posture", {}, "Bearer synthetic", identifier=key
    )
    second = store.add(
        endpoint, identity, p, "posture", {}, "Bearer synthetic", identifier=key
    )
    assert first == second
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1
    with pytest.raises(ValueError):
        store.add(
            uuid4(), identity, p, "posture", {}, "Bearer synthetic", identifier=key
        )


def test_policy_requires_explicit_valid_utc_window() -> None:
    with pytest.raises(ValueError):
        validate_record(
            "policy",
            {
                "name": "Bad window",
                "action": "posture",
                "window": {"days": [0], "start": "25:00", "end": "26:00"},
            },
        )


def test_dispatch_id_cannot_be_reused_for_changed_parameters(tmp_path: Path) -> None:
    store = ManagementStore(tmp_path, b"x" * 16)
    endpoint, identity, key = uuid4(), uuid4(), str(uuid4())
    p = principal()
    store.add(endpoint, identity, p, "posture", {}, "Bearer synthetic", identifier=key)
    with pytest.raises(ValueError):
        store.add(
            endpoint,
            identity,
            p,
            "posture",
            {"changed": True},
            "Bearer synthetic",
            identifier=key,
        )


def test_event_export_resumes_after_retention_without_exporting_secrets(
    tmp_path: Path,
) -> None:
    store = ManagementStore(tmp_path / "state", b"x" * 16)
    output, checkpoint = tmp_path / "events.jsonl", tmp_path / "cursor.json"
    store.event(
        "",
        "fleet",
        "fleet.rollout.completed",
        {
            "run": "first",
            "authorization": "must-not-export",
            "note": "private-note",
        },
    )
    assert export_events(store, output, checkpoint) == 1
    assert export_events(store, output, checkpoint) == 0
    with store.connect() as db:
        db.execute("DELETE FROM evidence")
    store.event("", "fleet", "fleet.rollout.completed", {"run": "second"})
    assert export_events(store, output, checkpoint) == 1
    content = output.read_text()
    assert len(content.splitlines()) == 2
    assert "must-not-export" not in content
    assert "private-note" not in content
