"""Fleet policy and maintenance-window contracts stay typed and bounded."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from northgate_rmm.fleet_models import (
    boolean,
    identifier,
    integer,
    text,
    validate_record,
    window,
    window_open,
)


@pytest.mark.parametrize("value", [None, 0, "not-a-uuid"])
def test_fleet_identifier_rejects_untyped_or_invalid_value(value: object) -> None:
    with pytest.raises(ValueError):
        identifier(value)


@pytest.mark.parametrize("value", [None, 0, "", "x" * 129, "bad\x00control"])
def test_fleet_text_is_bounded_and_printable(value: object) -> None:
    with pytest.raises(ValueError):
        text(value)


@pytest.mark.parametrize("value", [True, 1.0, "1", -1, 11])
def test_fleet_integer_requires_real_integer_in_range(value: object) -> None:
    with pytest.raises(ValueError):
        integer(value, 0, 10)


@pytest.mark.parametrize("value", [None, 0, 1, "false"])
def test_fleet_boolean_rejects_truthy_coercion(value: object) -> None:
    with pytest.raises(ValueError):
        boolean(value)


def test_fleet_scalar_normalization() -> None:
    key = str(uuid4())
    assert identifier(key.upper()) == key
    assert text("\n  bounded\ttext  ") == "bounded\ttext"
    assert text("  ", empty=True) == ""
    assert integer(0, 0, 10) == 0 and integer(10, 0, 10) == 10
    assert boolean(False) is False and boolean(True) is True


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"days": [], "start": "00:00", "end": "00:00"},
        {"days": {}, "start": "00:00", "end": "00:00"},
        {"days": [0] * 8, "start": "00:00", "end": "00:00"},
        {"days": [7], "start": "00:00", "end": "00:00"},
        {"days": [True], "start": "00:00", "end": "00:00"},
        {"days": [0], "start": 0, "end": "00:00"},
        {"days": [0], "start": "24:00", "end": "00:00"},
        {"days": [0], "start": "00:00", "end": "00:60"},
    ],
)
def test_maintenance_window_requires_explicit_bounded_utc_fields(value: object) -> None:
    with pytest.raises(ValueError):
        window(value)


def test_maintenance_day_boundaries_and_overnight_ownership() -> None:
    parsed = window({"days": [1, 0, 0], "start": "09:00", "end": "10:00"})
    assert parsed["days"] == [0, 1]
    for clock, expected in (
        ("08:59", False),
        ("09:00", True),
        ("09:59", True),
        ("10:00", False),
    ):
        now = datetime.fromisoformat("2026-09-07T" + clock + ":00+00:00").timestamp()
        assert window_open(parsed, now) is expected
    assert not window_open(parsed, datetime(2026, 9, 9, 9, 30, tzinfo=UTC).timestamp())
    overnight = window({"days": [6], "start": "23:00", "end": "02:00"})
    assert window_open(overnight, datetime(2026, 9, 6, 23, 30, tzinfo=UTC).timestamp())
    assert window_open(overnight, datetime(2026, 9, 7, 1, 30, tzinfo=UTC).timestamp())
    assert not window_open(
        overnight, datetime(2026, 9, 7, 2, 0, tzinfo=UTC).timestamp()
    )
    all_day = window({"days": [0], "start": "00:00", "end": "00:00"})
    assert window_open(all_day, datetime(2026, 9, 7, 23, 59, tzinfo=UTC).timestamp())
    assert not window_open(all_day, datetime(2026, 9, 8, 0, 0, tzinfo=UTC).timestamp())


@pytest.mark.parametrize(
    "kind,value",
    [
        ("rollout", {"name": "immutable"}),
        ("asset", []),
        ("asset", {"notes": "x" * 65536}),
        ("asset", {"tags": {}}),
        ("asset", {"tags": ["tag"] * 21}),
        ("policy", {"name": "unbounded", "action": "shell.start"}),
        ("policy", {"name": "unsupported", "action": "posture", "platform": "other"}),
        ("policy", {"name": "overwide", "action": "posture", "concurrency": 17}),
        ("policy", {"name": "invalid flag", "action": "posture", "review_canary": 1}),
        (
            "automation",
            {"name": "invalid interval", "policy": str(uuid4()), "interval": 299},
        ),
        ("rule", {"name": "unsupported", "condition": "arbitrary"}),
        ("rule", {"name": "unsupported", "condition": "offline", "severity": "urgent"}),
        ("exercise", {"name": "unsupported", "status": "approved"}),
        ("view", {"name": "unsupported", "platform": "other"}),
        ("view", {"name": "unsupported", "health": "unknown"}),
    ],
)
def test_fleet_records_reject_invalid_scope_and_execution_controls(
    kind: str, value: object
) -> None:
    with pytest.raises(ValueError):
        validate_record(kind, value)


def test_all_editable_fleet_models_preserve_explicit_scope() -> None:
    group, parent, policy = str(uuid4()), str(uuid4()), str(uuid4())
    asset = validate_record(
        "asset",
        {
            "name": "Lab device",
            "group": group,
            "site": "lab",
            "owner": "operator",
            "criticality": "important",
            "tags": ["test", "test"],
            "notes": "planned maintenance",
        },
    )
    assert asset["group"] == group and asset["criticality"] == "important"
    assert asset["tags"] == ["test"]
    assert (
        validate_record("asset", {"criticality": "invalid"})["criticality"]
        == "standard"
    )
    assert (
        validate_record("group", {"name": "Child", "parent": parent})["parent"]
        == parent
    )
    assert validate_record("group", {"name": "Root"})["parent"] == ""
    for platform in ("all", "windows", "linux"):
        result = validate_record(
            "policy",
            {
                "name": "Read posture",
                "action": "posture",
                "platform": platform,
                "params": {},
                "group": group,
            },
        )
        assert result["platform"] == platform and result["group"] == group
        assert result["review_canary"] is True and result["concurrency"] == 3
    result = validate_record(
        "automation",
        {"name": "Recurring", "policy": policy, "group": group, "enabled": True},
    )
    assert result["policy"] == policy and result["interval"] == 3600
    assert result["enabled"] is True
    result = validate_record(
        "rule",
        {
            "name": "Readiness",
            "condition": "worker_missing",
            "severity": "critical",
            "group": group,
        },
    )
    assert result["condition"] == "worker_missing" and result["enabled"] is True
    assert result["delay"] == 120
    result = validate_record(
        "exercise",
        {
            "name": "Simulation",
            "status": "closed",
            "description": "isolated",
            "technique": "T1059",
            "outcome": "cleanup verified",
        },
    )
    assert result["status"] == "closed" and result["outcome"] == "cleanup verified"
    result = validate_record(
        "view",
        {
            "name": "Linux offline",
            "group": group,
            "query": "lab",
            "platform": "linux",
            "health": "offline",
        },
    )
    assert result["query"] == "lab" and result["group"] == group
