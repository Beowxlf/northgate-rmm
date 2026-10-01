"""Operations records preserve bounded, non-secret and verifiable data contracts."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from northgate_rmm.operations_models import (
    bounded_json,
    check_secrets,
    identifier,
    identifiers,
    stamp,
    text,
    validate,
)


@pytest.mark.parametrize("value", [None, 7, "", "not-a-uuid"])
def test_operations_identifiers_reject_untyped_or_invalid_values(value: object) -> None:
    with pytest.raises(ValueError):
        identifier(value)


def test_operations_scalar_normalization_preserves_meaning_and_byte_bounds() -> None:
    first, second = str(uuid4()), str(uuid4())
    assert identifiers([second, first, first]) == sorted([first, second])
    assert identifier(first.upper()) == first
    assert text("  multi\nline\ttext  ") == "multi\nline\ttext"
    assert text("  ", empty=True) == ""
    assert stamp(None) is None and stamp("") is None
    assert stamp("2026-10-01T00:00:00Z") == "2026-10-01T00:00:00+00:00"
    assert bounded_json({"z": 1, "a": True}) == '{"a":true,"z":1}'
    assert json.loads(bounded_json({"description": "safe context"})) == {
        "description": "safe context"
    }
    with pytest.raises(ValueError, match="size limit"):
        bounded_json({"description": "é" * 100}, maximum=100)
    with pytest.raises(ValueError):
        bounded_json({"value": float("nan")})


@pytest.mark.parametrize(
    "value", [None, 1, "", "x" * 257, "bad\x00control", "bad\x1fcontrol"]
)
def test_operations_text_is_bounded_and_excludes_controls(value: object) -> None:
    with pytest.raises(ValueError):
        text(value)


@pytest.mark.parametrize("value", [{}, [str(uuid4())] * 129])
def test_identifier_collection_is_bounded(value: object) -> None:
    with pytest.raises(ValueError, match="identifier list"):
        identifiers(value)


@pytest.mark.parametrize("value", [7, "2026-10-01T00:00:00", "not-a-time"])
def test_timestamp_requires_explicit_timezone(value: object) -> None:
    with pytest.raises(ValueError):
        stamp(value)


@pytest.mark.parametrize(
    "value",
    [
        {"nested": [{"access-token": "synthetic fixture"}]},
        {"nested": ({"PRIVATE_KEY": "synthetic fixture"},)},
        {"note": "password" + "=synthetic-only"},
        ["-----BEGIN " + "PRIVATE KEY-----"],
    ],
)
def test_operations_records_refuse_secret_fields_recursively(value: object) -> None:
    with pytest.raises(ValueError, match=r"[Ss]ecret|credential"):
        check_secrets(value)
    with pytest.raises(ValueError):
        bounded_json(value)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("alert", {"name": "external-only"}),
        ("case", []),
        ("case", {"name": "test", "unapproved_field": True}),
        ("case", {"name": "test", "tags": {}}),
        ("case", {"name": "test", "tags": ["tag"] * 33}),
        ("case", {"name": "test", "type": "incident-with-unknown-contract"}),
        ("case", {"name": "test", "priority": "urgent"}),
        ("case", {"name": "test", "category": "unknown"}),
        ("case", {"name": "test", "disposition": "unknown"}),
        ("case", {"name": "test", "containment_status": "unknown"}),
        ("case", {"name": "test", "resolution_code": "unknown"}),
        ("asset", {"name": "test", "intended": []}),
        ("asset", {"name": "test", "observed": "unstructured"}),
        ("service", {"name": "test", "provenance": False}),
        ("asset", {"name": "test", "intended": {"large": "x" * 32769}}),
        ("exercise", {"name": "test", "techniques": {}}),
        ("exercise", {"name": "test", "allowed_activities": ["observe"] * 101}),
        ("network", {"name": "test", "vlan": True}),
        ("network", {"name": "test", "vlan": 0}),
        ("network", {"name": "test", "vlan": 4095}),
        ("network", {"name": "test", "cidr": "192.0.2.1/24"}),
        ("document", {"name": "test", "document_type": "unsupported"}),
        ("change", {"name": "test", "status": "unapproved"}),
        ("exercise", {"name": "test", "status": "unapproved"}),
        ("change", {"name": "test", "status": "closed"}),
        ("exercise", {"name": "test", "status": "closed"}),
    ],
)
def test_operations_record_validation_rejects_unbounded_or_unsupported_fields(
    kind: str, value: object
) -> None:
    with pytest.raises(ValueError):
        validate(kind, value)


def test_valid_records_normalize_each_supported_model() -> None:
    endpoint, asset, service, network, case = (str(uuid4()) for _ in range(5))
    common: dict[str, object] = {
        "name": "  retained context  ",
        "endpoints": [endpoint, endpoint],
        "assets": [asset],
        "services": [service],
        "networks": [network],
        "tags": ["triage", "triage"],
        "owner": "owner",
        "team": "operations",
        "description": "reviewable evidence",
    }
    case_record = validate(
        "case",
        {
            **common,
            "type": "soc",
            "priority": "high",
            "response_due": "2026-10-01T00:00:00Z",
            "resolve_due": None,
            "assignee": "analyst",
        },
    )
    assert case_record["name"] == "retained context"
    assert case_record["endpoints"] == [endpoint] and case_record["tags"] == ["triage"]
    assert case_record["category"] == "security"
    assert case_record["containment_status"] == "not_started"
    assert case_record["response_due"].endswith("+00:00")
    assert case_record["resolve_due"] is None
    assert validate("case", {"name": "IT case"})["containment_status"] == "not_required"
    for kind in ("asset", "service"):
        value = validate(
            kind,
            {
                **common,
                "intended": {"state": "approved"},
                "observed": {"state": "observed"},
                "provenance": {"source": "snapshot"},
            },
        )
        assert value["intended"] != value["observed"]
        assert value["provenance"] == {"source": "snapshot"}
    value = validate("network", {**common, "cidr": "2001:db8:0000::/48", "vlan": 4094})
    assert value["cidr"] == "2001:db8::/48" and value["vlan"] == 4094
    value = validate(
        "document",
        {
            **common,
            "document_type": "runbook",
            "content": "Check\nVerify",
            "review_due": "2026-10-02T01:00:00+01:00",
            "source_ref": "internal record",
        },
    )
    assert value["content"] == "Check\nVerify"
    value = validate(
        "change",
        {
            **common,
            "planned_at": "2026-10-01T00:00:00Z",
            "implementation": "bounded action",
            "rollback": "restore baseline",
            "verification": "passed checks",
            "status": "closed",
            "case_id": case,
        },
    )
    assert value["status"] == "closed" and value["case_id"] == case
    value = validate(
        "exercise",
        {
            **common,
            "techniques": ["T1059"],
            "allowed_activities": ["observe"],
            "expected_detections": ["process creation"],
            "cleanup_verification": "baseline restored",
            "status": "closed",
            "case_id": "",
        },
    )
    assert value["expected_detections"] == ["process creation"]
    assert value["case_id"] == ""


@pytest.mark.parametrize(
    "mode",
    [
        "missing",
        "not-object",
        "extra-field",
        "unsupported-kind",
        "same-record",
        "unknown-relation",
        "unknown-confidence",
    ],
)
def test_relationship_requires_distinct_typed_endpoints_and_known_relation(
    mode: str,
) -> None:
    source = {"kind": "asset", "id": str(uuid4())}
    target = {"kind": "service", "id": str(uuid4())}
    value: dict[str, object] = {
        "name": "Relationship",
        "source": source,
        "target": target,
        "relation": "depends_on",
        "confidence": "verified",
    }
    if mode == "missing":
        value.pop("target")
    elif mode == "not-object":
        value["source"] = "asset"
    elif mode == "extra-field":
        value["source"] = {**source, "unapproved": True}
    elif mode == "unsupported-kind":
        value["source"] = {"kind": "case", "id": str(uuid4())}
    elif mode == "same-record":
        value["target"] = source
    elif mode == "unknown-relation":
        value["relation"] = "arbitrary-authority"
    elif mode == "unknown-confidence":
        value["confidence"] = "certain"
    with pytest.raises(ValueError):
        validate("relationship", value)
    value.update(
        source=source,
        target=target,
        relation="depends_on",
        confidence="verified",
        verified_at="2026-10-01T00:00:00Z",
    )
    assert validate("relationship", value)["source"] == source
