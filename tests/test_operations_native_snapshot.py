"""Bounded enrollment lookups without releasing revoked snapshot data."""

import json
from collections import Counter
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from aiohttp import web

from northgate_rmm.operations import IntegrationActor
from tests.test_operations import replace_enrollment, save
from tests.test_operations import rig as rig


def native_actor(rig: Any) -> tuple[Any, Any, Any]:
    live: dict[str, Any] = {
        "id": "audit",
        "actions": sorted(rig.permissions),
        "endpoints": dict(rig.identities),
    }
    calls: Counter[str] = Counter()

    def current(entry: Any) -> Any:
        return json.loads(json.dumps(live))

    def endpoint(entry: Any, identifier: str, permission: str) -> Any:
        calls[identifier] += 1
        device = rig.devices.get_endpoint(UUID(identifier))
        if permission not in live["actions"] or live["endpoints"].get(
            identifier
        ) != str(device.identity_id):
            raise web.HTTPConflict()
        return UUID(identifier), device

    rig.ops.m.integration = SimpleNamespace(
        auth=SimpleNamespace(current=current), endpoint=endpoint
    )
    return IntegrationActor("integration:audit", "test", current(live)), live, calls


def test_native_snapshot_checks_each_enrollment_twice_not_each_record(rig: Any) -> None:
    for i in range(30):
        save(rig, name=f"Audit {i}")
    actor, _, calls = native_actor(rig)
    assert len(rig.ops.snapshot(actor)["cases"]) == 30
    assert calls == Counter({endpoint: 2 for endpoint in rig.endpoints})
    # A later request must not reuse the previous snapshot's authorization.
    rig.ops.snapshot(actor)
    assert calls == Counter({endpoint: 4 for endpoint in rig.endpoints})


@pytest.mark.parametrize("change", ["enrollment", "permission", "scope"])
def test_native_snapshot_rechecks_before_returning(rig: Any, change: str) -> None:
    save(rig)
    actor, live, _ = native_actor(rig)
    original = rig.ops._snapshot

    def changed(principal: Any) -> Any:
        result = original(principal)
        if change == "enrollment":
            replace_enrollment(rig, rig.endpoints[0])
        elif change == "permission":
            live["actions"].remove("case.manage")
        else:
            live["endpoints"].pop(rig.endpoints[0])
        return result

    rig.ops._snapshot = changed
    with pytest.raises(web.HTTPException):
        rig.ops.snapshot(actor)
