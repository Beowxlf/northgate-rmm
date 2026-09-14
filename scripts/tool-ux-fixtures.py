"""Render real tool handlers with isolated synthetic device data for browser review."""

import asyncio
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.capture_store import CaptureStore
from northgate_rmm.capture_ui import CaptureUI
from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.remote_workspace import RemoteWorkspace


async def main():
    endpoint = UUID("11111111-1111-4111-8111-111111111110")
    identity = UUID("22222222-2222-4222-8222-222222222220")
    principal = SimpleNamespace(
        subject="review",
        session_id="synthetic",
        roles={"remote_operator", "recovery_operator"},
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    target = SimpleNamespace(endpoint_id=endpoint, identity_id=identity)

    async def authenticate(*args, **kwargs):
        return principal

    async def audit(*args):
        pass

    async def runner(*args):
        return {
            "state": "ready",
            "interfaces": [{"CaptureName": "1", "Name": "Ethernet · Lab network"}],
        }

    output = Path(os.environ.get("RMM_REVIEW_OUTPUT", "../../outputs/tool-ux-review"))
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        device = SimpleNamespace(
            platform=SimpleNamespace(value="windows"), identity_id=identity
        )
        gateway = SimpleNamespace(
            key=bytes(16),
            origin="https://operator.test",
            principal=authenticate,
            audit=audit,
            targets={endpoint: (target, {})},
            operation=SimpleNamespace(
                _store=SimpleNamespace(get_endpoint=lambda _: device),
                _policy=SimpleNamespace(permits=lambda *args: True),
            ),
        )
        app = web.Application()
        Management(gateway, ManagementStore(root / "manage", bytes(16))).register(app)
        RemoteWorkspace(
            gateway, {endpoint: (identity, "lab\\review", "synthetic-only")}
        ).register(app)
        store = CaptureStore(root / "capture")
        job = dict(
            id="33333333-3333-4333-8333-333333333333",
            endpoint_id=str(endpoint),
            identity_id=str(identity),
            state="capturing",
            started=datetime.now(UTC).isoformat(),
            updated=datetime.now(UTC).isoformat(),
            bytes=32768,
            max_bytes=16777216,
            packets=132,
            dropped_packets=0,
            preset="dns",
            report={
                "provisional": True,
                "packets": 132,
                "assets": [
                    {
                        "ip": "10.0.0.2",
                        "scope": "untagged",
                        "macs": [],
                        "roles": [
                            {
                                "name": "DNS server",
                                "confidence": "observed",
                                "packet": 2,
                                "evidence": "DNS reply",
                            }
                        ],
                        "first": "12:00",
                        "last": "12:01",
                    }
                ],
                "flows": [],
                "findings": [
                    {
                        "kind": "DNS timeout",
                        "description": "<img src=x onerror=alert(1)> unanswered query",
                        "source": "10.0.0.3",
                        "destination": "10.0.0.2",
                        "confidence": "possible",
                        "packet": 1,
                        "scope": "untagged",
                        "time": "12:01",
                    }
                ],
                "warnings": [],
            },
            artifacts=[],
        )
        store.add(endpoint, identity, principal, job)
        CaptureUI(gateway, store, runner, setup=True).register(app)
        async with TestClient(TestServer(app)) as client:
            fixtures = {"endpoint": str(endpoint), "job": job, "pages": {}}
            for name in ("manage", "tools", "capture"):
                response = await client.get(f"/remote/{endpoint}/{name}")
                if response.status != 200:
                    raise AssertionError((name, await response.text()))
                fixtures["pages"][name] = {
                    "body": await response.text(),
                    "headers": dict(response.headers),
                }
            (output / "fixtures.json").write_text(
                json.dumps(fixtures), encoding="utf-8"
            )


asyncio.run(main())
