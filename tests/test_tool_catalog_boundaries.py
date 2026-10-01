"""Only approved signed recipes may enter the tool job queue."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from northgate_rmm.errors import ValidationError
from northgate_rmm.management import Management
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.tool_catalog import ToolCatalog
from northgate_rmm.tool_catalog_models import manifest_bytes
from tests.test_tool_catalog_models import manifest


def signed_catalog(root: Path) -> None:
    root.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    authority = root / "authority.pub"
    authority.write_bytes(
        base64.b64encode(
            key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
    )
    authority.chmod(0o600)
    for revision in (1, 2):
        value = manifest()
        value.update(revision=revision, version=f"5.19.{revision}")
        signature = key.sign(b"NorthGate-Tool-v1\0" + manifest_bytes(value))
        path = root / f"osquery-{revision}.json"
        path.write_text(
            json.dumps(
                {"manifest": value, "signature": base64.b64encode(signature).decode()}
            )
        )
        path.chmod(0o600)


def test_signed_catalog_filters_platform_and_architecture_and_orders_revisions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "catalog"
    signed_catalog(root)
    catalog = ToolCatalog(cast(Management, object()), root)
    assert [e["manifest"]["revision"] for e in catalog.entries("linux")] == [2, 1]
    assert len(catalog.entries("linux", "amd64")) == 2
    assert catalog.entries("linux", "arm64") == []
    assert catalog.entries("windows") == []


@pytest.mark.parametrize(
    "mode", ["invalid-envelope", "short-signature", "tamper", "public-symlink"]
)
def test_catalog_rejects_unapproved_or_untrusted_manifests(
    tmp_path: Path, mode: str
) -> None:
    root = tmp_path / "catalog"
    signed_catalog(root)
    path = root / "osquery-1.json"
    content = json.loads(path.read_text())
    if mode == "invalid-envelope":
        content = {}
    elif mode == "short-signature":
        content["signature"] = base64.b64encode(b"invalid").decode()
    elif mode == "tamper":
        content["manifest"]["revision"] = 10
    elif mode == "public-symlink":
        authority = root / "authority.pub"
        preserved = root / "preserved.pub"
        authority.rename(preserved)
        authority.symlink_to(preserved)
    path.write_text(json.dumps(content))
    catalog = ToolCatalog(cast(Management, object()), root)
    failure = (
        ValidationError
        if mode == "public-symlink"
        else InvalidSignature
        if mode == "tamper"
        else ValueError
    )
    with pytest.raises(failure):
        catalog.entries("linux")


def test_catalog_http_enforces_approval_permissions_cancellation_and_form_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        endpoint, identity = uuid4(), uuid4()
        now = datetime.now(UTC)
        principal = OperatorPrincipal(
            "https://idp.test",
            "lab",
            "owner",
            "session",
            "rmm",
            ("remote_operator",),
            now,
            now + timedelta(hours=1),
            True,
        )
        allowed = True
        audits: list[str] = []

        async def authenticate(*args: object, **kwargs: object) -> OperatorPrincipal:
            return principal

        async def audit(
            p: OperatorPrincipal, endpoint: UUID, action: str, correlation: UUID
        ) -> None:
            audits.append(action)

        gateway = SimpleNamespace(
            key=bytes(16),
            origin="https://operator.test",
            principal=authenticate,
            audit=audit,
            operation=SimpleNamespace(
                _store=SimpleNamespace(
                    get_endpoint=lambda _: SimpleNamespace(
                        identity_id=identity, platform=SimpleNamespace(value="linux")
                    )
                ),
                _policy=SimpleNamespace(permits=lambda *args: allowed),
            ),
        )
        store = ManagementStore(tmp_path / "state", bytes(16))
        monkeypatch.setattr(
            store, "worker", lambda _: {"ready": True, "identity": str(uuid4())}
        )
        management = Management(cast(RemoteGateway, gateway), store)
        signed_catalog(tmp_path / "catalog")
        catalog = ToolCatalog(management, tmp_path / "catalog")
        app = web.Application()
        catalog.register(app)
        async with TestClient(TestServer(app)) as client:
            url = f"/remote/{endpoint}/tool-catalog"
            state = await (await client.get(url)).json()
            assert state["worker"]["ready"] is False
            headers = {"Origin": gateway.origin, "Authorization": "Bearer synthetic"}
            identifier = str(uuid4())
            fields: dict[str, object] = {
                "csrf": state["csrf"],
                "action": "tool.install",
                "tool_id": "osquery",
                "version": "5.19.2",
                "request_id": identifier,
            }
            result = await client.post(url + "/action", json=fields, headers=headers)
            assert result.status == 202
            queued = store.job(identifier, private=True)
            assert queued["state"] == "queued"
            assert (
                json.loads(base64.b64decode(queued["payload"]["params"]["manifest"]))[
                    "revision"
                ]
                == 2
            )
            fields.update(action="cancel", job=identifier)
            assert (
                await client.post(url + "/action", json=fields, headers=headers)
            ).status == 200
            assert store.job(identifier)["cancel"]
            assert "tools.job.cancelled" in audits
            other = store.add(
                endpoint, identity, principal, "posture", {}, "Bearer synthetic"
            )
            fields["job"] = other
            assert (
                await client.post(url + "/action", json=fields, headers=headers)
            ).status == 403
            fields.update(action="unsupported")
            assert (
                await client.post(url + "/action", json=fields, headers=headers)
            ).status == 400
            fields.update(action="tool.install", version="not-approved")
            rejected = await client.post(url + "/action", json=fields, headers=headers)
            assert rejected.status == 400
            fields.update(
                action="tool.verify", tool_id="osquery", request_id=str(uuid4())
            )
            allowed = False
            assert (
                await client.post(url + "/action", json=fields, headers=headers)
            ).status == 403
            allowed = True
            assert (
                await client.post(url + "/action", json=fields, headers=headers)
            ).status == 202
            fields.update(
                action="tool.run",
                tool_id="health",
                profile="snapshot",
                inputs={},
                case_id=str(uuid4()),
                request_id=str(uuid4()),
            )
            assert (
                await client.post(url + "/action", json=fields, headers=headers)
            ).status == 409
            fields.update(action="tool.list", request_id=str(uuid4()))
            assert (
                await client.post(url + "/action", json=fields, headers=headers)
            ).status == 202
            management.forms = {
                str(i): ("owner", "session", str(endpoint), time.time() + 300)
                for i in range(128)
            }
            assert (await client.get(url)).status == 429

    asyncio.run(scenario())
