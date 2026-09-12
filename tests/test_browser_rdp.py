from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from northgate_rmm.operator_api import OperatorPrincipal
from northgate_rmm.remote_gateway import COOKIE, LeaseState, RemoteGateway
from northgate_rmm.remote_policy import RemoteLease, parse_remote_targets
from northgate_rmm.remote_sessions import RemoteSessionStore
from northgate_rmm.remote_workspace import open_credentials, seal_credentials


def configuration():
    endpoint, identity = str(uuid4()), str(uuid4())
    return [
        {
            "endpoint_id": endpoint,
            "identity_id": identity,
            "address": "10.20.30.40",
            "protocol": method,
            "port": port,
            "parameters": {"username": "remote", **params},
        }
        for method, port, params in [
            ("ssh", 22, {"host-key": "test-pin"}),
            (
                "rdp",
                3389,
                {"password": "synthetic", "cert-fingerprints": "sha256:" + "11" * 32},
            ),
        ]
    ]


@pytest.mark.parametrize("change", ["duplicate", "identity", "host", "nla", "bypass"])
def test_multi_method_targets_reject_cross_enrollment_and_weakened_rdp(change):
    entries = configuration()
    if change == "duplicate":
        entries.append(entries[0])
    elif change == "identity":
        entries[1]["identity_id"] = str(uuid4())
    elif change == "host":
        entries[1]["address"] = "10.20.30.41"
    elif change == "nla":
        entries[1]["parameters"]["security"] = "rdp"
    else:
        entries[1]["parameters"]["ignore-cert"] = "true"
    with pytest.raises(ValueError):
        parse_remote_targets(entries)


def test_browser_rdp_uses_own_target_pins_case_and_csrf(tmp_path):
    async def scenario():
        targets = parse_remote_targets(configuration())
        endpoint = next(iter(targets))
        assert targets[endpoint][0].protocol == "ssh"
        gateway = RemoteGateway(
            None,
            targets,
            bytes(16),
            "https://operator.test",
            receipt_store=RemoteSessionStore(tmp_path / "sessions.sqlite"),
        )
        now = datetime.now(UTC)
        p = OperatorPrincipal(
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
        gateway.operation = SimpleNamespace(
            _store=SimpleNamespace(
                get_endpoint=lambda _: SimpleNamespace(display_name="Workstation")
            )
        )

        async def principal(*args, **kwargs):
            return p

        async def audit(*args, **kwargs):
            return None

        gateway.principal = principal
        gateway.audit = audit
        gateway.case_authorizer = audit
        async with TestClient(TestServer(gateway.application())) as client:
            path = f"/remote/{endpoint}/desktop"
            await client.get(path + "?case_id=IT-123")
            nonce = next(iter(gateway.forms))
            wrong = await client.post(
                f"/remote/{endpoint}",
                data={"nonce": nonce},
                headers={"Origin": gateway.origin},
            )
            assert wrong.status == 403
            await client.get(path + "?case_id=IT-123")
            nonce = next(iter(gateway.forms))
            response = await client.post(
                path,
                data={"nonce": nonce},
                headers={"Origin": gateway.origin},
                allow_redirects=False,
            )
            assert response.status == 302
            ciphertext = base64.b64decode(
                parse_qs(urlsplit(response.headers["Location"]).query)["data"][0]
            )
            decryptor = Cipher(
                algorithms.AES(bytes(16)), modes.CBC(bytes(16))
            ).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decoded = unpadder.update(padded) + unpadder.finalize()
            params = json.loads(decoded[32:])["connections"]["Browser Desktop"][
                "parameters"
            ]
            assert params["port"] == "3389"
            assert params["security"] == "nla"
            assert params["ignore-cert"] == params["cert-tofu"] == "false"
            assert params["cert-fingerprints"].startswith("sha256:")
            cookie = response.cookies[COOKIE].value
            state = gateway.leases[cookie]
            receipts = gateway.receipt_store.list(
                endpoint, targets[endpoint][0].identity_id
            )
            assert receipts[0]["case_id"] == "IT-123"
            assert "synthetic" not in json.dumps(receipts)
            stopped = await client.post(
                "/remote/end",
                headers={"Origin": gateway.origin, "Cookie": COOKIE + "=" + cookie},
                allow_redirects=False,
            )
            assert stopped.status == 302
            assert (
                gateway.receipt_store.list(endpoint, targets[endpoint][0].identity_id)[
                    0
                ]["outcome"]
                == "operator_disconnected"
            )
            assert state.lease.session_id

    asyncio.run(scenario())


def test_session_store_marks_restart_and_filters_enrollment(tmp_path):
    path = tmp_path / "session.sqlite"
    now = datetime.now(UTC)
    lease = RemoteLease(
        uuid4(), uuid4(), uuid4(), "owner", "s", now, now + timedelta(minutes=1)
    )
    store = RemoteSessionStore(path)
    store.create(lease, "rdp", "SOC-12")
    reopened = RemoteSessionStore(path)
    assert reopened.list(lease.endpoint_id, uuid4()) == []
    assert (
        reopened.list(lease.endpoint_id, lease.identity_id)[0]["status"]
        == "interrupted"
    )


def test_legacy_saved_credentials_support_more_than_eight():
    entries = [
        {
            "endpoint_id": str(uuid4()),
            "identity_id": str(uuid4()),
            "username": "remote",
            "password": "synthetic",
        }
        for _ in range(12)
    ]
    assert len(open_credentials(bytes(16), seal_credentials(bytes(16), entries))) == 12


def test_browser_disconnect_closes_upstream_websocket(monkeypatch):
    from northgate_rmm import remote_gateway

    async def scenario():
        connected, closed = asyncio.Event(), asyncio.Event()

        async def upstream_socket(request):
            ws = web.WebSocketResponse(protocols=("guacamole",))
            await ws.prepare(request)
            connected.set()
            async for _ in ws:
                pass
            closed.set()
            return ws

        upstream = web.Application()
        upstream.router.add_get("/guacamole/websocket-tunnel", upstream_socket)
        async with TestServer(upstream) as server:
            monkeypatch.setattr(remote_gateway, "UPSTREAM", str(server.make_url("")))
            targets = parse_remote_targets(configuration())
            endpoint = next(iter(targets))
            gateway = RemoteGateway(None, targets, bytes(16), "https://operator.test")
            now = datetime.now(UTC)
            p = OperatorPrincipal(
                "https://idp.test",
                "lab",
                "owner",
                "s",
                "rmm",
                ("remote_operator",),
                now,
                now + timedelta(hours=1),
                True,
            )
            lease = RemoteLease(
                uuid4(),
                endpoint,
                targets[endpoint][0].identity_id,
                p.subject,
                p.session_id,
                now,
                now + timedelta(minutes=5),
            )
            state = LeaseState(lease, method="rdp")
            gateway.leases["cookie"] = state
            gateway.receipt_store.create(lease, "rdp", "")

            async def principal(*args, **kwargs):
                return p

            async def audit(*args, **kwargs):
                pass

            gateway.principal, gateway.audit = principal, audit
            headers = {"Origin": gateway.origin, "Cookie": COOKIE + "=cookie"}
            async with TestClient(TestServer(gateway.application())) as client:
                denied = await client.get("/guacamole/tunnel", headers=headers)
                assert denied.status == 403
                ws = await client.ws_connect(
                    "/guacamole/websocket-tunnel",
                    headers=headers,
                    protocols=("guacamole",),
                )
                await asyncio.wait_for(connected.wait(), 2)
                await client.post("/remote/end", headers=headers, allow_redirects=False)
                await asyncio.wait_for(closed.wait(), 2)
                await ws.close()
                assert not gateway.leases

    asyncio.run(scenario())
