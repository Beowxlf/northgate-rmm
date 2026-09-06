"""Management authorization, durable custody, crypto and browser contracts."""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from northgate_rmm.management import Management
from northgate_rmm.management_admin import backup, restore
from northgate_rmm.management_protocol import (
    canonical,
    open_worker_result,
    public_configuration,
    seal,
    sign,
    unseal,
    validate_action,
)
from northgate_rmm.management_store import ManagementStore

KEY = bytes(range(16))


def test_upload_envelope_fits_existing_authentication_limit():
    data = b"x" * (15 * 1024 * 1024)
    params = dict(
        path="/var/ops/boundary.bin",
        data=base64.b64encode(data).decode(),
        sha256=hashlib.sha256(data).hexdigest(),
        overwrite=False,
    )
    validate_action("files.write", params, "linux")
    assert (
        len(
            json.dumps(
                dict(action="files.write", params=params, csrf="a" * 64)
            ).encode()
        )
        < 21 * 1024 * 1024
    )
    data += b"x"
    params.update(
        data=base64.b64encode(data).decode(), sha256=hashlib.sha256(data).hexdigest()
    )
    with pytest.raises(ValueError):
        validate_action("files.write", params, "linux")


def test_worker_certificate_uses_read_only_identity_checks(tmp_path, monkeypatch):
    from northgate_rmm.domain import EndpointLifecycle

    endpoint, identity = uuid4(), uuid4()
    peer = SimpleNamespace(
        endpoint_id=endpoint, public_key_fingerprint="sha256:" + "a" * 64
    )
    record = SimpleNamespace(
        identity_id=identity,
        endpoint_id=endpoint,
        status=EndpointLifecycle.ACTIVE,
        revoked_at=None,
        public_key_fingerprint=peer.public_key_fingerprint,
    )
    monkeypatch.setattr(
        "northgate_rmm.management.extract_verified_client_certificate", lambda _: peer
    )
    # Deliberately no mutating certificate-authentication method on this reader.
    reader = SimpleNamespace(
        get_endpoint=lambda _: SimpleNamespace(identity_id=identity),
        get_identity=lambda _: record,
    )
    gateway = SimpleNamespace(
        key=KEY,
        operation=SimpleNamespace(_store=reader),
        targets={endpoint: (SimpleNamespace(identity_id=identity), {})},
    )
    m = Management(gateway, ManagementStore(tmp_path, KEY))
    request = SimpleNamespace(
        transport=SimpleNamespace(get_extra_info=lambda _: object())
    )
    assert asyncio.run(m.worker_identity(request))[1] is record
    record.public_key_fingerprint = "sha256:" + "b" * 64
    with pytest.raises(web.HTTPForbidden):
        asyncio.run(m.worker_identity(request))
    record.public_key_fingerprint = peer.public_key_fingerprint
    record.status = EndpointLifecycle.REVOKED
    with pytest.raises(web.HTTPForbidden):
        asyncio.run(m.worker_identity(request))


def principal():
    return SimpleNamespace(
        subject="owner",
        session_id="session",
        roles={"owner", "remote_operator", "recovery_operator"},
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )


def receipt(output="ok"):
    return dict(
        state="completed",
        exit_code=0,
        output=output,
        execution_identity="root (uid=0)",
        truncated=False,
    )


def encrypted_receipt(job, result):
    private = x25519.X25519PrivateKey.generate()
    remote = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(public_configuration(KEY)["escrow_key"])
    )
    key = hmac.digest(private.exchange(remote), b"NorthGate-Receipt-v1", "sha256")
    nonce = bytes(12)
    return {
        "ephemeral": base64.b64encode(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "body": base64.b64encode(
            AESGCM(key).encrypt(nonce, canonical(result), job.encode())
        ).decode(),
    }


def test_custody_rejects_changed_context_and_signature():
    blob = seal(KEY, {"secret": "synthetic-recovery"}, "job")
    assert b"synthetic-recovery" not in blob
    assert unseal(KEY, blob, "job")["secret"] == "synthetic-recovery"  # noqa: S105 -- synthetic fixture
    with pytest.raises(InvalidTag):
        unseal(KEY, blob, "other-job")
    envelope = sign(KEY, {"endpoint": "one", "nonce": "unique"})
    public = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.b64decode(public_configuration(KEY)["signing_key"])
    )
    public.verify(
        base64.b64decode(envelope["signature"]),
        b"NorthGate-Management-v1\0" + base64.b64decode(envelope["payload"]),
    )
    job = str(uuid4())
    sealed = encrypted_receipt(job, receipt())
    assert open_worker_result(KEY, sealed, job) == receipt()
    with pytest.raises(InvalidTag):
        open_worker_result(KEY, sealed, str(uuid4()))


def test_durable_dispatch_receipt_and_secret_boundaries(tmp_path):
    store = ManagementStore(tmp_path, KEY)
    endpoint, identity = uuid4(), uuid4()
    job = store.add(
        endpoint, identity, principal(), "bitlocker.escrow", {}, "Bearer synthetic"
    )
    assert b"Bearer synthetic" not in store.path.read_bytes()
    assert store.dispatch(job)
    assert not store.dispatch(job)
    with pytest.raises(ValueError):
        store.result(endpoint, uuid4(), job, receipt())
    store.result(endpoint, identity, job, receipt("synthetic-secret"))
    store.result(endpoint, identity, job, receipt("replacement-forbidden"))
    assert "receipt" not in store.list(endpoint)[0]
    assert store.job(job, private=True)["receipt"]["output"] == "synthetic-secret"
    assert b"synthetic-secret" not in store.path.read_bytes()
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM escrow").fetchone()[0] == 1


def test_expired_job_not_replayed_and_terminal_retry_integrity(tmp_path):
    store = ManagementStore(tmp_path, KEY)
    endpoint, identity = uuid4(), uuid4()
    job = store.add(endpoint, identity, principal(), "posture", {}, "Bearer synthetic")
    store.dispatch(job)
    with store.connect() as db:
        db.execute("UPDATE jobs SET expires=? WHERE id=?", (time.time() - 1, job))
    assert not store.pending(endpoint, identity)
    assert store.job(job)["state"] == "result_unknown"
    store.io(job, "out", 1, {"data": "YQ=="})
    store.io(job, "out", 1, {"data": "YQ=="})
    with pytest.raises(ValueError):
        store.io(job, "out", 1, {"data": "Yg=="})
    store.prune_frames(job, "out", 1)
    assert store.frames(job, "out", 0) == []


@pytest.mark.parametrize(
    "action,params",
    [
        ("reboot", {"delay": True}),
        ("isolation.start", {"seconds": 301}),
        ("service.control", {"name": "x;reboot", "operation": "restart"}),
        ("package.install", {"name": "--help"}),
        ("shell.start", {"columns": 100, "rows": 0}),
        (
            "files.write",
            {
                "path": "/var/ops/x",
                "data": "eA==",
                "sha256": "0" * 64,
                "overwrite": False,
            },
        ),
    ],
)
def test_unbounded_or_injected_operations_rejected(action, params):
    with pytest.raises((ValueError, TypeError)):
        validate_action(action, params, "linux")


def test_management_routes_bind_session_role_csrf_and_dispatch(tmp_path):
    async def scenario():
        p = principal()
        endpoint, identity = uuid4(), uuid4()
        events = []

        async def audit(*args):
            events.append(args[2])

        async def authenticate(request, eid, **kwargs):
            if request.headers.get("Authorization") != "Bearer synthetic":
                raise web.HTTPForbidden()
            return p

        device = SimpleNamespace(
            identity_id=identity, platform=SimpleNamespace(value="windows")
        )
        gateway = SimpleNamespace(
            key=KEY,
            origin="https://operator.test",
            principal=authenticate,
            audit=audit,
            operation=SimpleNamespace(
                _store=SimpleNamespace(get_endpoint=lambda eid: device)
            ),
            targets={},
        )
        store = ManagementStore(tmp_path, KEY)
        m = Management(gateway, store)
        app = web.Application(client_max_size=32 * 1024 * 1024)
        m.register(app)
        client = TestClient(TestServer(app))
        await client.start_server()
        headers = {
            "Authorization": "Bearer synthetic",
            "Origin": "https://operator.test",
        }
        base = f"/remote/{endpoint}/manage"
        try:
            assert (await client.get(base)).status == 403
            response = await client.get(base, headers=headers)
            html = await response.text()
            assert response.status == 200
            assert "script-src" in response.headers["Content-Security-Policy"]
            csrf = re.search(r'"csrf": "([^"]+)"', html).group(1)
            action = {"action": "bitlocker.escrow", "params": {}, "csrf": csrf}
            p.roles.remove("recovery_operator")
            assert (
                await client.post(base + "/action", json=action, headers=headers)
            ).status == 403
            p.roles.add("recovery_operator")
            assert (
                await client.post(
                    base + "/action", json={**action, "csrf": "wrong"}, headers=headers
                )
            ).status == 403
            response = await client.post(base + "/action", json=action, headers=headers)
            assert response.status == 202
            job = (await response.json())["job"]
            store.dispatch(job)
            store.result(endpoint, identity, job, receipt("synthetic-secret"))
            response = await client.get(base + "/state", headers=headers)
            assert "synthetic-secret" not in await response.text()
            assert (
                await client.post(
                    base + "/reveal", json={"job": job, "csrf": csrf}, headers=headers
                )
            ).status == 200
            assert "management.escrow.revealed" in events
            p.session_id = "different"
            assert (
                await client.post(
                    base + "/reveal", json={"job": job, "csrf": csrf}, headers=headers
                )
            ).status == 403
        finally:
            await client.close()

    asyncio.run(scenario())


def test_worker_poll_revocation_and_duplicate_receipt(tmp_path):
    async def scenario():
        endpoint, identity = uuid4(), uuid4()
        store = ManagementStore(tmp_path, KEY)
        m = Management(SimpleNamespace(key=KEY), store)
        allowed = True

        async def peer(request):
            return SimpleNamespace(endpoint_id=endpoint), SimpleNamespace(
                identity_id=identity
            )

        async def authorize(job):
            if not allowed:
                raise ValueError("Session revoked")

        m.worker_identity = peer
        m.authorize_job = authorize
        client = TestClient(TestServer(m.worker_application()))
        await client.start_server()
        body = {"nonce": "0123456789abcdef", "capabilities": {"privileged": True}}
        try:
            first = store.add(
                endpoint, identity, principal(), "posture", {}, "Bearer synthetic"
            )
            response = await client.post("/v1/management/poll", json=body)
            assert response.status == 200
            signed = await response.json()
            claims = json.loads(base64.b64decode(signed["payload"]))
            assert claims["job"]["id"] == first
            response = await client.post("/v1/management/poll", json=body)
            assert (
                json.loads(base64.b64decode((await response.json())["payload"]))["job"]
                is None
            )
            item = {"job": first, "sealed": encrypted_receipt(first, receipt())}
            for _ in range(2):
                response = await client.post(
                    "/v1/management/poll", json={**body, "receipts": [item]}
                )
                assert response.status == 200
            second = store.add(
                endpoint, identity, principal(), "posture", {}, "Bearer synthetic"
            )
            allowed = False
            response = await client.post("/v1/management/poll", json=body)
            assert (
                json.loads(base64.b64decode((await response.json())["payload"]))["job"]
                is None
            )
            assert store.job(second)["state"] == "cancelled"
        finally:
            await client.close()

    asyncio.run(scenario())


def test_full_recovery_roundtrip_and_tamper_rejection(tmp_path):
    root = tmp_path / "state"
    ManagementStore(root / "management", KEY)
    for relative in ["captures/capture.sqlite3", "inspection.sqlite3"]:
        path = root / relative
        path.parent.mkdir(exist_ok=True)
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE evidence (id TEXT)")
        path.chmod(0o600)
    credentials = tmp_path / "credentials.aes"
    credentials.write_bytes(b"synthetic-encrypted-credentials")
    credentials.chmod(0o600)
    archive = tmp_path / "backup.aes"
    backup(root, credentials, KEY, archive)
    restored = tmp_path / "restored"
    restore(archive, KEY, restored)
    assert (
        restored / "remote-credentials.aes"
    ).read_bytes() == credentials.read_bytes()
    with pytest.raises(FileExistsError):
        restore(archive, KEY, restored)
    broken = bytearray(archive.read_bytes())
    broken[-1] ^= 1
    archive.write_bytes(broken)
    with pytest.raises(InvalidTag):
        restore(archive, KEY, tmp_path / "bad-restore")
    assert not (tmp_path / "bad-restore").exists()
