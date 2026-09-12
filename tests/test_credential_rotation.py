"""No real account changes: durable queue and encrypted candidate contracts."""

import asyncio
import base64
import hmac
import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aiohttp import web
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from northgate_rmm.credential_rotation import (
    CredentialRotationExecutor,
    load_rotation_configuration,
)
from northgate_rmm.domain import Endpoint, Platform
from northgate_rmm.fleet_access import action_permission
from northgate_rmm.management import Management
from northgate_rmm.management_protocol import SECRET_ACTIONS, validate_action
from northgate_rmm.management_store import ManagementStore
from northgate_rmm.remote_policy import RemoteTarget
from tests.test_secrets_api import fixture

PASSWORD = "Synthetic" + "Candidate-" + "12345"


def rig(tmp_path):
    endpoint, identity, config, config_path, gateway, provider, api = fixture(tmp_path)
    gateway.user = replace(gateway.user, roles=("remote_operator", "recovery_operator"))
    device = Endpoint(
        endpoint, "WORKSTATION", Platform.WINDOWS, "amd64", identity, datetime.now(UTC)
    )
    target = RemoteTarget(endpoint, identity, "10.0.0.10", "rdp", 3389)
    parameters = {"cert-fingerprints": "sha256:" + ":".join(["ab"] * 32)}
    gateway.targets = {endpoint: (target, parameters)}
    gateway.method_target = lambda e, method: (target, parameters)
    gateway.key = bytes(range(16))
    gateway.operation = SimpleNamespace(
        _store=SimpleNamespace(get_endpoint=lambda e: device),
        _policy=SimpleNamespace(permits=lambda subject, e, permission: True),
    )
    store = ManagementStore(tmp_path / "management", gateway.key)
    management = Management(gateway, store)
    key = x25519.X25519PrivateKey.generate()
    cap = {
        "available": True,
        "username": "rmmremote",
        "account_sid": "S-1-5-21-1-2-3-1001",
        "protocol": "rdp",
        "domain": "WORKSTATION",
        "recipient": base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
    }
    capabilities = {"platform": "windows", "features": {"credential_rotation": cap}}
    store.seen(endpoint, identity, capabilities)

    class Verifier:
        calls = 0
        succeeds = True
        ready = True

        async def preflight(self, **kwargs):
            return self.ready

        async def verify(self, **kwargs):
            self.calls += 1
            assert kwargs["fields"]["password"] == PASSWORD
            return self.succeeds

    verifier = Verifier()
    executor = CredentialRotationExecutor(management, verifier)
    executor.bind(api)
    api.rotation_executor = executor
    record = {
        "id": str(uuid4()),
        "endpoint_id": str(endpoint),
        "identity_id": str(identity),
        "kind": "rdp",
        "retired": False,
        "path": "northgate-rmm/test",
        "label": "Managed login",
        "use_for_remote": True,
    }
    api.state.save_record(record)
    provider.write(
        record["path"],
        {
            "username": "rmmremote",
            "password": "SyntheticPrevious-12345",
            "domain": "WORKSTATION",
        },
        cas=0,
    )
    request = SimpleNamespace(
        match_info={"endpoint": str(endpoint)},
        headers={"Authorization": "Bearer actual-request-header"},
    )
    fields = {"username": "rmmremote", "domain": "WORKSTATION", "password": PASSWORD}
    return SimpleNamespace(**locals())


async def start(r):
    rid = str(uuid4())
    result = await r.api.rotate(
        r.request,
        r.gateway.user,
        r.endpoint,
        r.record,
        r.provider,
        r.config,
        {"rotation_id": rid, "expected_version": 1, "fields": r.fields},
        "rotate",
    )
    assert result["status"] == "pending"
    rotation = r.api.state.get("rotations", rid)
    assert r.provider.read(rotation["stage_path"])["password"] == PASSWORD
    assert r.provider.metadata(r.record["path"])["current_version"] == 1
    return result


def verified_receipt(r, job):
    r.store.dispatch(job["id"])
    r.store.result(
        r.endpoint,
        r.identity,
        job["id"],
        {
            "state": "completed",
            "exit_code": 0,
            "truncated": False,
            "execution_identity": "NT AUTHORITY\\SYSTEM",
            "output": json.dumps(
                {
                    "rotation_id": job["payload"]["params"]["rotation_id"],
                    "account_sid": r.cap["account_sid"],
                    "username": "rmmremote",
                    "protocol": "rdp",
                    "status": "verified",
                    "local_authenticated": True,
                }
            ),
        },
    )


def test_rotation_stages_encrypts_then_requires_two_independent_authentications(
    tmp_path,
):
    async def scenario():
        r = rig(tmp_path)
        result = await start(r)
        job = r.store.job(result["job_id"], private=True)
        params = job["payload"]["params"]
        assert PASSWORD not in json.dumps(job)
        assert PASSWORD not in json.dumps(r.api.state.get("rotations", result["id"]))
        assert job["payload"]["authorization"] == "Bearer actual-request-header"
        envelope = base64.b64decode(params["candidate"])
        shared = r.key.exchange(x25519.X25519PublicKey.from_public_bytes(envelope[:32]))
        cipher = AESGCM(hmac.digest(shared, b"NorthGate-Credential-v1", "sha256"))
        aad = "/".join(
            [
                "NorthGate-Credential-v1",
                str(r.endpoint),
                str(r.identity),
                job["id"],
                result["id"],
                "apply",
                "rmmremote",
                r.cap["account_sid"],
                "1",
            ]
        ).encode()
        assert cipher.decrypt(envelope[32:44], envelope[44:], aad).decode() == PASSWORD
        with pytest.raises(InvalidTag):
            cipher.decrypt(
                envelope[32:44], envelope[44:], aad.replace(b"/apply/", b"/check/")
            )
        assert r.store.job(job["id"])["secret_result"]
        verified_receipt(r, job)
        assert "receipt" not in r.store.job(job["id"])
        r.verifier.succeeds = False
        body = {"rotation_id": result["id"]}
        uncertain = await r.api.rotate(
            r.request,
            r.gateway.user,
            r.endpoint,
            r.record,
            r.provider,
            r.config,
            body,
            "resume_rotation",
        )
        assert uncertain["status"] == "unknown"
        assert r.provider.metadata(r.record["path"])["current_version"] == 1
        r.verifier.succeeds = True
        completed = await r.api.rotate(
            r.request,
            r.gateway.user,
            r.endpoint,
            r.record,
            r.provider,
            r.config,
            body,
            "resume_rotation",
        )
        assert completed["status"] == "completed"
        assert r.provider.read(r.record["path"])["password"] == PASSWORD
        assert r.verifier.calls == 2
        assert len(r.store.list(r.endpoint)) == 1

    asyncio.run(scenario())


def test_uncertain_apply_only_creates_idempotent_authentication_check(tmp_path):
    async def scenario():
        r = rig(tmp_path)
        result = await start(r)
        job = r.store.job(result["job_id"], private=True)
        r.store.dispatch(job["id"])
        r.store.result(
            r.endpoint,
            r.identity,
            job["id"],
            {
                "state": "result_unknown",
                "exit_code": -1,
                "output": "",
                "execution_identity": "NT AUTHORITY\\SYSTEM",
                "truncated": False,
            },
        )
        body = {"rotation_id": result["id"]}
        checked = await r.api.rotate(
            r.request,
            r.gateway.user,
            r.endpoint,
            r.record,
            r.provider,
            r.config,
            body,
            "resume_rotation",
        )
        check = r.store.job(checked["job_id"], private=True)
        assert check["payload"]["params"]["phase"] == "check"
        assert checked["job_id"] != job["id"]
        again = await r.api.rotate(
            r.request,
            r.gateway.user,
            r.endpoint,
            r.record,
            r.provider,
            r.config,
            body,
            "resume_rotation",
        )
        assert again["job_id"] == checked["job_id"]
        assert len(r.store.list(r.endpoint)) == 2
        assert r.verifier.calls == 0
        assert r.provider.metadata(r.record["path"])["current_version"] == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("defect", ["grant", "mfa", "enrollment", "account", "retired"])
def test_each_poll_rechecks_fresh_grant_and_exact_binding(tmp_path, defect):
    async def scenario():
        r = rig(tmp_path)
        result = await start(r)
        job = r.store.job(result["job_id"], private=True)
        if defect == "grant":
            r.config["grants"][0]["permissions"].remove("rotate")
            r.config_path.write_text(json.dumps(r.config))
        elif defect == "mfa":
            r.gateway.user = replace(
                r.gateway.user,
                authenticated_at=datetime.now(UTC) - timedelta(minutes=6),
            )
        elif defect == "enrollment":
            r.gateway.targets[r.endpoint] = (replace(r.target, identity_id=uuid4()), {})
        elif defect == "account":
            r.cap["account_sid"] = "S-1-5-21-1-2-3-1002"
            r.store.seen(r.endpoint, r.identity, r.capabilities)
        else:
            r.record["retired"] = True
            r.api.state.save_record(r.record)
        with pytest.raises((web.HTTPException, ValueError)):
            await r.executor.authorize_job(r.gateway.user, job)

    asyncio.run(scenario())


def test_scope_and_protocol_gate_precede_escrow_and_native_never_authorizes(tmp_path):
    async def scenario():
        r = rig(tmp_path)
        assert "credential.rotate" in SECRET_ACTIONS
        assert action_permission("credential.rotate") == "recovery"
        r.record["kind"] = "ssh"
        with pytest.raises(web.HTTPForbidden):
            await r.executor.prepare(
                record=r.record,
                fields=r.fields,
                principal=r.gateway.user,
                request=r.request,
            )
        assert not r.store.list(r.endpoint)
        r.record["kind"] = "rdp"
        result = await start(r)
        job = r.store.job(result["job_id"], private=True)
        validate_action("credential.rotate", job["payload"]["params"], "windows")
        with pytest.raises(ValueError):
            validate_action("credential.rotate", job["payload"]["params"], "linux")
        from northgate_rmm.integration_auth import PREFIX

        job["payload"]["authorization"] = PREFIX + "synthetic"
        with pytest.raises(ValueError, match="Native integrations"):
            await r.management.authorize_job(job)

    asyncio.run(scenario())


def test_duplicate_secret_cannot_rotate_the_same_account_concurrently(tmp_path):
    async def scenario():
        r = rig(tmp_path)
        await start(r)
        other = {**r.record, "id": str(uuid4()), "path": "northgate-rmm/other"}
        r.api.state.save_record(other)
        with pytest.raises(web.HTTPConflict):
            await r.executor.prepare(
                record=other,
                fields=r.fields,
                principal=r.gateway.user,
                request=r.request,
            )

    asyncio.run(scenario())


def test_rotation_keeps_escrow_when_provider_version_changes(tmp_path):
    async def scenario():
        r = rig(tmp_path)
        result = await start(r)
        job = r.store.job(result["job_id"], private=True)
        verified_receipt(r, job)
        r.provider.write(
            r.record["path"], {"password": "SyntheticDifferent-12345"}, cas=1
        )
        result = await r.api.rotate(
            r.request,
            r.gateway.user,
            r.endpoint,
            r.record,
            r.provider,
            r.config,
            {"rotation_id": result["id"]},
            "resume_rotation",
        )
        assert result["status"] == "commit_conflict"
        rotation = r.api.state.get("rotations", result["id"])
        assert r.provider.read(rotation["stage_path"])["password"] == PASSWORD
        assert r.provider.read(r.record["path"])["password"] != PASSWORD

    asyncio.run(scenario())


def test_optional_verifier_configuration_has_exact_bounded_fields(
    tmp_path, monkeypatch
):
    from northgate_rmm import credential_rotation

    original_reference = credential_rotation.regular_file_reference

    @contextmanager
    def deployment_owned_reference(*args, **kwargs):
        # Model the root-owned deployment config without requiring test CI to
        # own a privileged account. Real no-follow/size checks still run.
        with original_reference(*args, **kwargs) as ref:
            yield SimpleNamespace(
                stat=lambda: SimpleNamespace(st_uid=0, st_mode=0o100644),
                read_text=ref.read_text,
            )

    monkeypatch.setattr(
        credential_rotation, "regular_file_reference", deployment_owned_reference
    )
    value = {
        "schema": 1,
        "executable": str(tmp_path / "freerdp"),
        "executable_sha256": "ab" * 32,
        "timeout_seconds": 20,
    }
    path = tmp_path / "rotation.json"
    path.write_text(json.dumps(value))
    assert load_rotation_configuration(path) == value
    for change in (
        {"timeout_seconds": True},
        {"timeout_seconds": 60},
        {"schema": True},
        {"executable": "relative"},
        {"executable_sha256": "placeholder"},
        {"extra": "flag"},
    ):
        path.write_text(json.dumps({**value, **change}))
        with pytest.raises(ValueError):
            load_rotation_configuration(path)
    path.write_text(
        json.dumps(
            {
                **value,
                "xvfb_executable": str(tmp_path / "Xvfb"),
                "xvfb_sha256": "ab" * 32,
            }
        )
    )
    assert load_rotation_configuration(path)["xvfb_sha256"] == "ab" * 32
    path.write_text(json.dumps({**value, "xvfb_executable": str(tmp_path / "Xvfb")}))
    with pytest.raises(ValueError):
        load_rotation_configuration(path)


def test_unavailable_verifier_never_stages_or_dispatches(tmp_path):
    async def scenario():
        r = rig(tmp_path)
        r.verifier.ready = False
        with pytest.raises(web.HTTPConflict):
            await start(r)
        assert len(r.provider.values) == 1
        assert r.api.state.rotations(r.record["id"]) == []
        assert r.store.list(r.endpoint) == []

    asyncio.run(scenario())
