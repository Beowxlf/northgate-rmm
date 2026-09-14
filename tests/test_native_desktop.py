import asyncio
import json
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer

from northgate_rmm.native_desktop import NativeDesktopProfiles, credential_binding
from northgate_rmm.remote_gateway import RemoteGateway
from northgate_rmm.remote_policy import parse_remote_targets
from tests.test_browser_rdp import configuration


def profile(tmp_path):
    targets = parse_remote_targets(configuration())
    target, fields = next(iter(targets.methods.values()))["rdp"]
    record = {
        "subject": "owner",
        "endpoint_id": str(target.endpoint_id),
        "identity_id": str(target.identity_id),
        "address": target.address,
        "username": fields["username"],
        "password51": "01000000d08c9ddf0115d1118c7a00c04fc297eb" + "ab" * 100,
        "credential_binding": credential_binding(
            bytes(16),
            target.endpoint_id,
            target.identity_id,
            target.address,
            fields["username"],
            fields["password"],
        ),
    }
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({"schema": 1, "records": [record]}))
    path.chmod(0o600)
    return targets, target, fields, NativeDesktopProfiles(path, bytes(16)), record


@pytest.mark.parametrize("field", ["username", "password", "domain"])
def test_password_or_account_rotation_invalidates_envelope(tmp_path, field):
    _, target, fields, profiles, record = profile(tmp_path)
    assert profiles.validate(record, target, fields) == record["password51"]
    with pytest.raises(ValueError):
        profiles.validate(record, target, {**fields, field: "changed"})


def test_profiles_bound_to_subject_and_current_enrollment(tmp_path):
    _, target, _, profiles, record = profile(tmp_path)
    assert profiles.record("other", target) is None
    assert profiles.record("owner", target) == record
    record["address"] = "10.20.30.99"
    profiles.path.write_text(json.dumps({"schema": 1, "records": [record]}))
    with pytest.raises(ValueError):
        profiles.record("owner", target)


def test_native_download_contains_only_encrypted_password(tmp_path):
    async def scenario():
        targets, target, fields, profiles, record = profile(tmp_path)
        gateway = RemoteGateway(None, targets, bytes(16), "https://operator.test")
        calls = []

        async def principal(*args, **kwargs):
            return SimpleNamespace(subject="owner")

        async def audit(*args, **kwargs):
            return None

        async def resolve(*args):
            calls.append("authorized reveal")
            return fields

        gateway.principal, gateway.audit = principal, audit
        gateway.native_profiles, gateway.native_secret_resolver = profiles, resolve
        async with TestClient(TestServer(gateway.application())) as client:
            response = await client.get(f"/remote/{target.endpoint_id}/desktop.rdp")
            assert response.status == 200
            content = (await response.read()).decode("utf-16")
            assert "password 51:b:" + record["password51"] in content
            assert fields["password"] not in content
            assert calls == ["authorized reveal"]
            fields["password"] = "rotated"  # noqa: S105 - synthetic rotation fixture
            response = await client.get(f"/remote/{target.endpoint_id}/desktop.rdp")
            assert response.status == 409

    asyncio.run(scenario())
