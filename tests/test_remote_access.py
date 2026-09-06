from __future__ import annotations

import asyncio
import base64
import hmac
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from northgate_rmm.domain import EndpointHealth, EndpointLifecycle, EndpointStatus
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.operator_api import OperatorAuthorizationPolicy, OperatorPrincipal
from northgate_rmm.remote_gateway import COOKIE, RemoteGateway, encrypt_connection
from northgate_rmm.remote_policy import RemoteLease, RemoteTarget, authorize_remote

NOW = datetime.now(UTC)
TARGET = RemoteTarget(uuid4(), uuid4(), "10.20.30.40")
POLICY = OperatorAuthorizationPolicy("https://idp.test", "lab", "owner", "rmm")
PRINCIPAL = OperatorPrincipal(
    "https://idp.test",
    "lab",
    "owner",
    "login1",
    "rmm",
    ("viewer", "remote_operator"),
    NOW - timedelta(minutes=1),
    NOW + timedelta(hours=1),
    True,
)
STATUS = EndpointStatus(
    TARGET.endpoint_id, EndpointLifecycle.ACTIVE, EndpointHealth.ONLINE, NOW
)


@pytest.mark.parametrize(
    "change",
    [
        {"roles": ("viewer",)},
        {"mfa": False},
        {"subject": "someone-else"},
        {"issuer": "https://other.test"},
        {"client_id": "other"},
        {"tenant": "other"},
        {"expires_at": NOW - timedelta(seconds=1)},
        {"authenticated_at": NOW + timedelta(seconds=1)},
    ],
)
def test_remote_access_rejects_wrong_human_scope(change):
    with pytest.raises(AuthorizationError):
        authorize_remote(
            replace(PRINCIPAL, **change),
            POLICY,
            TARGET,
            STATUS,
            TARGET.identity_id,
            now=NOW,
        )


@pytest.mark.parametrize(
    "change",
    [
        {"lifecycle": EndpointLifecycle.REVOKED},
        {"health": EndpointHealth.OFFLINE},
        {"health": EndpointHealth.STALE},
        {"endpoint_id": uuid4()},
    ],
)
def test_remote_access_rejects_unavailable_endpoint(change):
    with pytest.raises(AuthorizationError):
        authorize_remote(
            PRINCIPAL,
            POLICY,
            TARGET,
            replace(STATUS, **change),
            TARGET.identity_id,
            now=NOW,
        )


def test_remote_access_requires_current_cryptographic_identity():
    authorize_remote(PRINCIPAL, POLICY, TARGET, STATUS, TARGET.identity_id, now=NOW)
    with pytest.raises(AuthorizationError):
        authorize_remote(PRINCIPAL, POLICY, TARGET, STATUS, uuid4(), now=NOW)


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "169.254.169.254", "8.8.8.8", "example.test"]
)
def test_remote_targets_do_not_allow_browser_style_arbitrary_destinations(address):
    with pytest.raises(ValidationError):
        replace(TARGET, address=address)


def test_lease_cannot_be_reused_after_login_change_or_expiry():
    lease = RemoteLease(
        uuid4(),
        TARGET.endpoint_id,
        TARGET.identity_id,
        "owner",
        "login1",
        NOW,
        NOW + timedelta(minutes=10),
    )
    lease.check(PRINCIPAL, TARGET, now=NOW)
    with pytest.raises(AuthorizationError):
        lease.check(replace(PRINCIPAL, session_id="login2"), TARGET, now=NOW)
    with pytest.raises(AuthorizationError):
        lease.check(PRINCIPAL, TARGET, now=NOW + timedelta(minutes=10))


def decrypt(key, ciphertext):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    padded = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    signed = unpadder.update(padded) + unpadder.finalize()
    assert hmac.compare_digest(signed[:32], hmac.digest(key, signed[32:], "sha256"))
    return json.loads(signed[32:])


def test_guacamole_format_is_signed_then_encrypted_and_expires():
    key = bytes(range(16))
    value = {"username": "test", "expires": 123456, "connections": {}}
    assert decrypt(key, encrypt_connection(key, value)) == value


def test_connect_requires_csrf_and_issues_only_the_exact_target():
    class Operation:
        _policy = POLICY
        _store = SimpleNamespace(
            get_endpoint=lambda endpoint: SimpleNamespace(
                identity_id=TARGET.identity_id, display_name="Workstation"
            ),
            endpoint_status=lambda endpoint, now: STATUS,
        )

        def _authenticate(self, authorization, **kwargs):
            if authorization != "Bearer synthetic":
                raise AuthorizationError("invalid")
            return PRINCIPAL

        def _audit(self, *args, **kwargs):
            pass

    async def scenario():
        gateway = RemoteGateway(
            Operation(),
            {
                TARGET.endpoint_id: (
                    TARGET,
                    {"username": "remote", "password": "synthetic-password"},
                )
            },
            bytes(range(16)),
            "https://operator.test",
        )
        async with TestClient(TestServer(gateway.application())) as client:
            path = "/remote/" + str(TARGET.endpoint_id)
            response = await client.get(path)
            assert response.status == 403
            headers = {
                "Authorization": "Bearer synthetic",
                "Origin": "https://operator.test",
            }
            response = await client.get(path + "/desktop.rdp")
            assert response.status == 403
            response = await client.get(path + "/desktop.rdp", headers=headers)
            assert response.status == 200
            rdp = (await response.read()).decode("utf-16")
            assert f"full address:s:{TARGET.address}:3389" in rdp
            assert "synthetic-password" not in rdp
            assert "prompt for credentials:i:1" in rdp
            response = await client.get(path, headers=headers)
            assert response.status == 200
            assert response.headers["Referrer-Policy"] == "strict-origin"
            nonce = next(iter(gateway.forms))
            # Null origins remain forbidden; fix the browser policy, not CSRF.
            response = await client.post(
                path,
                headers={**headers, "Origin": "null"},
                data={"nonce": nonce},
                allow_redirects=False,
            )
            assert response.status == 403
            response = await client.post(
                path,
                headers={**headers, "Origin": "https://evil.test"},
                data={"nonce": nonce},
                allow_redirects=False,
            )
            assert response.status == 403
            response = await client.post(
                path, headers=headers, data={"nonce": nonce}, allow_redirects=False
            )
            assert response.status == 302
            ciphertext = parse_qs(urlsplit(response.headers["Location"]).query)["data"][
                0
            ]
            value = decrypt(bytes(range(16)), ciphertext)
            parameters = value["connections"]["SSH Terminal"]["parameters"]
            assert parameters["hostname"] == TARGET.address
            assert parameters["disable-copy"] == "true"
            assert parameters["enable-drive"] == "false"
            assert "synthetic-password" not in response.headers["Location"]
            assert response.cookies[COOKIE]["httponly"]
            assert response.cookies[COOKIE]["secure"]
            cookie = response.cookies[COOKIE].value
            state = gateway.leases[cookie]
            assert state.lease.expires_at > PRINCIPAL.expires_at
            response = await client.get(
                "/remote/keepalive",
                headers={**headers, "Cookie": COOKIE + "=" + cookie},
            )
            assert response.status == 204
            assert state.authorization == "Bearer synthetic"
            response = await client.post(
                "/remote/end",
                headers={**headers, "Cookie": COOKIE + "=" + cookie},
                allow_redirects=False,
            )
            assert response.status == 302
            assert not gateway.leases
            response = await client.post(
                path, headers=headers, data={"nonce": nonce}, allow_redirects=False
            )
            assert response.status == 403

    asyncio.run(scenario())
