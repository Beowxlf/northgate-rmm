"""OIDC introspection binds identity, audience, MFA and token lifetime."""

from __future__ import annotations

import ipaddress
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

import northgate_rmm.oidc_bridge as oidc_bridge
from northgate_rmm.errors import AuthorizationError, ValidationError


def bridge_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[oidc_bridge.OIDCBridge, dict[str, Any], Mock]:
    secret = tmp_path / "introspection-secret"
    secret.write_text("synthetic" + "-client-credential")
    secret.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(ssl, "create_default_context", lambda **kw: context)
    config: dict[str, Any] = {
        "subject": "operator-1",
        "allowed_subjects": ["operator-2"],
        "introspection_url": "https://idp.example.test/introspect",
        "idp_connect_address": "127.0.0.1",
        "idp_ca_certificate": "synthetic-ca.pem",
        "client_secret_file": str(secret),
        "client_id": "northgate",
        "issuer": "https://idp.example.test",
        "tenant": "synthetic-tenant",
        "required_acr": "urn:synthetic:mfa",
        "required_amr": "otp",
    }
    connection = Mock()
    response = connection.getresponse.return_value
    response.status = 200
    response.getheader.return_value = None
    now = int(datetime.now(UTC).timestamp())
    value: dict[str, Any] = {
        "active": True,
        "iss": config["issuer"],
        "sub": "operator-1",
        "aud": "northgate",
        "client_id": "northgate",
        "acr": config["required_acr"],
        "amr": ["pwd", "otp"],
        "auth_time": now - 60,
        "exp": now + 300,
        "sid": "synthetic-session",
        "resource_access": {"northgate": {"roles": ["viewer", "remote_operator"]}},
    }
    response.read.side_effect = lambda maximum: json.dumps(value).encode()
    monkeypatch.setattr(
        oidc_bridge, "PinnedHTTPSConnection", Mock(return_value=connection)
    )
    return oidc_bridge.OIDCBridge(config), value, connection


def test_oidc_success_pins_transport_and_preserves_allowed_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, value, connection = bridge_fixture(tmp_path, monkeypatch)
    status, result = bridge.handle("/verify", b"", "Bearer synthetic-session")
    assert status == 200
    assert result["subject"] == "operator-1"
    assert result["roles"] == ["viewer", "remote_operator"]
    assert result["mfa"] is True
    assert bridge.address == "127.0.0.1"
    assert bridge.context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert bridge.context.maximum_version is ssl.TLSVersion.TLSv1_3
    connection.request.assert_called_once()
    assert connection.request.call_args.args == ("POST", "/introspect")
    assert (
        connection.request.call_args.kwargs["headers"]["Authorization"] == bridge.basic
    )
    assert b"token=synthetic-session" in connection.request.call_args.kwargs["body"]
    connection.close.assert_called_once()
    value["sub"] = "operator-2"
    value["aud"] = ["northgate"]
    assert (
        bridge.handle("/verify", b"", "Bearer synthetic-session")[1]["subject"]
        == "operator-2"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active", False),
        ("iss", "https://other.example.test"),
        ("sub", "unlisted"),
        ("aud", "another-client"),
        ("aud", None),
        ("client_id", "another-client"),
        ("acr", "weak"),
        ("amr", []),
        ("amr", "otp"),
        ("auth_time", "invalid"),
        ("exp", True),
        ("auth_time", 0),
        ("exp", 0),
        ("resource_access", {"northgate": {"roles": []}}),
        ("resource_access", {"northgate": {"roles": "viewer"}}),
    ],
)
def test_oidc_rejects_untrusted_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    bridge, claims, connection = bridge_fixture(tmp_path, monkeypatch)
    claims[field] = value
    with pytest.raises(AuthorizationError):
        bridge.handle("/verify", b"", "Bearer synthetic-session")
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic synthetic", "Bearer bad token", "Bearer " + "x" * 4096],
)
def test_oidc_rejects_invalid_authorization_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, authorization: str | None
) -> None:
    bridge, _, connection = bridge_fixture(tmp_path, monkeypatch)
    with pytest.raises(AuthorizationError):
        bridge.handle("/verify", b"", authorization)
    connection.request.assert_not_called()


@pytest.mark.parametrize("status, encoding", [(302, None), (200, "gzip")])
def test_oidc_rejects_redirect_and_encoded_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int, encoding: str | None
) -> None:
    bridge, _, connection = bridge_fixture(tmp_path, monkeypatch)
    connection.getresponse.return_value.status = status
    connection.getresponse.return_value.getheader.return_value = encoding
    with pytest.raises(AuthorizationError):
        bridge.handle("/verify", b"", "Bearer synthetic-session")
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    "field,value",
    [
        ("allowed_subjects", "operator"),
        ("allowed_subjects", [""]),
        ("introspection_url", "http://idp.example.test"),
        ("introspection_url", "https://user@idp.example.test"),
        ("introspection_url", "https://idp.example.test/?query=1"),
        ("idp_connect_address", "8.8.8.8"),
        ("idp_connect_address", str(ipaddress.IPv4Address(0))),
        ("client_id", "invalid:client"),
    ],
)
def test_oidc_rejects_unsafe_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    bridge, _, _ = bridge_fixture(tmp_path, monkeypatch)
    with pytest.raises(ValidationError):
        oidc_bridge.OIDCBridge({**bridge.config, field: value})


def test_oidc_factory_routes_and_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge, _, _ = bridge_fixture(tmp_path, monkeypatch)
    operation, paths = oidc_bridge.factory(bridge.config)
    assert callable(operation)
    assert paths == frozenset({"/v1/operator-sessions/verify"})
    main = Mock(return_value=17)
    monkeypatch.setattr(oidc_bridge, "service_main", main)
    assert oidc_bridge.main(["--config", "synthetic.json"]) == 17
    main.assert_called_once_with(oidc_bridge.factory, ["--config", "synthetic.json"])
