"""Same-key renewal revalidates current identity after external issuance."""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from northgate_rmm.agent_api import VerifiedClientCertificate
from northgate_rmm.domain import EndpointIdentity
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.persistence import PostgresControlPlane
from northgate_rmm.renewal import RenewalService
from northgate_rmm.workload_service import canonical
from tests.test_enrollment import NOW, FakeIssuer, csr_for, issue_root


def renewal_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    RenewalService,
    VerifiedClientCertificate,
    dict[str, Any],
    MagicMock,
    FakeIssuer,
    list[Any],
]:
    monkeypatch.setattr("northgate_rmm.enrollment._current_utc_time", lambda: NOW)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = csr_for(key)
    fingerprint = (
        "sha256:"
        + hashlib.sha256(
            key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
    )
    endpoint = uuid4()
    identity = EndpointIdentity(
        identity_id=uuid4(),
        endpoint_id=endpoint,
        public_key_fingerprint=fingerprint,
        created_at=NOW,
    )
    peer = VerifiedClientCertificate(endpoint, fingerprint)
    root, root_key = issue_root()
    issuer = FakeIssuer(root, root_key)
    store = MagicMock(spec=PostgresControlPlane)
    store.authenticate_endpoint_certificate.return_value = identity
    connection = store._connect.return_value.__enter__.return_value
    cursor = connection.cursor.return_value.__enter__.return_value
    rows: list[Any] = [
        None,
        {"certificate_not_after": NOW + timedelta(hours=1)},
        {
            "identity_status": "active",
            "revoked_at": None,
            "certificate_not_after": NOW + timedelta(hours=1),
            "current_identity": identity.identity_id,
        },
        None,
    ]
    cursor.fetchone.side_effect = lambda: rows.pop(0)
    body: dict[str, Any] = {
        "request_id": str(uuid4()),
        "csr": base64.b64encode(csr).decode(),
    }
    return RenewalService(store, issuer, root), peer, body, cursor, issuer, rows


def test_renewal_preserves_identity_and_records_signed_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, peer, body, cursor, issuer, _ = renewal_fixture(monkeypatch)
    result = service.renew(canonical(body), peer, NOW)
    assert result["endpoint_id"] == str(peer.endpoint_id)
    assert result["state"] == "issued"
    assert base64.b64decode(result["leaf_certificate"])
    assert len(issuer.requests) == 1
    statements = [call.args[0] for call in cursor.execute.call_args_list]
    assert any("FOR UPDATE OF i,e" in sql for sql in statements)
    assert any("INSERT INTO certificate_renewals" in sql for sql in statements)
    assert any("UPDATE endpoint_identities" in sql for sql in statements)


@pytest.mark.parametrize("late", [False, True])
def test_renewal_retry_returns_original_response(
    monkeypatch: pytest.MonkeyPatch,
    late: bool,
) -> None:
    service, peer, body, _, issuer, rows = renewal_fixture(monkeypatch)
    rows[3 if late else 0] = {"response": {"state": "previously-issued"}}
    assert service.renew(canonical(body), peer, NOW) == {"state": "previously-issued"}
    assert len(issuer.requests) == int(late)


@pytest.mark.parametrize(
    "window",
    [
        None,
        {"certificate_not_after": None},
        {"certificate_not_after": NOW + timedelta(hours=7)},
    ],
)
def test_renewal_refuses_requests_outside_window(
    monkeypatch: pytest.MonkeyPatch,
    window: dict[str, object] | None,
) -> None:
    service, peer, body, _, issuer, rows = renewal_fixture(monkeypatch)
    rows[1] = window
    with pytest.raises(AuthorizationError, match="outside its window"):
        service.renew(canonical(body), peer, NOW)
    assert not issuer.requests


@pytest.mark.parametrize(
    "change", ["missing", "revoked", "status", "identity", "renewed"]
)
def test_renewal_rejects_identity_changes_during_issuance(
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    service, peer, body, cursor, _, rows = renewal_fixture(monkeypatch)
    current = rows[2]
    if change == "missing":
        rows[2] = None
    elif change == "revoked":
        current["revoked_at"] = NOW
    elif change == "status":
        current["identity_status"] = "pending"
    elif change == "identity":
        current["current_identity"] = uuid4()
    else:
        current["certificate_not_after"] = NOW + timedelta(hours=12)
    with pytest.raises(AuthorizationError):
        service.renew(canonical(body), peer, NOW)
    assert not any(
        "UPDATE endpoint_identities" in call.args[0]
        for call in cursor.execute.call_args_list
    )


def test_renewal_rejects_wrong_key_and_noncanonical_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, peer, body, _, issuer, _ = renewal_fixture(monkeypatch)
    with pytest.raises(ValidationError, match="fields invalid"):
        service.renew(canonical({**body, "extra": True}), peer, NOW)
    with pytest.raises(ValidationError, match="request ID invalid"):
        service.renew(
            canonical({**body, "request_id": body["request_id"].upper()}), peer, NOW
        )
    another = VerifiedClientCertificate(peer.endpoint_id, "sha256:" + "f" * 64)
    with pytest.raises(AuthorizationError, match="authenticated key"):
        service.renew(canonical(body), another, NOW)
    assert not issuer.requests
