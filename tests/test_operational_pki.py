"""Verify offline trust separation and restricted endpoint issuance end to end."""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID

from northgate_rmm import pki_admin
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.issuer_service import RestrictedIssuer, open_ledger
from northgate_rmm.workload_service import canonical

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX offline key custody")


def generate(
    tmp_path: Path, profile: str, name: str, issuer: Path | None = None
) -> Path:
    output = tmp_path / name
    args = [profile, "--output", str(output), "--name", name]
    if issuer is not None:
        args += [
            "--issuer-key",
            str(issuer / "private.pem"),
            "--issuer-chain",
            str(issuer / "chain.pem"),
        ]
    assert pki_admin.main(args) == 0
    return output


def test_offline_profiles_have_separate_authorities_and_constraints(
    tmp_path: Path,
) -> None:
    root = generate(tmp_path, "root", "root")
    intermediate = generate(tmp_path, "endpoint-intermediate", "intermediate", root)
    server = generate(tmp_path, "server", "server.example.internal", root)
    workload = generate(tmp_path, "workload", "workload", root)
    signing = generate(tmp_path, "signing", "signing")
    for directory, expected_ca, path_length in [
        (root, True, 1),
        (intermediate, True, 0),
        (server, False, None),
        (workload, False, None),
    ]:
        chain = x509.load_pem_x509_certificates((directory / "chain.pem").read_bytes())
        leaf = chain[0]
        constraints = leaf.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        assert (constraints.ca, constraints.path_length) == (expected_ca, path_length)
        assert (directory / "private.pem").stat().st_mode & 0o077 == 0
        if directory != root:
            leaf.verify_directly_issued_by(chain[1])
        if not expected_ca:
            usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            assert list(usage) == [
                ExtendedKeyUsageOID.SERVER_AUTH
                if directory == server
                else ExtendedKeyUsageOID.CLIENT_AUTH
            ]
    cert = x509.load_pem_x509_certificate((server / "chain.pem").read_bytes())
    assert cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName) == ["server.example.internal"]
    public = serialization.load_pem_public_key((signing / "public.pem").read_bytes())
    assert isinstance(public, ed25519.Ed25519PublicKey)
    before = (root / "private.pem").read_bytes()
    assert pki_admin.main(["root", "--output", str(root), "--name", "duplicate"]) == 1
    assert (root / "private.pem").read_bytes() == before
    assert (
        pki_admin.main(
            [
                "server",
                "--output",
                str(tmp_path / "missing-issuer"),
                "--name",
                "invalid",
            ]
        )
        == 1
    )
    assert (
        pki_admin.main(
            [
                "endpoint-intermediate",
                "--output",
                str(tmp_path / "too-deep"),
                "--name",
                "invalid",
                "--issuer-key",
                str(intermediate / "private.pem"),
                "--issuer-chain",
                str(intermediate / "chain.pem"),
            ]
        )
        == 1
    )


def test_restricted_issuer_binds_idempotence_key_and_endpoint(tmp_path: Path) -> None:
    root = generate(tmp_path, "root", "root")
    intermediate = generate(tmp_path, "endpoint-intermediate", "issuer", root)
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir(mode=0o700)
    config = {
        "ledger": str(ledger_dir / "issuer.sqlite"),
        "issuer_private_key": str(intermediate / "private.pem"),
        "issuer_chain": str(intermediate / "chain.pem"),
    }
    issuer = RestrictedIssuer(config)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, hashes.SHA256())
    )
    request: dict[str, Any] = {
        "identity_id": str(uuid4()),
        "endpoint_id": str(uuid4()),
        "csr": base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode(),
        "public_key_fingerprint": "sha256:"
        + hashlib.sha256(
            key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest(),
        "requested_at": datetime.now(UTC).isoformat(),
    }
    status, response = issuer.handle(
        "/v1/endpoint-certificates", canonical(request), None
    )
    assert status == 201
    leaf = x509.load_der_x509_certificate(
        base64.b64decode(response["leaf_certificate"])
    )
    leaf.verify_directly_issued_by(
        x509.load_pem_x509_certificate((intermediate / "chain.pem").read_bytes())
    )
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc <= timedelta(hours=24)
    assert leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier) == [
        "urn:northgate-rmm:endpoint:" + request["endpoint_id"]
    ]
    assert issuer.handle("/v1/endpoint-certificates", canonical(request), None) == (
        status,
        response,
    )
    with pytest.raises(AuthorizationError):
        issuer.handle(
            "/v1/endpoint-certificates",
            canonical({**request, "endpoint_id": str(uuid4())}),
            None,
        )
    with pytest.raises(ValidationError):
        issuer.handle(
            "/v1/endpoint-certificates",
            canonical({**request, "public_key_fingerprint": "sha256:" + "0" * 64}),
            None,
        )
    with pytest.raises(ValidationError):
        issuer.handle(
            "/v1/endpoint-certificates",
            canonical(
                {
                    **request,
                    "requested_at": (
                        datetime.now(UTC) - timedelta(minutes=2)
                    ).isoformat(),
                }
            ),
            None,
        )
    with pytest.raises(ValidationError):
        issuer.handle(
            "/v1/endpoint-certificates", canonical({**request, "extra": 1}), None
        )
    with open_ledger(issuer.path) as db:
        assert db.execute("SELECT count(*) FROM issued").fetchone()[0] == 1
        db.execute("UPDATE issued SET revoked=1")
    with pytest.raises(AuthorizationError):
        issuer.handle("/v1/endpoint-certificates", canonical(request), None)
    with pytest.raises(ValidationError, match="path-length-zero"):
        RestrictedIssuer(
            {
                **config,
                "issuer_chain": str(root / "chain.pem"),
                "issuer_private_key": str(root / "private.pem"),
            }
        )
