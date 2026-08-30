"""Ephemeral test-only certificate authority for protocol identity tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True, slots=True)
class TestCredentialSet:
    root_certificate: x509.Certificate
    endpoint_certificate: x509.Certificate


def issue_test_endpoint_credential(
    endpoint_id: UUID,
    *,
    now: datetime,
) -> TestCredentialSet:
    """Create a short-lived root and endpoint certificate entirely in memory."""

    root_key = Ed25519PrivateKey.generate()
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "NorthGate Test CA")]
    )
    root_certificate = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, algorithm=None)
    )

    endpoint_key = Ed25519PrivateKey.generate()
    endpoint_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"test-endpoint-{endpoint_id}")]
    )
    endpoint_certificate = (
        x509.CertificateBuilder()
        .subject_name(endpoint_name)
        .issuer_name(root_certificate.subject)
        .public_key(endpoint_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        f"urn:northgate-rmm:endpoint:{endpoint_id}"
                    )
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, algorithm=None)
    )
    return TestCredentialSet(
        root_certificate=root_certificate,
        endpoint_certificate=endpoint_certificate,
    )
