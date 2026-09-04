"""Bounded public-key identity comparison for separated TLS roles."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from northgate_rmm.agent_service import _read_regular_file
from northgate_rmm.errors import ValidationError

MAX_TLS_IDENTITY_CERTIFICATE_BYTES = 65_536


def load_tls_identity_public_key(path: Path, *, label: str) -> bytes:
    """Load the first PEM leaf and return canonical SubjectPublicKeyInfo bytes."""

    encoded = _read_regular_file(
        path,
        label=label,
        maximum_bytes=MAX_TLS_IDENTITY_CERTIFICATE_BYTES,
        private=False,
    )
    try:
        certificates = x509.load_pem_x509_certificates(encoded)
        if not certificates:
            raise ValueError("certificate bundle is empty")
        return (
            certificates[0]
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    except (ValueError, UnsupportedAlgorithm) as error:
        raise ValidationError(f"{label} is invalid") from error
