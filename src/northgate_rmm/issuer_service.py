"""Isolated restricted endpoint issuer with durable idempotent issuance."""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from northgate_rmm.enrollment import _validate_csr
from northgate_rmm.errors import AuthorizationError, ValidationError
from northgate_rmm.workload_service import (
    Operation,
    read_private,
    service_main,
    strict_object,
)


@contextmanager
def open_ledger(path: Path) -> Iterator[sqlite3.Connection]:
    if not path.is_absolute() or path.is_symlink() or path.parent.is_symlink():
        raise ValidationError("ledger path invalid")
    parent = path.parent.stat()
    if os.name == "posix" and (parent.st_mode & 0o077 or parent.st_uid != os.geteuid()):
        raise ValidationError("ledger directory must be private and owned by workload")
    if not path.exists():
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise ValidationError("ledger file must be private")
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


class RestrictedIssuer:
    def __init__(self, configuration: dict[str, Any]) -> None:
        self.path = Path(configuration["ledger"])
        loaded_key = serialization.load_pem_private_key(
            read_private(configuration["issuer_private_key"]), password=None
        )
        if not isinstance(loaded_key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
            raise ValidationError("issuer key algorithm unsupported")
        self.key = loaded_key
        self.chain = x509.load_pem_x509_certificates(
            read_private(configuration["issuer_chain"])
        )
        if not 1 <= len(self.chain) <= 4:
            raise ValidationError("issuer chain length invalid")
        self.issuer = self.chain[0]
        constraints = self.issuer.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        usage = self.issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        if (
            not constraints.ca
            or constraints.path_length != 0
            or not usage.key_cert_sign
        ):
            raise ValidationError("restricted path-length-zero intermediate required")
        if self.issuer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValidationError("issuer key mismatch")
        with open_ledger(self.path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS issued (identity TEXT PRIMARY KEY, "
                "endpoint TEXT NOT NULL, key_digest TEXT NOT NULL, certificate "
                "BLOB NOT NULL, fingerprint TEXT UNIQUE NOT NULL, revoked INTEGER "
                "NOT NULL DEFAULT 0, reason TEXT, created TEXT NOT NULL)"
            )

    def handle(
        self, _path: str, body: bytes, _authorization: str | None
    ) -> tuple[int, dict[str, Any]]:
        request = strict_object(body, maximum=16384)
        if set(request) != {
            "identity_id",
            "endpoint_id",
            "public_key_fingerprint",
            "csr",
            "requested_at",
        }:
            raise ValidationError("issuance schema invalid")
        identity, endpoint = (
            str(UUID(request["identity_id"])),
            str(UUID(request["endpoint_id"])),
        )
        if identity != request["identity_id"] or endpoint != request["endpoint_id"]:
            raise ValidationError("issuance identifiers invalid")
        now = datetime.now(UTC)
        requested = datetime.fromisoformat(request["requested_at"])
        if requested.tzinfo is None or abs((now - requested).total_seconds()) > 60:
            raise ValidationError("issuance request expired")
        canonical, fingerprint = _validate_csr(
            base64.b64decode(request["csr"], validate=True)
        )
        if fingerprint != request["public_key_fingerprint"]:
            raise ValidationError("issuance key mismatch")
        csr = x509.load_der_x509_csr(canonical)
        not_before, not_after = now - timedelta(seconds=30), now + timedelta(hours=23)
        if (
            not self.issuer.not_valid_before_utc
            <= not_before
            < not_after
            <= self.issuer.not_valid_after_utc
        ):
            raise ValidationError("issuer validity cannot cover requested certificate")
        if shutil.disk_usage(self.path.parent).free < 128 * 1024 * 1024:
            raise ValidationError("issuer capacity exhausted")
        with open_ledger(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT * FROM issued WHERE identity=?", (identity,)
            ).fetchone()
            if old is not None:
                if (
                    old["endpoint"] != endpoint
                    or old["key_digest"] != fingerprint
                    or old["revoked"]
                ):
                    raise AuthorizationError("issuance identity unavailable")
                encoded = bytes(old["certificate"])
                if x509.load_der_x509_certificate(encoded).not_valid_after_utc <= now:
                    raise AuthorizationError("issuance identity expired")
            else:
                count = db.execute("SELECT count(*) FROM issued").fetchone()[0]
                if count >= 100000:
                    raise ValidationError("issuer retention limit reached")
                certificate = (
                    x509.CertificateBuilder()
                    .subject_name(x509.Name([]))
                    .issuer_name(self.issuer.subject)
                    .public_key(csr.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(not_before)
                    .not_valid_after(not_after)
                    .add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True
                    )
                    .add_extension(
                        x509.KeyUsage(
                            True, False, False, False, False, False, False, False, False
                        ),
                        critical=True,
                    )
                    .add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                        critical=False,
                    )
                    .add_extension(
                        x509.SubjectAlternativeName(
                            [
                                x509.UniformResourceIdentifier(
                                    "urn:northgate-rmm:endpoint:" + endpoint
                                )
                            ]
                        ),
                        critical=True,
                    )
                    .add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                        critical=False,
                    )
                    .add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(
                            self.key.public_key()
                        ),
                        critical=False,
                    )
                    .sign(self.key, hashes.SHA256())
                )
                encoded = certificate.public_bytes(serialization.Encoding.DER)
                db.execute(
                    "INSERT INTO "
                    "issued(identity,endpoint,key_digest,"
                    "certificate,fingerprint,created) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        identity,
                        endpoint,
                        fingerprint,
                        encoded,
                        hashlib.sha256(encoded).hexdigest(),
                        now.isoformat(),
                    ),
                )
        return 201, {
            "leaf_certificate": base64.b64encode(encoded).decode("ascii"),
            "intermediate_certificates": [
                base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(
                    "ascii"
                )
                for cert in self.chain
            ],
        }


def factory(configuration: dict[str, Any]) -> tuple[Operation, frozenset[str]]:
    return RestrictedIssuer(configuration).handle, frozenset(
        {"/v1/endpoint-certificates"}
    )


def main(argv: Sequence[str] | None = None) -> int:
    return service_main(factory, argv)


if __name__ == "__main__":
    raise SystemExit(main())
