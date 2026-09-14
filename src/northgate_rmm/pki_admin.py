"""Offline creation of separated trust roots and constrained workload certificates."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from northgate_rmm.errors import ValidationError
from northgate_rmm.workload_service import read_private


def write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "profile",
        choices=("root", "endpoint-intermediate", "server", "workload", "signing"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--issuer-key", type=Path)
    parser.add_argument("--issuer-chain", type=Path)
    args = parser.parse_args(argv)
    try:
        if (
            not args.output.is_absolute()
            or args.output.exists()
            or len(args.name) > 128
        ):
            raise ValidationError("new absolute output directory required")
        args.output.mkdir(mode=0o700)
        if args.profile == "signing":
            signing = ed25519.Ed25519PrivateKey.generate()
            write(
                args.output / "private.pem",
                signing.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            )
            write(
                args.output / "public.pem",
                signing.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
            return 0
        key = ec.generate_private_key(ec.SECP384R1())
        issuer_key = key
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.name)])
        now = datetime.now(UTC)
        lifetime = {
            "root": 3650,
            "endpoint-intermediate": 365,
            "server": 1,
            "workload": 1,
        }[args.profile]
        expires = now + timedelta(days=lifetime)
        issuer_name = subject
        chain: list[x509.Certificate] = []
        if args.profile != "root":
            if args.issuer_key is None or args.issuer_chain is None:
                raise ValidationError("offline issuer required")
            loaded = serialization.load_pem_private_key(
                read_private(str(args.issuer_key)), None
            )
            if not isinstance(loaded, ec.EllipticCurvePrivateKey):
                raise ValidationError("EC issuer required")
            issuer_key = loaded
            chain = x509.load_pem_x509_certificates(
                read_private(str(args.issuer_chain))
            )
            issuer = chain[0]
            constraints = issuer.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            if not constraints.ca or (
                args.profile == "endpoint-intermediate" and constraints.path_length == 0
            ):
                raise ValidationError("issuer scope invalid")
            if issuer.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ) != issuer_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ):
                raise ValidationError("issuer key mismatch")
            issuer_name = issuer.subject
            expires = min(expires, issuer.not_valid_after_utc)
            if issuer.not_valid_before_utc > now or expires <= now + timedelta(hours=1):
                raise ValidationError("issuer validity unavailable")
        ca = args.profile in ("root", "endpoint-intermediate")
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(expires)
            .add_extension(
                x509.BasicConstraints(
                    ca, (1 if args.profile == "root" else 0) if ca else None
                ),
                True,
            )
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, ca, ca, False, False),
                True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    issuer_key.public_key()
                ),
                False,
            )
        )
        if not ca:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if args.profile == "server"
                        else ExtendedKeyUsageOID.CLIENT_AUTH
                    ]
                ),
                False,
            )
            if args.profile == "server":
                builder = builder.add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(args.name)]), False
                )
        certificate = builder.sign(issuer_key, hashes.SHA384())
        write(
            args.output / "private.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        write(
            args.output / "chain.pem",
            b"".join(
                item.public_bytes(serialization.Encoding.PEM)
                for item in [certificate, *chain]
            ),
        )
    except Exception:
        print(
            "offline PKI operation incomplete; reconcile retained directory",
            file=sys.stderr,
        )
        return 1
    return 0
