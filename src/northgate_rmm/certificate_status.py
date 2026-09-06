"""Publish short-lived signed server-certificate status from an offline registry.

Serve only the public output directory over the private status HTTPS origin.
The signing identity and registry are not readable by the web server.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from northgate_rmm.errors import ValidationError
from northgate_rmm.workload_service import canonical, load_configuration, read_private


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = load_configuration(args.config)
        registry = load_configuration(Path(config["registry"]))
        key = serialization.load_pem_private_key(
            read_private(config["private_key"]), None
        )
        if not isinstance(key, Ed25519PrivateKey) or len(registry) > 256:
            raise ValidationError("status authority configuration invalid")
        destination = Path(config["output_directory"])
        if (
            not destination.is_absolute()
            or destination.is_symlink()
            or not destination.is_dir()
        ):
            raise ValidationError("status directory invalid")
        now = int(time.time())
        for fingerprint, state in registry.items():
            if re.fullmatch("[0-9a-f]{64}", fingerprint) is None or state not in (
                "good",
                "revoked",
            ):
                raise ValidationError("status registry invalid")
            # Sign exact bytes; consumers need not reproduce JSON canonicalization.
            payload = canonical(
                {
                    "sha256": fingerprint,
                    "status": state,
                    "issued": now,
                    "expires": now + 120,
                }
            )
            record = canonical(
                {
                    "payload": base64.b64encode(payload).decode("ascii"),
                    "signature": base64.b64encode(key.sign(payload)).decode("ascii"),
                }
            )
            temporary = destination / (fingerprint + ".pending")
            with temporary.open("xb") as output:
                output.write(record)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination / (fingerprint + ".json"))
        descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        print("certificate status publication unavailable", file=sys.stderr)
        return 1
    return 0
