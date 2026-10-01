"""Build an explicitly qualified optional-tool package; never downloads software."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from northgate_rmm.tool_catalog_models import (
    BUILTIN,
    TOOLS,
    manifest_bytes,
    validate_manifest,
)


def publish(
    source: Path, metadata: dict, key_file: Path, catalog: Path, releases: Path
):
    if source.is_symlink() or not source.is_dir():
        raise ValueError("A local reviewed payload directory is required")
    key = Ed25519PrivateKey.from_private_bytes(key_file.read_bytes())
    files = sorted(source.rglob("*"))
    if len(files) > 512 or any(p.is_symlink() for p in files):
        raise ValueError("Package files exceed bounds or contain symlinks")
    catalog.mkdir(mode=0o700, parents=True, exist_ok=True)
    releases.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="northgate-tool-") as staging:
        archive = Path(staging) / "bundle.zip"
        total = 0
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for path in files:
                if not path.is_file():
                    continue
                total += path.stat().st_size
                if total > metadata["budget"]["disk_mib"] * 1024 * 1024:
                    raise ValueError("Unpacked tool exceeds disk budget")
                name = path.relative_to(source).as_posix()
                if name.lower() == "installed.json":
                    raise ValueError("Reserved metadata filename")
                bundle.write(path, name)
        data = archive.read_bytes()
        metadata = dict(
            metadata, schema=1, sha256=hashlib.sha256(data).hexdigest(), size=len(data)
        )
        validate_manifest(metadata)
        if not (source / metadata["entrypoint"]).is_file():
            raise ValueError("Expected recipe entrypoint is absent")
        raw = manifest_bytes(metadata)
        signature = base64.b64encode(key.sign(b"NorthGate-Tool-v1\0" + raw)).decode()
        public = base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        authority = catalog / "authority.pub"
        if authority.exists() and authority.read_bytes().strip() != public:
            raise ValueError(
                "Catalog authority differs; rotate through a separate reviewed workflow"
            )
        blob = releases / metadata["sha256"]
        if not blob.exists():
            with blob.open("xb") as output:
                output.write(data)
            blob.chmod(0o600)
        elif hashlib.sha256(blob.read_bytes()).hexdigest() != metadata["sha256"]:
            raise ValueError("Existing release digest mismatch")
        name = "-".join(str(metadata[k]) for k in ("id", "platform", "arch"))
        entry = catalog / f"{name}-{metadata['revision']:07d}.json"
        encoded = json.dumps(
            {"manifest": metadata, "signature": signature}, indent=2
        ).encode()
        if entry.exists():
            raise ValueError(
                "Revision already exists; publish a new monotonic revision"
            )
        with entry.open("xb") as output:
            output.write(encoded)
        entry.chmod(0o600)
        if not authority.exists():
            with authority.open("xb") as output:
                output.write(public + b"\n")
            authority.chmod(0o600)
    return {
        "id": metadata["id"],
        "version": metadata["version"],
        "revision": metadata["revision"],
        "sha256": metadata["sha256"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--releases", type=Path, required=True)
    parser.add_argument("--license-reviewed", action="store_true", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    metadata = json.loads(args.metadata.read_text())
    if metadata.get("id") not in set(TOOLS) - BUILTIN:
        parser.error("Choose a supported optional tool")
    print(
        json.dumps(
            publish(args.source, metadata, args.key, args.catalog, args.releases)
        )
    )


if __name__ == "__main__":
    main()
