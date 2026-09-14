"""Local administrator utilities. Release signing keys never enter the web service."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import tarfile
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from northgate_rmm.management_protocol import canonical, derive
from northgate_rmm.secure_files import regular_file_reference

PREFIX = b"NorthGate-Recovery-v1\0"
SOURCES = {
    "management/management.sqlite3",
    "captures/capture.sqlite3",
    "inspection.sqlite3",
    "remote-credentials.aes",
}
MAX_BACKUP = 256 * 1024 * 1024


def read_private(path: Path | str, limit: int) -> bytes:
    with regular_file_reference(
        Path(path), label="administrative input", maximum_bytes=limit, private=True
    ) as ref:
        return ref.read_bytes()


def exclusive(path: Path | str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def publish_release(
    binary: Path | str,
    signing_key: Path | str,
    catalog: Path | str,
    component: str,
    platform: str,
    version: str,
    origin: str,
) -> dict[str, Any]:
    from urllib.parse import urlsplit

    u = urlsplit(origin)
    if (
        u.scheme != "https"
        or not u.hostname
        or u.path
        or u.query
        or u.fragment
        or u.username
    ):
        raise ValueError("Management HTTPS origin required")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-lab\.\d+)?", version):
        raise ValueError("Invalid version")
    if component not in {"worker", "agent", "wxlfgar"} or platform not in {
        "windows",
        "linux",
    }:
        raise ValueError("Invalid release target")
    data = read_private(binary, 64 * 1024 * 1024)
    digest = hashlib.sha256(data).hexdigest()
    key = Ed25519PrivateKey.from_private_bytes(read_private(signing_key, 32))
    manifest = {
        "component": component,
        "platform": platform,
        "sha256": digest,
        "version": version,
    }
    value = {
        "manifest": manifest,
        "url": origin + "/v1/management/releases/" + digest,
        "signature": base64.b64encode(
            key.sign(b"NorthGate-Release-v1\0" + canonical(manifest))
        ).decode(),
    }
    catalog = Path(catalog)
    catalog.mkdir(parents=True, exist_ok=True, mode=0o700)
    if catalog.is_symlink():
        raise ValueError("Catalog cannot be a symlink")
    exclusive(catalog / digest, data)
    exclusive(catalog / (digest + ".json"), canonical(value))
    return value


def backup(
    root: Path, credentials: Path | str, key: bytes, destination: Path
) -> dict[str, Any]:
    root = Path(root)
    files = {name: root / name for name in SOURCES if name != "remote-credentials.aes"}
    files["remote-credentials.aes"] = Path(credentials)
    archive = io.BytesIO()
    manifest = {}
    # Consistent SQLite snapshots avoid copying a database mid-transaction.
    with tempfile.TemporaryDirectory(prefix="northgate-recovery-") as temporary:
        Path(temporary).chmod(0o700)
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            total = 0
            for name, path in sorted(files.items()):
                read_private(
                    path, MAX_BACKUP
                )  # Require every declared recovery component.
                if name.endswith(".sqlite3"):
                    target = Path(temporary) / (
                        hashlib.sha256(name.encode()).hexdigest() + ".db"
                    )
                    exclusive(target, b"")
                    with (
                        closing(
                            sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
                        ) as source,
                        closing(sqlite3.connect(target)) as out,
                    ):
                        source.backup(out)
                        if out.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                            raise ValueError("Database integrity failure")
                    data = target.read_bytes()
                else:
                    data = read_private(path, MAX_BACKUP)
                total += len(data)
                if total > MAX_BACKUP:
                    raise ValueError(
                        "Recovery archive exceeds 256 MiB; archive history first"
                    )
                manifest[name] = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o600
                tar.addfile(member, io.BytesIO(data))
            data = canonical(manifest)
            member = tarfile.TarInfo("manifest.json")
            member.size = len(data)
            member.mode = 0o600
            tar.addfile(member, io.BytesIO(data))
    nonce = secrets.token_bytes(12)
    encrypted = (
        PREFIX
        + nonce
        + AESGCM(derive(key, "backup")).encrypt(nonce, archive.getvalue(), PREFIX)
    )
    exclusive(destination, encrypted)
    return {"sha256": hashlib.sha256(encrypted).hexdigest(), "files": manifest}


def restore(archive: Path | str, key: bytes, destination: Path) -> dict[str, Any]:
    raw = read_private(archive, MAX_BACKUP + 1024 * 1024)
    if not raw.startswith(PREFIX):
        raise ValueError("Invalid recovery archive")
    start = len(PREFIX)
    decoded = AESGCM(derive(key, "backup")).decrypt(
        raw[start : start + 12], raw[start + 12 :], PREFIX
    )
    contents = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:gz") as tar:
        for member in tar:
            if (
                member.name not in SOURCES | {"manifest.json"}
                or member.name in contents
                or not member.isfile()
                or member.size < 0
            ):
                raise ValueError("Invalid recovery member")
            total += member.size
            if total > MAX_BACKUP + 65536:
                raise ValueError("Recovery expansion exceeds limit")
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError("Missing archive member data")
            contents[member.name] = stream.read(member.size + 1)
    if set(contents) != SOURCES | {"manifest.json"}:
        raise ValueError("Incomplete recovery archive")
    manifest = json.loads(contents.pop("manifest.json"))
    if set(manifest) != SOURCES:
        raise ValueError("Invalid recovery manifest")
    for name, data in contents.items():
        if manifest[name] != {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }:
            raise ValueError("Recovery integrity mismatch")
    destination = Path(destination)
    destination.mkdir(
        mode=0o700, parents=False, exist_ok=False
    )  # Restore never overwrites live state.
    for name, data in contents.items():
        path = destination / name
        path.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
        exclusive(path, data)
        if name.endswith(".sqlite3"):
            with closing(sqlite3.connect(path)) as db:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Restored database invalid")
    return {"restored": sorted(contents), "destination": str(destination)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    generate = commands.add_parser("generate-release-key")
    generate.add_argument("--out", type=Path, required=True)
    publish = commands.add_parser("publish-release")
    for option in [
        "binary",
        "signing-key",
        "catalog",
        "component",
        "platform",
        "version",
        "origin",
    ]:
        publish.add_argument("--" + option, required=True)
    save = commands.add_parser("backup")
    for option in ["root", "credentials", "key", "out"]:
        save.add_argument("--" + option, required=True)
    recover = commands.add_parser("restore")
    for option in ["archive", "key", "out"]:
        recover.add_argument("--" + option, required=True)
    args = parser.parse_args()
    if args.action == "generate-release-key":
        raw = secrets.token_bytes(32)
        exclusive(args.out, raw)
        value = {
            "public_key": base64.b64encode(
                Ed25519PrivateKey.from_private_bytes(raw)
                .public_key()
                .public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode()
        }
    elif args.action == "publish-release":
        value = publish_release(
            args.binary,
            args.signing_key,
            args.catalog,
            args.component,
            args.platform,
            args.version,
            args.origin,
        )
    else:
        key = bytes.fromhex(read_private(args.key, 64).decode().strip())
        if len(key) != 16:
            raise ValueError("Existing remote gateway master key required")
        value = (
            backup(args.root, args.credentials, key, args.out)
            if args.action == "backup"
            else restore(args.archive, key, args.out)
        )
    print(json.dumps(value, indent=2))


if __name__ == "__main__":
    main()
