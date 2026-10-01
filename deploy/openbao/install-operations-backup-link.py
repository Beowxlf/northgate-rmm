"""Install the optional vault prerequisite from an explicitly reviewed bundle.

Linux / Python 3.11+. Installs configuration only; never starts a backup, enables
a timer, reads a vault token or changes the RMM application identity's policy.
"""

import argparse
import hashlib
import io
import json
import os
import re
import socket
import stat
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

CONFIG = Path("/etc/northgate-rmm/operations-backup.json")
SCRIPT = Path("/usr/local/lib/northgate-rmm-openbao/operations-snapshot.py")
UNIT = Path("/etc/systemd/system/northgate-rmm-openbao-snapshot.service")
BACKUP_UNIT = Path("/etc/systemd/system/northgate-rmm-operations-backup.service")
DROPIN = Path(str(BACKUP_UNIT) + ".d/20-vault-snapshot.conf")
LINK = "/etc/northgate-rmm/operations-openbao-snapshot.json"
MEMBERS = {
    "operations-snapshot-prerequisite.py",
    "northgate-rmm-openbao-snapshot.service",
}
DROPIN_BYTES = (
    b"[Unit]\nRequires=northgate-rmm-openbao-snapshot.service\n"
    b"After=northgate-rmm-openbao-snapshot.service\n"
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        require(
            stat.S_ISREG(info.st_mode) and info.st_size <= limit,
            "Invalid bounded regular file",
        )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, "File exceeded its bound")
        return data, info
    finally:
        os.close(descriptor)


def read_bundle(path, expected):
    raw, _ = regular_bytes(path, 256 * 1024)
    require(digest(raw) == expected, "Reviewed bundle hash mismatch")
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            require(
                member.name in MEMBERS
                and member.name not in result
                and member.isfile()
                and 0 < member.size < 65536,
                "Unexpected bundle member",
            )
            with archive.extractfile(member) as stream:
                data = stream.read(65536)
            require(len(data) == member.size, "Incomplete bundle member")
            result[member.name] = data
    require(set(result) == MEMBERS, "Required bundle member missing")
    return result


def write_new(path, content, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(mode)
    except BaseException:
        path.unlink()
        raise


def install(args):
    require(os.geteuid() == 0, "Run the reviewed installer as root")
    require(socket.gethostname() == args.expected_host, "Wrong installation target")
    for value in (args.bundle_sha256, args.expected_config_sha256):
        require(re.fullmatch(r"[0-9a-f]{64}", value), "A reviewed SHA-256 is required")
    members = read_bundle(args.bundle, args.bundle_sha256)
    original, metadata = regular_bytes(CONFIG, 65536)
    require(
        digest(original) == args.expected_config_sha256,
        "Backup configuration changed since review",
    )
    configuration = json.loads(original)
    require(isinstance(configuration, dict), "Backup configuration must be an object")
    require(
        not configuration.get("openbao_snapshot_receipt"),
        "Snapshot prerequisite already configured",
    )
    require(
        subprocess.run(
            [
                "/usr/bin/systemctl",
                "is-active",
                "--quiet",
                "northgate-rmm-operations-backup.timer",
            ],
            timeout=15,
        ).returncode
        != 0,
        "Pause the backup timer before installing",
    )
    enabled = subprocess.run(
        ["/usr/bin/systemctl", "is-enabled", "northgate-rmm-operations-backup.timer"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    require(
        enabled.stdout.strip() == "disabled",
        "Backup timer must be disabled during qualification",
    )
    require(
        not any(path.exists() or path.is_symlink() for path in (SCRIPT, UNIT, DROPIN)),
        "Prerequisite paths already exist",
    )
    for directory in (SCRIPT.parent, UNIT.parent, CONFIG.parent):
        require(
            directory.is_dir() and not directory.is_symlink(),
            "Provision the fixed deployment directories first",
        )
        info = directory.stat()
        require(
            info.st_uid == 0 and not info.st_mode & 0o022,
            "Deployment directories must be root-controlled",
        )
    require(
        Path("/usr/local/lib/northgate-rmm-openbao/snapshot.py").is_file(),
        "Provision the independent encrypted snapshot helper first",
    )
    backup = Path("/var/backups/northgate-rmm") / (
        "operations-backup-link-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )
    backup.mkdir(mode=0o700)
    write_new(backup / CONFIG.name, original, 0o600)
    DROPIN.parent.mkdir(mode=0o755, exist_ok=True)
    require(
        not DROPIN.parent.is_symlink()
        and DROPIN.parent.stat().st_uid == 0
        and not DROPIN.parent.stat().st_mode & 0o022,
        "Drop-in directory must be root-controlled",
    )
    created = []
    temporary = None
    config_replaced = False
    try:
        for path, content in (
            (SCRIPT, members["operations-snapshot-prerequisite.py"]),
            (UNIT, members["northgate-rmm-openbao-snapshot.service"]),
            (DROPIN, DROPIN_BYTES),
        ):
            write_new(path, content, 0o644)
            created.append(path)
        configuration["openbao_snapshot_receipt"] = LINK
        descriptor, name = tempfile.mkstemp(
            prefix=".operations-backup-link-", dir=CONFIG.parent
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(configuration, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
        temporary.chmod(0o600)
        # Refuse a concurrent configuration change even after preflight.
        require(
            digest(regular_bytes(CONFIG, 65536)[0]) == args.expected_config_sha256,
            "Backup configuration changed during installation",
        )
        os.replace(temporary, CONFIG)
        config_replaced = True
        subprocess.run(  # noqa: S603 - fixed installed unit paths, no caller-supplied arguments
            ["/usr/bin/systemd-analyze", "verify", str(UNIT), str(BACKUP_UNIT)],
            check=True,
            timeout=30,
        )
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True, timeout=30)
    except BaseException:
        if config_replaced:
            descriptor, name = tempfile.mkstemp(
                prefix=".operations-backup-rollback-", dir=CONFIG.parent
            )
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(original)
                stream.flush()
                os.fsync(stream.fileno())
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
            temporary.chmod(metadata.st_mode & 0o777)
            os.replace(temporary, CONFIG)
        for path in reversed(created):
            path.unlink()
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], timeout=30, check=False)
        raise
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    receipt = {
        "installed": True,
        "config_sha256": digest(regular_bytes(CONFIG, 65536)[0]),
        "rollback": str(backup),
        "daily_timer_enabled": False,
        "snapshot_identity": "dedicated OpenBao backup identity",
        "operations_identity": "northgate-rmm-operator",
        "bundle_sha256": args.bundle_sha256,
    }
    write_new(
        backup / "installation.json",
        (json.dumps(receipt, indent=2) + "\n").encode(),
        0o600,
    )
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    print(json.dumps(install(parser.parse_args())))


if __name__ == "__main__":
    main()
