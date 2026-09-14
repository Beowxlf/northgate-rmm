#!/usr/bin/python3
"""Install a reviewed worker on an already enrolled Debian/Ubuntu endpoint."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ["binary", "manifest", "configuration", "server-roots"]:
        p.add_argument("--" + key, required=True, type=Path)
    a = p.parse_args()
    if os.geteuid() != 0:
        raise ValueError("Root installation is required")
    config = json.loads(a.configuration.read_text())
    release = json.loads(a.manifest.read_text())
    root = Path("/var/lib/northgate-rmm-management")
    config_dir = Path("/etc/northgate-rmm-management")
    binary = Path(
        "/usr/local/libexec/northgate-rmm-management/northgate-rmm-management"
    )
    service = Path("/etc/systemd/system/northgate-rmm-management.service")
    for path in [root, config_dir, binary.parent, service]:
        if path.exists() or path.is_symlink():
            raise ValueError(
                "Existing management installation requires reconciliation or signed update"
            )
    if (config["state_directory"], config["identity_file"], config["server_roots"]) != (
        str(root),
        "/var/lib/northgate-rmm/identity/identity.json",
        str(config_dir / "server-ca.pem"),
    ):
        raise ValueError("Dedicated installation paths required")
    identity = json.loads(Path(config["identity_file"]).read_text())
    from uuid import UUID

    UUID(config["identity_id"])
    if config["endpoint_id"] != identity["endpoint_id"]:
        raise ValueError("Enrollment binding mismatch")
    data = a.binary.read_bytes()
    manifest = release["manifest"]
    if (
        len(data) > 64 * 1024 * 1024
        or manifest["sha256"] != hashlib.sha256(data).hexdigest()
        or manifest["platform"] != "linux"
        or manifest["component"] != "worker"
    ):
        raise ValueError("Candidate integrity mismatch")
    key = base64.b64decode(config["update_key"], validate=True)
    if len(key) != 32:
        raise ValueError("Invalid update key")
    with tempfile.TemporaryDirectory(prefix="northgate-verify-") as temp:
        d = Path(temp)
        (d / "key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
        (d / "signature").write_bytes(
            base64.b64decode(release["signature"], validate=True)
        )
        (d / "message").write_bytes(
            b"NorthGate-Release-v1\0"
            + json.dumps(manifest, separators=(",", ":"), ensure_ascii=True).encode()
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(d / "key.der"),
                "-keyform",
                "DER",
                "-rawin",
                "-in",
                str(d / "message"),
                "-sigfile",
                str(d / "signature"),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    for dependency in ["/usr/bin/python3", "/usr/bin/systemctl", "/bin/bash"]:
        if not Path(dependency).exists():
            raise ValueError("Missing management prerequisite: " + dependency)
    for path in [root, config_dir, binary.parent]:
        path.mkdir(parents=True, mode=0o700)
    binary.write_bytes(data)
    binary.chmod(0o700)
    (config_dir / "config.json").write_text(json.dumps(config))
    (config_dir / "config.json").chmod(0o600)
    shutil.copyfile(a.server_roots, config_dir / "server-ca.pem")
    (config_dir / "server-ca.pem").chmod(0o600)
    service.write_text("""[Unit]
Description=NorthGate RMM privileged management worker
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5
[Service]
Type=exec
User=root
Group=root
ExecStart=/usr/local/libexec/northgate-rmm-management/northgate-rmm-management --config /etc/northgate-rmm-management/config.json
WorkingDirectory=/var/lib/northgate-rmm-management
Restart=on-failure
RestartSec=30
TimeoutStopSec=30
UMask=0077
KillMode=control-group
LimitNOFILE=2048
TasksMax=256
StandardOutput=null
StandardError=journal
[Install]
WantedBy=multi-user.target
""")
    service.chmod(0o644)
    subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
    subprocess.run(
        ["/usr/bin/systemctl", "enable", "--now", "northgate-rmm-management.service"],
        check=True,
    )
    subprocess.run(
        [
            "/usr/bin/systemctl",
            "is-active",
            "--quiet",
            "northgate-rmm-management.service",
        ],
        check=True,
    )
    print(
        "Root worker installed. Verify authenticated readiness in RMM before executing jobs."
    )


if __name__ == "__main__":
    main()
