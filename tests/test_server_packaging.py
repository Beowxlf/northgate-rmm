from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
PACKAGING = ROOT / "server" / "packaging"


def test_server_runtime_wheels_are_exactly_hash_pinned() -> None:
    requirements = (ROOT / "server" / "requirements-runtime.txt").read_text(
        encoding="utf-8"
    )
    manifest = (PACKAGING / "runtime-wheels.sha256").read_text(encoding="utf-8")

    requirement_hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", requirements)
    manifest_hashes = re.findall(r"^([0-9a-f]{64})  \S+$", manifest, re.MULTILINE)
    assert len(requirement_hashes) == 15
    assert sorted(requirement_hashes) == sorted(manifest_hashes)
    assert "git+" not in requirements
    assert "http://" not in requirements


def test_server_package_build_is_offline_and_uses_reference_units() -> None:
    build = (PACKAGING / "build-deb.sh").read_text(encoding="utf-8")
    launcher = (PACKAGING / "launcher.py").read_text(encoding="utf-8")

    assert "runtime-wheels.sha256" in build
    assert "sha256sum --check --strict" in build
    assert "../../deploy/systemd/northgate-rmm-${service}.service" in build
    assert "curl " not in build
    assert "wget " not in build
    assert "pip install" not in build
    assert "#!/usr/bin/python3 -I" in launcher
    assert "/usr/lib/northgate-rmm-server/site-packages" in launcher


def test_server_package_lifecycle_is_disabled_and_receipt_gated() -> None:
    preinst = (PACKAGING / "debian" / "preinst").read_text(encoding="utf-8")
    postinst = (PACKAGING / "debian" / "postinst").read_text(encoding="utf-8")
    prerm = (PACKAGING / "debian" / "prerm").read_text(encoding="utf-8")
    postrm = (PACKAGING / "debian" / "postrm").read_text(encoding="utf-8")

    for identity in ("agent", "enrollment", "operator"):
        assert identity in postinst
    assert "refusing package installation" in preinst
    assert "prior purge evidence remains unarchived" in preinst
    assert "systemctl disable" in postinst
    assert ".server-identities-revoked" in prerm
    assert ".evidence-exported" in prerm
    assert ".purge-approved" in postrm
    assert "northgate-rmm-server-purge-v1:authorized" in postrm
