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
    assert "../../deploy/systemd/northgate-rmm-${unit_service}.service" in build
    assert "curl " not in build
    assert "wget " not in build
    assert "pip install" not in build
    assert "#!/usr/bin/python3 -I" in launcher
    assert "/usr/lib/northgate-rmm-server/site-packages" in launcher
    assert (
        ROOT / "deploy" / "systemd" / "northgate-rmm-agent-ingress.service"
    ).is_file()
    assert not (ROOT / "deploy" / "systemd" / "northgate-rmm-agent.service").exists()


def test_server_package_lifecycle_is_disabled_and_receipt_gated() -> None:
    preinst = (PACKAGING / "debian" / "preinst").read_text(encoding="utf-8")
    postinst = (PACKAGING / "debian" / "postinst").read_text(encoding="utf-8")
    prerm = (PACKAGING / "debian" / "prerm").read_text(encoding="utf-8")
    postrm = (PACKAGING / "debian" / "postrm").read_text(encoding="utf-8")

    for identity in ("agent", "enrollment", "operator"):
        assert identity in postinst
    assert "refusing package installation" in preinst
    assert "prior purge evidence remains unarchived" in preinst
    assert "symlinked server path" in preinst
    assert "systemctl disable" in postinst
    assert ".server-identities-revoked" in prerm
    assert ".server-evidence-exported" in prerm
    assert ".server-purge-approved" in postrm
    assert "northgate-rmm-server-purge-v1:authorized" in postrm
    assert "symlinked configuration path" in postrm
    assert "rm -rf -- /var/lib/northgate-rmm-server /etc/northgate-rmm" not in postrm


def test_server_package_is_qualified_with_the_endpoint_package_installed() -> None:
    workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text(
        encoding="utf-8"
    )
    package_test = (PACKAGING / "debian" / "test-package.sh").read_text(
        encoding="utf-8"
    )

    assert "/agent-packages/northgate-rmm-agent_0.2.0_amd64.deb" in workflow
    assert 'dpkg -i "$agent_package"' in package_test
    assert "dpkg-query -W" in package_test
    assert "retained endpoint agent configuration" in package_test
