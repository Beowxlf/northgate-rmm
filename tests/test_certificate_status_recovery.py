"""Publication survives abandoned writes without damaging signed assertions."""

from __future__ import annotations

import base64
import json
import os
import signal
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from northgate_rmm import certificate_status

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX publisher")


def fixture(tmp_path: Path) -> tuple[Path, Path, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "key.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"a" * 64: "good"}))
    registry.chmod(0o600)
    destination = tmp_path / "public"
    destination.mkdir()
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "registry": str(registry),
                "private_key": str(private),
                "output_directory": str(destination),
            }
        )
    )
    config.chmod(0o600)
    return config, destination, key


def test_abandoned_temporary_files_do_not_block_publication(tmp_path: Path) -> None:
    config, destination, key = fixture(tmp_path)
    leftovers = [
        destination / ("a" * 64 + suffix)
        for suffix in (".pending", ".interrupted.pending")
    ]
    for path in leftovers:
        path.write_bytes(b"interrupted")
    for _ in range(2):
        assert certificate_status.main(["--config", str(config)]) == 0
    result = destination / ("a" * 64 + ".json")
    record = json.loads(result.read_text())
    payload = base64.b64decode(record["payload"])
    key.public_key().verify(base64.b64decode(record["signature"]), payload)
    assert json.loads(payload)["status"] == "good"
    assert stat.S_IMODE(result.stat().st_mode) == 0o644
    assert set(destination.glob("*.pending")) == set(leftovers)
    assert all(path.read_bytes() == b"interrupted" for path in leftovers)


@pytest.mark.parametrize("operation", ["replace", "fsync"])
def test_io_failure_preserves_previous_assertion_and_allows_retry(
    tmp_path: Path,
    operation: str,
) -> None:
    config, destination, _ = fixture(tmp_path)
    assert certificate_status.main(["--config", str(config)]) == 0
    result = destination / ("a" * 64 + ".json")
    before = result.read_bytes()
    with patch.object(certificate_status.os, operation, side_effect=OSError("fault")):
        assert certificate_status.main(["--config", str(config)]) == 1
    assert result.read_bytes() == before
    assert list(destination.glob("*.pending")) == []
    assert certificate_status.main(["--config", str(config)]) == 0


def test_killed_writer_does_not_block_next_run(tmp_path: Path) -> None:
    config, destination, _ = fixture(tmp_path)
    assert certificate_status.main(["--config", str(config)]) == 0
    result = destination / ("a" * 64 + ".json")
    before = result.read_bytes()
    child = """
import importlib.util, os, signal, sys
spec = importlib.util.spec_from_file_location('candidate', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def interrupt(*args):
    os.kill(os.getpid(), signal.SIGKILL)
module.os.replace = interrupt
module.main(['--config', sys.argv[2]])
"""
    completed = subprocess.run(  # noqa: S603 - fixed test code and owned fixture paths
        [sys.executable, "-c", child, certificate_status.__file__, str(config)],
        check=False,
        timeout=20,
        capture_output=True,
    )
    assert completed.returncode == -signal.SIGKILL
    assert result.read_bytes() == before
    abandoned = set(destination.glob("*.pending"))
    assert len(abandoned) == 1
    assert certificate_status.main(["--config", str(config)]) == 0
    assert set(destination.glob("*.pending")) == abandoned
