"""Exercise the actual snapshot producer with fake transport and encryption only."""

import hashlib
import io
import json
import os
import pathlib
import runpy
import ssl
import subprocess
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).parents[1] / "deploy/openbao/snapshot.py"


@pytest.mark.parametrize("read_failure", [False, True])
def test_ciphertext_digest_streams_and_read_errors_do_not_publish_receipts(
    tmp_path, monkeypatch, capsys, read_failure
):
    # Synthetic bytes and fake encryption exercise production file/receipt logic,
    # not OpenBao access, age encryption correctness, or any real credential.
    raw = b"synthetic snapshot content\n" * 131072
    prefix = b"synthetic encrypted stream\n"
    expected_sha = hashlib.sha256(prefix + raw).hexdigest()
    read_sizes = []
    path_type = type(tmp_path)
    actual_open = path_type.open

    def mapped_path(value):
        return tmp_path / str(value).lstrip("/")

    for name, text in (
        ("/etc/northgate-rmm/secrets/openbao-backup.token", "synthetic-token"),
        ("/etc/openbao/recovery-recipient.txt", "synthetic-recipient"),
    ):
        target = mapped_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    mapped_path("/var/lib/openbao-maintenance").mkdir(parents=True)

    class BoundedCiphertextReader:
        def __init__(self, stream):
            self.stream = stream

        def readable(self):
            return True

        def readinto(self, buffer):
            read_sizes.append(len(buffer))
            assert 0 < len(buffer) <= 1024 * 1024
            if read_failure:
                raise OSError("synthetic ciphertext read failure")
            return self.stream.readinto(buffer)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.stream.close()

    def tracked_open(path, mode="r", *args, **kwargs):
        stream = actual_open(path, mode, *args, **kwargs)
        if path.name.endswith(".snap.age") and mode == "rb":
            return BoundedCiphertextReader(stream)
        return stream

    def disallow_whole_file_read(_):
        raise AssertionError("Snapshot hashing must not load whole ciphertext")

    class FakeAgeProcess:
        def __init__(self, command, *, stdin, stdout, stderr):
            assert command == ["age", "-r", "synthetic-recipient"]
            stdout.write(prefix)
            self.stdin = SimpleNamespace(write=stdout.write, close=lambda: None)

        def wait(self, timeout):
            assert timeout == 30
            return 0

        def poll(self):
            return 0

    def fake_urlopen(request, *, context, timeout):
        assert request.full_url.endswith("/v1/sys/storage/raft/snapshot")
        assert timeout == 30
        return io.BytesIO(raw)

    monkeypatch.setattr(pathlib, "Path", mapped_path)
    monkeypatch.setattr(path_type, "open", tracked_open)
    monkeypatch.setattr(path_type, "read_bytes", disallow_whole_file_read)
    monkeypatch.setattr(os, "umask", lambda _: None)
    monkeypatch.setattr(ssl, "create_default_context", lambda **_: object())
    monkeypatch.setattr(subprocess, "Popen", FakeAgeProcess)
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    if read_failure:
        with pytest.raises(OSError, match="synthetic ciphertext read failure"):
            runpy.run_path(str(SOURCE))
        assert not list(tmp_path.rglob("*.receipt.json"))
        assert not list(tmp_path.rglob("*.details.json"))
        assert capsys.readouterr().out == ""
        assert read_sizes
        return

    runpy.run_path(str(SOURCE))
    stdout = capsys.readouterr().out
    details = json.loads(stdout)
    assert details["sha256"] == expected_sha
    assert details["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert details["raw_size"] == len(raw)
    assert details["encrypted_size"] == len(prefix) + len(raw)
    assert "synthetic-token" not in stdout
    assert len(read_sizes) > 2
    receipt = json.loads(next(tmp_path.rglob("*.receipt.json")).read_text())
    assert set(receipt) == {"snapshot_id", "sha256", "created_at"}
    assert all(receipt[key] == details[key] for key in receipt)
