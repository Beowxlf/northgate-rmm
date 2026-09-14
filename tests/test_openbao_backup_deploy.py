"""Bounded, offline checks of the optional deployment bundle contract."""

import hashlib
import importlib.util
import io
import tarfile
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[1] / "deploy/openbao/install-operations-backup-link.py"
SPEC = importlib.util.spec_from_file_location("openbao_backup_installer", SOURCE)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def bundle(tmp_path, items):
    target = tmp_path / "reviewed.tgz"
    with tarfile.open(target, "w:gz") as archive:
        for name, data, kind in items:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return target, hashlib.sha256(target.read_bytes()).hexdigest()


def valid_items():
    return [
        (name, b"reviewed deployment asset\n", tarfile.REGTYPE)
        for name in installer.MEMBERS
    ]


def test_exact_reviewed_bundle_reads_without_extracting_paths(tmp_path):
    path, sha = bundle(tmp_path, valid_items())
    assert set(installer.read_bundle(path, sha)) == installer.MEMBERS
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize(
    "kind", ["hash", "missing", "duplicate", "traversal", "symlink", "oversized"]
)
def test_unreviewed_or_unsafe_bundle_is_rejected(tmp_path, kind):
    items = valid_items()
    if kind == "missing":
        items.pop()
    elif kind == "duplicate":
        items.append(items[0])
    elif kind == "traversal":
        items.append(("../unexpected", b"x", tarfile.REGTYPE))
    elif kind == "symlink":
        items[0] = (items[0][0], b"", tarfile.SYMTYPE)
    elif kind == "oversized":
        items[0] = (items[0][0], b"x" * 65536, tarfile.REGTYPE)
    path, sha = bundle(tmp_path, items)
    with pytest.raises(RuntimeError):
        installer.read_bundle(path, "0" * 64 if kind == "hash" else sha)


def test_installed_dropin_matches_reviewed_asset():
    assert (
        SOURCE.parent / "20-vault-snapshot.conf"
    ).read_bytes() == installer.DROPIN_BYTES
