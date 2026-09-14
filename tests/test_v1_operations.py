from __future__ import annotations

from pathlib import Path

import pytest

from northgate_rmm.errors import ValidationError
from northgate_rmm.recovery import environment, executable
from northgate_rmm.workload_service import canonical, strict_object


@pytest.mark.parametrize("payload", [b'{"a":1,"a":2}', b'{"a":NaN}', b"[]", b""])
def test_workload_rejects_ambiguous_or_nonobject_json(payload: bytes) -> None:
    with pytest.raises(ValidationError):
        strict_object(payload)


def test_canonical_wire_bytes_do_not_depend_on_dictionary_order() -> None:
    assert canonical({"b": 2, "a": 1}) == canonical({"a": 1, "b": 2})


def test_recovery_does_not_inherit_ambient_database_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PGHOST", "untrusted.invalid")
    monkeypatch.setenv("PGSERVICE", "untrusted")
    result = environment("host=127.0.0.1 dbname=northgate_restore_test user=recovery")
    assert result["PGHOST"] == "127.0.0.1"
    assert "PGSERVICE" not in result
    assert result["PGCONNECT_TIMEOUT"] == "5"


def test_recovery_requires_absolute_installed_tool(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        executable("pg_dump")
    with pytest.raises(ValidationError):
        executable(str(tmp_path / "absent"))
