from pathlib import Path

import pytest

from northgate_rmm import admin


def test_database_exception_does_not_disclose_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(_path: Path) -> str:
        raise ValueError("postgresql://sensitive-user:sensitive-value@localhost/db")

    monkeypatch.setattr(admin, "load_database_dsn", fail)
    assert admin.main(["--dsn-file", "/private/dsn", "check-schema"]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "sensitive" not in output.err
    assert "reconcile" in output.err


def test_invalid_command_never_reads_database_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(_path: Path) -> str:
        pytest.fail("invalid command opened database credentials")

    monkeypatch.setattr(admin, "load_database_dsn", forbidden)
    with pytest.raises(SystemExit):
        admin.main(["--dsn-file", "/private/dsn", "execute-command"])
