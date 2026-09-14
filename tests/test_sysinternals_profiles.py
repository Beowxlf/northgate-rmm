import json
from pathlib import Path

import pytest

from northgate_rmm.management_protocol import validate_action

CASES = json.loads(
    (
        Path(__file__).parents[1] / "agent/management/testdata/sysinternals-paths.json"
    ).read_text(encoding="utf-8")
)


def run(profile, inputs, platform="windows"):
    validate_action(
        "tool.run",
        {
            "tool_id": "sysinternals",
            "profile": profile,
            "inputs": inputs,
            "case_id": "",
        },
        platform,
    )


@pytest.mark.parametrize("path", CASES["valid"])
def test_trust_accepts_one_explicit_local_file(path):
    run("trust", {"path": path})


@pytest.mark.parametrize("path", CASES["invalid"] + ["C:\\" + "x" * 1025, 1, None])
def test_trust_rejects_unsafe_or_untyped_paths(path):
    with pytest.raises(ValueError):
        run("trust", {"path": path})


@pytest.mark.parametrize("profile", ["startup", "trust"])
def test_empty_inputs_remain_compatible(profile):
    run(profile, {})


@pytest.mark.parametrize("profile", ["startup", "trust"])
@pytest.mark.parametrize(
    "inputs", [{"flags": "-a *"}, {"path": r"C:\Ops\app.exe", "flags": "-v"}]
)
def test_extra_switches_cannot_be_supplied(profile, inputs):
    with pytest.raises(ValueError):
        run(profile, inputs)


def test_explicit_path_is_trust_only_and_windows_only():
    with pytest.raises(ValueError):
        run("startup", {"path": r"C:\Ops\app.exe"})
    with pytest.raises(ValueError):
        run("trust", {"path": r"C:\Ops\app.exe"}, "linux")
