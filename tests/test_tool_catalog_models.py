import base64
import copy

import pytest

from northgate_rmm.management_protocol import validate_action
from northgate_rmm.tool_catalog_models import manifest_bytes, validate_manifest


def manifest():
    return {
        "schema": 1,
        "id": "osquery",
        "revision": 1,
        "version": "5.19.0",
        "platform": "linux",
        "arch": "amd64",
        "sha256": "a" * 64,
        "size": 1024,
        "entrypoint": "osqueryi",
        "license": "Apache-2.0",
        "source": "https://osquery.io/",
        "privilege": "system",
        "budget": {
            "seconds": 30,
            "memory_mib": 128,
            "cpu_percent": 10,
            "output_kib": 64,
            "disk_mib": 64,
        },
    }


def test_valid_signed_contract_and_malformed_metadata():
    value = manifest()
    validate_manifest(value)
    validate_action(
        "tool.install",
        {
            "manifest": base64.b64encode(manifest_bytes(value)).decode(),
            "signature": base64.b64encode(bytes(64)).decode(),
        },
        "linux",
    )
    for field, changed in (
        ("entrypoint", "/bin/bash"),
        ("sha256", "invalid"),
        ("revision", 0),
        ("schema", True),
        ("id", {}),
        ("arch", {}),
        ("platform", "plan9"),
        ("privilege", "user"),
        ("arch", "any"),
        ("source", "http://bad"),
    ):
        bad = dict(value, **{field: changed})
        with pytest.raises(ValueError):
            validate_manifest(bad)
    bad = copy.deepcopy(value)
    bad["budget"]["memory_mib"] = 65536
    with pytest.raises(ValueError):
        validate_manifest(bad)


@pytest.mark.parametrize(
    "tool,profile,inputs",
    [
        ("osquery", "arbitrary", {}),
        ("osquery", "system", {"query": "select * from file"}),
        ("connectivity", "tcp", {"host": "example.com", "port": "443"}),
        ("nmap", "connect", {"host": "10.0.0.1", "ports": "1-65535"}),
        ("yara-x", "scan", {"path": "-whatever"}),
    ],
)
def test_untyped_or_unbounded_invocation_rejected(tool, profile, inputs):
    with pytest.raises(ValueError):
        validate_action(
            "tool.run",
            {"tool_id": tool, "profile": profile, "inputs": inputs, "case_id": ""},
            "linux",
        )


def test_chunks_and_platforms():
    validate_action(
        "tool.artifact.read",
        {
            "artifact_id": "33333333-3333-4333-8333-333333333333",
            "offset": 0,
            "size": 262144,
            "case_id": "",
        },
        "windows",
    )
    with pytest.raises(ValueError):
        validate_action(
            "tool.artifact.read",
            {
                "artifact_id": "33333333-3333-4333-8333-333333333333",
                "offset": 0,
                "size": 262145,
                "case_id": "",
            },
            "windows",
        )
    with pytest.raises(ValueError):
        validate_action("tool.verify", {"tool_id": "sysinternals"}, "linux")
    with pytest.raises(ValueError):
        validate_action("tool.remove", {"tool_id": "health"}, "windows")


@pytest.mark.parametrize("case", [None, 1, True, {}, []])
def test_case_context_has_a_strict_type(case):
    with pytest.raises(ValueError):
        validate_action(
            "tool.run",
            {"tool_id": "health", "profile": "snapshot", "inputs": {}, "case_id": case},
            "linux",
        )
