"""Contract tests for the standalone Python 3.10 Wazuh integration."""

import copy
import importlib.machinery
import importlib.util
import json
import os
import re
import ssl
from pathlib import Path
from uuid import uuid4

import pytest

SOURCE = Path(__file__).parents[1] / "deploy/wazuh/custom-northgate-rmm"
LOADER = importlib.machinery.SourceFileLoader("wazuh_forwarder", str(SOURCE))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
forwarder = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(forwarder)


@pytest.fixture
def config(tmp_path):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    token = root / "bearer"
    token.write_text("A" * 48)
    token.chmod(0o600)
    ca = root / "ca.pem"
    ca.write_text("test CA")
    ca.chmod(0o600)
    return {
        "schema": 1,
        "url": "https://operator.rmm.internal/remote/ops/intake/wazuh",
        "connect_address": "10.10.150.22",
        "token_file": str(token.resolve()),
        "ca_file": str(ca.resolve()),
        "queue_file": str(root / "queue.sqlite3"),
        "minimum_level": 3,
        "detections": {"550": {"context_fields": []}},
        "agents": {"020": {"endpoint": str(uuid4()), "identity": str(uuid4())}},
    }


@pytest.fixture
def alert():
    return {
        "id": "1788987654.321",
        "timestamp": "2026-09-10T11:34:14.123+0000",
        "agent": {"id": "020", "name": "CANARY", "ip": "10.10.150.99"},
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck"],
        },
        "full_log": "password=do-not-forward",
        "data": {"private_key": "do-not-forward"},
        "syscheck": {"path": "/sensitive/file"},
    }


def test_strict_metadata_contract_and_redaction(config, alert):
    alert["rule"]["description"] = "Changed password=super-secret\x00\nfield"
    result = forwarder.normalize(alert, config)
    assert set(result) == {"id", "timestamp", "agent", "rule"}
    assert result["agent"] == {"id": "020"}
    assert result["timestamp"] == "2026-09-10T11:34:14.123000+00:00"
    assert result["rule"]["description"] == "Changed [redacted] field"
    assert "secret" not in json.dumps(result)
    assert "full_log" not in json.dumps(result)


def test_unmapped_qualifying_alert_is_queued_and_below_filter_is_skipped(config, alert):
    alert["agent"]["id"] = "000"
    assert forwarder.enqueue(alert, config) == "queued"
    alert["agent"]["id"] = "020"
    alert["id"] = "below-filter"
    alert["rule"]["level"] = 2
    assert forwarder.enqueue(alert, config) == "filtered"


def test_only_allowlisted_context_is_forwarded(config, alert):
    config["detections"]["550"]["context_fields"] = ["syscheck.path"]
    result = forwarder.normalize(alert, config)
    assert result["context"] == {"syscheck.path": "/sensitive/file"}
    assert "full_log" not in json.dumps(result)


@pytest.mark.parametrize(
    "offset,expected",
    [("+0000", "+00:00"), ("-0530", "-05:30"), ("+05:30", "+05:30"), ("Z", "+00:00")],
)
def test_wazuh_timestamp_is_compatible_with_python310(
    config, alert, monkeypatch, offset, expected
):
    actual_datetime = forwarder.datetime

    class Python310ISOParser:
        @staticmethod
        def fromisoformat(value):
            # Preserve Python 3.10's parser restriction when tests run with a
            # newer interpreter that otherwise masks this live incompatibility.
            if re.search(r"[+-]\d{4}$", value):
                raise ValueError("Python 3.10 requires a colon in the UTC offset")
            return actual_datetime.fromisoformat(value)

    monkeypatch.setattr(forwarder, "datetime", Python310ISOParser)
    alert["timestamp"] = "2026-09-10T15:48:50.695" + offset
    assert forwarder.normalize(alert, config)["timestamp"] == (
        "2026-09-10T15:48:50.695000" + expected
    )


@pytest.mark.parametrize(
    "stamp", ["2026-09-10T15:48:50.695", "not-a-timestamp", "2026-09-10T15:48:50+9999"]
)
def test_malformed_or_naive_wazuh_timestamp_is_rejected(config, alert, stamp):
    alert["timestamp"] = stamp
    with pytest.raises((ValueError, forwarder.IntakeError)):
        forwarder.normalize(alert, config)


@pytest.mark.parametrize(
    "field,value", [("level", True), ("level", 17), ("groups", ["x"] * 33)]
)
def test_reject_bad_rule(config, alert, field, value):
    alert["rule"][field] = value
    with pytest.raises(forwarder.IntakeError):
        forwarder.normalize(alert, config)


def test_queue_deduplicates_and_persists_retry(config, alert):
    assert forwarder.enqueue(alert, config) == "queued"
    assert forwarder.enqueue(alert, config) == "duplicate"
    result = forwarder.flush(config, lambda *_: 503)
    assert result == {"sent": 0, "rejected": 0, "deferred": 1}
    assert forwarder.status(config)["pending"] == 1
    assert (
        forwarder.flush(config, lambda *_: pytest.fail("backoff ignored"))["sent"] == 0
    )
    with forwarder.queue(config["queue_file"]) as db:
        db.execute("UPDATE queue SET next_try=0")
        db.commit()
    captured = []

    def receipt(payload, _):
        captured.append(json.loads(payload))
        return 202

    assert forwarder.flush(config, receipt)["sent"] == 1
    assert forwarder.status(config)["pending"] == 0
    assert captured == [forwarder.normalize(alert, config)]


def test_queue_conflict_and_hard_capacity(config, alert, monkeypatch):
    forwarder.enqueue(alert, config)
    changed = copy.deepcopy(alert)
    changed["rule"]["level"] = 8
    with pytest.raises(forwarder.IntakeError, match="source_identifier_conflict"):
        forwarder.enqueue(changed, config)
    monkeypatch.setattr(forwarder, "MAX_QUEUE", 1)
    changed["id"] = "another"
    with pytest.raises(forwarder.IntakeError, match="queue_full"):
        forwarder.enqueue(changed, config)


@pytest.mark.parametrize("code", [400, 409, 413, 422])
def test_rejection_retained_without_retry_loop(config, alert, code):
    forwarder.enqueue(alert, config)
    assert forwarder.flush(config, lambda *_: code)["rejected"] == 1
    assert forwarder.status(config)["rejected"] == 1
    assert (
        forwarder.flush(config, lambda *_: pytest.fail("must remain rejected"))["sent"]
        == 0
    )


def test_local_reenrollment_never_reassigns_queued_old_alert(config, alert):
    forwarder.enqueue(alert, config)
    config["agents"]["020"]["identity"] = str(uuid4())
    result = forwarder.flush(config, lambda *_: pytest.fail("old enrollment was sent"))
    assert result["rejected"] == 1


def test_configuration_rejects_unsafe_destination(config, tmp_path):
    path = tmp_path / "config.json"
    for url in [
        "http://operator.rmm.internal/remote/ops/intake/wazuh",
        "https://user:pass@operator.rmm.internal/remote/ops/intake/wazuh",
        "https://operator.rmm.internal/somewhere-else",
        "https://operator.rmm.internal/remote/ops/intake/wazuh?key=abc",
    ]:
        config["url"] = url
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        with pytest.raises(forwarder.IntakeError, match="invalid_destination"):
            forwarder.load_config(path)


def test_https_bearer_ca_fixed_address_and_receipt_validation(
    config, alert, monkeypatch
):
    requests = []
    tls = ssl.create_default_context()
    monkeypatch.setattr(forwarder.ssl, "create_default_context", lambda **_: tls)

    class Connection:
        status = 202
        body = json.dumps({"alert": str(uuid4()), "duplicate": False}).encode()

        def __init__(self, host, address, context):
            assert host == "operator.rmm.internal"
            assert address == "10.10.150.22"
            assert context.check_hostname

        def request(self, method, path, payload, headers):
            requests.append((method, path, payload, headers))

        def getresponse(self):
            return self

        def read(self, maximum):
            return self.body[:maximum]

        def close(self):
            pass

    monkeypatch.setattr(forwarder, "PinnedHTTPS", Connection)
    payload = forwarder.encode(forwarder.normalize(alert, config))
    assert forwarder.send(payload, config) == 202
    assert requests[0][3]["Authorization"] == "Bearer " + "A" * 48
    assert "Origin" not in requests[0][3]
    Connection.body = b'{"ok":true}'
    assert forwarder.send(payload, config) == 502
    Connection.status = 302
    assert forwarder.send(payload, config) == 302
    assert len(requests) == 3  # No redirect request.


def test_invalid_input_never_logs_raw_data(config, tmp_path, capsys):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    bad = tmp_path / "event.json"
    bad.write_text('{"full_log":"sensitive-value"')
    assert forwarder.main([str(bad), "--config", str(config_path)]) == 1
    text = capsys.readouterr()
    assert "sensitive-value" not in text.err
    assert text.out == ""


@pytest.mark.skipif(os.name != "posix", reason="Linux deployment permissions")
def test_queue_rejects_symlink_or_public_directory(config, tmp_path):
    directory = Path(config["queue_file"]).parent
    directory.chmod(0o755)
    with pytest.raises(forwarder.IntakeError, match="unsafe_queue_directory"):
        forwarder.status(config)
    directory.chmod(0o700)
    target = tmp_path / "target"
    target.write_text("do not overwrite")
    Path(config["queue_file"]).symlink_to(target)
    with pytest.raises(OSError):
        forwarder.status(config)
    assert target.read_text() == "do not overwrite"
