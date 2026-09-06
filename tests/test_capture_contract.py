"""Source-level contract checks prepared for the subsequent bug-review phase."""

import base64
import json
from types import SimpleNamespace
from uuid import uuid4
import pytest
from northgate_rmm.capture_ui import CaptureUI, validate_job
from northgate_rmm.capture_store import CaptureStore


def test_capture_signature_binds_action_and_identity(tmp_path):
    gateway = SimpleNamespace(key=b"synthetic-key-16", origin="https://operator.test")
    ui = CaptureUI(gateway, CaptureStore(tmp_path / "capture"))
    target = SimpleNamespace(endpoint_id=uuid4(), identity_id=uuid4())
    principal = SimpleNamespace(subject="owner", session_id="session")
    envelope = ui.envelope(target, principal, "stop", uuid4())
    payload = base64.b64decode(envelope["payload"])
    ui.key.public_key().verify(
        base64.b64decode(envelope["signature"]), b"NorthGate-Wxlfgar-v1\0" + payload
    )
    claims = json.loads(payload)
    assert claims["endpoint_id"] == str(target.endpoint_id)
    assert claims["identity_id"] == str(target.identity_id)
    assert claims["expires"] - claims["issued"] == 45
    assert claims["action"] == "stop"


def test_capture_history_is_bound_to_enrollment(tmp_path):
    store = CaptureStore(tmp_path / "capture")
    endpoint, identity, job_id = uuid4(), uuid4(), uuid4()
    principal = SimpleNamespace(subject="owner", session_id="session")
    job = {
        "id": str(job_id),
        "endpoint_id": str(endpoint),
        "identity_id": str(identity),
        "state": "capturing",
    }
    store.add(endpoint, identity, principal, job)
    assert store.get(endpoint, identity, "owner", str(job_id))
    assert store.get(endpoint, uuid4(), "owner", str(job_id)) is None
    assert store.get(endpoint, identity, "other", str(job_id)) is None
    with pytest.raises(ValueError):
        validate_job(job, job_id, endpoint, uuid4())
