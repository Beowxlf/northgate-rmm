from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import NoReturn
from uuid import UUID, uuid4

import pytest

from northgate_rmm.agent_api import (
    AgentMessageApplication,
    AgentMessageRequest,
    VerifiedClientCertificate,
)
from northgate_rmm.domain import EndpointIdentity, HeartbeatMessage, InventoryMessage
from northgate_rmm.errors import AuthorizationError, ReplayError, ValidationError

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def message_body(
    endpoint_id: UUID,
    message_id: UUID | None = None,
    *,
    message_type: str = "inventory",
) -> bytes:
    payload: dict[str, object]
    if message_type == "heartbeat":
        payload = {
            "agent_version": "0.2.0",
            "capabilities": ["inventory.v1"],
        }
    else:
        payload = {
            "platform": "linux",
            "architecture": "amd64",
            "fields": {"os.id": "debian"},
            "collector_complete": True,
            "schema_version": 1,
        }
    return json.dumps(
        {
            "type": message_type,
            "envelope": {
                "message_id": str(message_id or uuid4()),
                "endpoint_id": str(endpoint_id),
                "boot_id": str(uuid4()),
                "sequence": 1,
                "created_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
                "correlation_id": str(uuid4()),
                "protocol_version": 1,
            },
            "payload": payload,
        },
        separators=(",", ":"),
    ).encode()


@dataclass
class FakeStore:
    endpoint_id: UUID
    identity_id: UUID = field(default_factory=uuid4)
    authenticated: int = 0
    heartbeats: list[tuple[HeartbeatMessage, str | None]] = field(default_factory=list)
    inventories: list[tuple[InventoryMessage, str | None]] = field(default_factory=list)

    def authenticate_endpoint_certificate(
        self,
        *,
        endpoint_id: UUID,
        public_key_fingerprint: str,
        authenticated_at: datetime,
        correlation_id: UUID,
    ) -> EndpointIdentity:
        del public_key_fingerprint, authenticated_at, correlation_id
        if endpoint_id != self.endpoint_id:
            raise AuthorizationError("synthetic rejection")
        self.authenticated += 1
        return EndpointIdentity(
            identity_id=self.identity_id,
            endpoint_id=self.endpoint_id,
            public_key_fingerprint="sha256:" + "a" * 64,
            created_at=NOW,
        )

    def ingest_heartbeat(
        self,
        *,
        authenticated_identity_id: UUID,
        message: HeartbeatMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> object:
        del received_at
        assert authenticated_identity_id == self.identity_id
        self.heartbeats.append((message, encoded_message_digest))
        return object()

    def ingest_inventory(
        self,
        *,
        authenticated_identity_id: UUID,
        message: InventoryMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> object:
        del received_at
        assert authenticated_identity_id == self.identity_id
        self.inventories.append((message, encoded_message_digest))
        return object()


def request(default_body: bytes, **changes: object) -> AgentMessageRequest:
    values: dict[str, object] = {
        "method": "POST",
        "path": "/v1/agent/messages",
        "content_type": "application/json",
        "content_encoding": None,
        "body": default_body,
    }
    values.update(changes)
    return AgentMessageRequest(**values)  # type: ignore[arg-type]


def test_agent_message_boundary_returns_exact_acknowledgement() -> None:
    endpoint_id = uuid4()
    message_id = uuid4()
    store = FakeStore(endpoint_id)
    app = AgentMessageApplication(store)
    response = app.handle(
        request(message_body(endpoint_id, message_id)),
        peer=VerifiedClientCertificate(endpoint_id, "sha256:" + "a" * 64),
        received_at=NOW,
    )

    assert response.status == 200
    assert json.loads(response.body) == {
        "message_id": str(message_id),
        "accepted": True,
    }
    assert response.headers == (
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
    )
    assert store.authenticated == 1
    assert len(store.inventories) == 1
    assert len(store.inventories[0][1] or "") == 64


def test_agent_message_boundary_routes_heartbeat() -> None:
    endpoint_id = uuid4()
    message_id = uuid4()
    store = FakeStore(endpoint_id)
    response = AgentMessageApplication(store).handle(
        request(message_body(endpoint_id, message_id, message_type="heartbeat")),
        peer=VerifiedClientCertificate(endpoint_id, "sha256:" + "a" * 64),
        received_at=NOW,
    )

    assert response.status == 200
    assert json.loads(response.body)["message_id"] == str(message_id)
    assert len(store.heartbeats) == 1
    assert store.inventories == []


@pytest.mark.parametrize(
    ("changes", "status"),
    [
        ({"path": "/unknown"}, 404),
        ({"method": "GET"}, 405),
        ({"content_type": "text/plain"}, 415),
        ({"content_encoding": "gzip"}, 415),
        ({"body": b"x" * 65_537}, 413),
    ],
)
def test_agent_message_boundary_rejects_http_contract_failures(
    changes: dict[str, object],
    status: int,
) -> None:
    endpoint_id = uuid4()
    store = FakeStore(endpoint_id)
    response = AgentMessageApplication(store).handle(
        request(message_body(endpoint_id), **changes),
        peer=VerifiedClientCertificate(endpoint_id, "sha256:" + "a" * 64),
        received_at=NOW,
    )

    assert response.status == status
    assert store.authenticated == 0
    assert store.inventories == []


def test_agent_message_boundary_maps_failures_without_detail_leakage() -> None:
    endpoint_id = uuid4()
    store = FakeStore(endpoint_id)
    app = AgentMessageApplication(store)
    peer = VerifiedClientCertificate(endpoint_id, "sha256:" + "a" * 64)

    malformed = app.handle(request(b"not-json"), peer=peer, received_at=NOW)
    unauthorized = app.handle(
        request(message_body(endpoint_id)),
        peer=VerifiedClientCertificate(uuid4(), "sha256:" + "a" * 64),
        received_at=NOW,
    )

    assert (malformed.status, malformed.body) == (400, b'{"error":"invalid_message"}')
    assert (unauthorized.status, unauthorized.body) == (
        403,
        b'{"error":"unauthorized"}',
    )
    assert store.authenticated == 0


def test_agent_message_boundary_maps_replay_conflict() -> None:
    class ReplayStore(FakeStore):
        def ingest_inventory(
            self,
            *,
            authenticated_identity_id: UUID,
            message: InventoryMessage,
            received_at: datetime,
            encoded_message_digest: str | None = None,
        ) -> NoReturn:
            del (
                authenticated_identity_id,
                message,
                received_at,
                encoded_message_digest,
            )
            raise ReplayError("sensitive conflict detail")

    endpoint_id = uuid4()
    response = AgentMessageApplication(ReplayStore(endpoint_id)).handle(
        request(message_body(endpoint_id)),
        peer=VerifiedClientCertificate(endpoint_id, "sha256:" + "a" * 64),
        received_at=NOW,
    )
    assert (response.status, response.body) == (
        409,
        b'{"error":"message_conflict"}',
    )


def test_verified_client_certificate_rejects_invalid_fingerprint() -> None:
    with pytest.raises(ValidationError, match="fingerprint"):
        VerifiedClientCertificate(uuid4(), "not-a-fingerprint")
