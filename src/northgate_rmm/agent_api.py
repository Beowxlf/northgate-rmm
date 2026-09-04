"""Bounded in-process HTTP contract for post-enrollment agent messages.

This module does not open a socket or terminate TLS. A separately qualified
listener must validate the client certificate chain and construct the verified
certificate value before calling this boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from northgate_rmm.codec import MAX_ENCODED_MESSAGE_BYTES, decode_message
from northgate_rmm.domain import (
    EndpointIdentity,
    HeartbeatMessage,
    InventoryMessage,
)
from northgate_rmm.errors import AuthorizationError, ReplayError, ValidationError

AGENT_MESSAGE_PATH = "/v1/agent/messages"


@dataclass(frozen=True, slots=True)
class VerifiedClientCertificate:
    """Identity facts extracted from an already TLS-verified certificate."""

    endpoint_id: UUID
    public_key_fingerprint: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.public_key_fingerprint) is None:
            raise ValidationError("client certificate fingerprint is invalid")


@dataclass(frozen=True, slots=True)
class AgentMessageRequest:
    method: str
    path: str
    content_type: str | None
    content_encoding: str | None
    body: bytes


@dataclass(frozen=True, slots=True)
class AgentMessageResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class AgentMessageStore(Protocol):
    def authenticate_endpoint_certificate(
        self,
        *,
        endpoint_id: UUID,
        public_key_fingerprint: str,
        authenticated_at: datetime,
        correlation_id: UUID,
    ) -> EndpointIdentity: ...

    def ingest_heartbeat(
        self,
        *,
        authenticated_identity_id: UUID,
        message: HeartbeatMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> object: ...

    def ingest_inventory(
        self,
        *,
        authenticated_identity_id: UUID,
        message: InventoryMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> object: ...


class AgentMessageApplication:
    """Translate the narrow agent HTTP contract into control-plane calls."""

    def __init__(self, store: AgentMessageStore) -> None:
        self._store = store

    def handle(
        self,
        request: AgentMessageRequest,
        *,
        peer: VerifiedClientCertificate,
        received_at: datetime,
    ) -> AgentMessageResponse:
        if request.path != AGENT_MESSAGE_PATH:
            return _error_response(404, "not_found")
        if request.method != "POST":
            return _error_response(405, "method_not_allowed", allow="POST")
        if (
            request.content_type is None
            or request.content_type.lower() != "application/json"
        ):
            return _error_response(415, "unsupported_media_type")
        if request.content_encoding is not None:
            return _error_response(415, "content_encoding_not_allowed")
        if len(request.body) > MAX_ENCODED_MESSAGE_BYTES:
            return _error_response(413, "request_too_large")

        try:
            message = decode_message(request.body)
            encoded_digest = hashlib.sha256(request.body).hexdigest()
            identity = self._store.authenticate_endpoint_certificate(
                endpoint_id=peer.endpoint_id,
                public_key_fingerprint=peer.public_key_fingerprint,
                authenticated_at=received_at,
                correlation_id=message.envelope.correlation_id,
            )
            if isinstance(message, HeartbeatMessage):
                self._store.ingest_heartbeat(
                    authenticated_identity_id=identity.identity_id,
                    message=message,
                    received_at=received_at,
                    encoded_message_digest=encoded_digest,
                )
            else:
                self._store.ingest_inventory(
                    authenticated_identity_id=identity.identity_id,
                    message=message,
                    received_at=received_at,
                    encoded_message_digest=encoded_digest,
                )
        except AuthorizationError:
            return _error_response(403, "unauthorized")
        except ReplayError:
            return _error_response(409, "message_conflict")
        except ValidationError:
            return _error_response(400, "invalid_message")

        return _json_response(
            200,
            {
                "message_id": str(message.envelope.message_id),
                "accepted": True,
            },
        )


def _error_response(
    status: int,
    code: str,
    *,
    allow: str | None = None,
) -> AgentMessageResponse:
    response = _json_response(status, {"error": code})
    if allow is None:
        return response
    return AgentMessageResponse(
        status=response.status,
        headers=(*response.headers, ("allow", allow)),
        body=response.body,
    )


def _json_response(status: int, value: dict[str, object]) -> AgentMessageResponse:
    return AgentMessageResponse(
        status=status,
        headers=(
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ),
        body=json.dumps(value, separators=(",", ":")).encode("ascii"),
    )
