"""Unprivileged synthetic endpoint simulator for Windows and Linux fixtures."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from northgate_rmm.domain import (
    Endpoint,
    EndpointIdentity,
    HeartbeatMessage,
    HeartbeatPayload,
    InventoryMessage,
    InventoryPayload,
    MessageEnvelope,
    Platform,
)


class EnrollmentControlPlane(Protocol):
    """Small interface needed by the unprivileged synthetic fixture."""

    def enroll_synthetic_endpoint(
        self,
        *,
        display_name: str,
        platform: Platform,
        architecture: str,
        public_key_fingerprint: str,
        now: datetime,
        actor_id: str = "phase1-simulator",
    ) -> tuple[Endpoint, EndpointIdentity]: ...


@dataclass(slots=True)
class SyntheticAgent:
    """Creates protocol fixtures without reading or changing the host OS."""

    endpoint_id: UUID
    identity_id: UUID
    platform: Platform
    architecture: str
    agent_version: str = "0.1.0-sim"
    boot_id: UUID = field(default_factory=uuid4)
    _sequence: int = 0

    @classmethod
    def enroll(
        cls,
        control_plane: EnrollmentControlPlane,
        *,
        display_name: str,
        platform: Platform,
        architecture: str,
        now: datetime,
    ) -> SyntheticAgent:
        """Enroll a random synthetic fingerprint, never an actual host key."""

        seed = uuid4().bytes
        fingerprint = f"sha256:{hashlib.sha256(seed).hexdigest()}"
        endpoint, identity = control_plane.enroll_synthetic_endpoint(
            display_name=display_name,
            platform=platform,
            architecture=architecture,
            public_key_fingerprint=fingerprint,
            now=now,
        )
        return cls(
            endpoint_id=endpoint.endpoint_id,
            identity_id=identity.identity_id,
            platform=platform,
            architecture=architecture,
        )

    def heartbeat(
        self,
        *,
        now: datetime,
        ttl: timedelta = timedelta(seconds=30),
        capabilities: tuple[str, ...] = ("inventory.v1",),
    ) -> HeartbeatMessage:
        return HeartbeatMessage(
            envelope=self._envelope(now=now, ttl=ttl),
            payload=HeartbeatPayload(
                agent_version=self.agent_version,
                capabilities=capabilities,
            ),
        )

    def inventory(
        self,
        *,
        now: datetime,
        fields: Mapping[str, str],
        collector_complete: bool = True,
        ttl: timedelta = timedelta(minutes=2),
    ) -> InventoryMessage:
        return InventoryMessage(
            envelope=self._envelope(now=now, ttl=ttl),
            payload=InventoryPayload(
                platform=self.platform,
                architecture=self.architecture,
                fields=tuple(sorted(fields.items())),
                collector_complete=collector_complete,
            ),
        )

    def restart(self) -> None:
        """Start a new synthetic boot sequence."""

        self.boot_id = uuid4()
        self._sequence = 0

    def _envelope(self, *, now: datetime, ttl: timedelta) -> MessageEnvelope:
        self._sequence += 1
        return MessageEnvelope(
            message_id=uuid4(),
            endpoint_id=self.endpoint_id,
            boot_id=self.boot_id,
            sequence=self._sequence,
            created_at=now,
            expires_at=now + ttl,
            correlation_id=uuid4(),
        )
