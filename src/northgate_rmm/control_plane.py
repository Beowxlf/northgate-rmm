"""In-memory Phase 1 control-plane domain service.

This module intentionally has no network listener, operating-system collector,
job scheduler, command execution, or persistence adapter.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import Never
from uuid import UUID, uuid4

from northgate_rmm.domain import (
    MAX_CLOCK_SKEW,
    AuditEvent,
    Endpoint,
    EndpointHealth,
    EndpointIdentity,
    EndpointLifecycle,
    EndpointStatus,
    FreshnessPolicy,
    HeartbeatMessage,
    InventoryMessage,
    Observation,
    Platform,
    require_aware,
)
from northgate_rmm.errors import (
    AuthorizationError,
    NotFoundError,
    ReplayError,
    ValidationError,
)


class ControlPlane:
    """A fail-closed, synthetic-only RMM domain boundary."""

    def __init__(self) -> None:
        self._endpoints: dict[UUID, Endpoint] = {}
        self._identities: dict[UUID, EndpointIdentity] = {}
        self._fingerprints: dict[str, UUID] = {}
        self._observations: list[Observation] = []
        self._audit_events: list[AuditEvent] = []
        self._seen_message_ids: set[UUID] = set()
        self._last_sequences: dict[tuple[UUID, UUID], int] = {}

    @property
    def observations(self) -> tuple[Observation, ...]:
        """Return immutable observation history."""

        return tuple(self._observations)

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        """Return immutable audit history."""

        return tuple(self._audit_events)

    def list_endpoints(self) -> tuple[Endpoint, ...]:
        return tuple(
            sorted(self._endpoints.values(), key=lambda item: str(item.endpoint_id))
        )

    def get_endpoint(self, endpoint_id: UUID) -> Endpoint:
        try:
            return self._endpoints[endpoint_id]
        except KeyError as exc:
            raise NotFoundError("endpoint does not exist") from exc

    def get_identity(self, identity_id: UUID) -> EndpointIdentity:
        try:
            return self._identities[identity_id]
        except KeyError as exc:
            raise NotFoundError("identity does not exist") from exc

    def record_operator_access(
        self,
        *,
        actor_id: str,
        subject: str,
        action: str,
        decision: str,
        reason: str,
        correlation_id: UUID,
        now: datetime,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> None:
        """Append a synthetic operator read or denial decision."""

        require_aware(now, "now")
        if not actor_id or len(actor_id) > 512:
            raise ValidationError("operator audit actor is invalid")
        if not subject or len(subject) > 512:
            raise ValidationError("operator audit subject is invalid")
        if not action or len(action) > 128:
            raise ValidationError("operator audit action is invalid")
        if decision not in {"accepted", "rejected"}:
            raise ValidationError("operator audit decision is invalid")
        if not reason or len(reason) > 512:
            raise ValidationError("operator audit reason is invalid")
        if len(metadata) > 8 or any(
            not key or len(key) > 64 or len(value) > 512 for key, value in metadata
        ):
            raise ValidationError("operator audit metadata is invalid")
        self._audit(
            server_time=now,
            actor_type="human_operator",
            actor_id=actor_id,
            subject=subject,
            action=action,
            decision=decision,
            reason=reason,
            correlation_id=correlation_id,
            metadata=metadata,
        )

    def enroll_synthetic_endpoint(
        self,
        *,
        display_name: str,
        platform: Platform,
        architecture: str,
        public_key_fingerprint: str,
        now: datetime,
        actor_id: str = "phase1-simulator",
    ) -> tuple[Endpoint, EndpointIdentity]:
        """Create an endpoint and one synthetic identity atomically."""

        require_aware(now, "now")
        if public_key_fingerprint in self._fingerprints:
            raise ValidationError("fingerprint is already enrolled")

        endpoint_id = uuid4()
        identity_id = uuid4()
        identity = EndpointIdentity(
            identity_id=identity_id,
            endpoint_id=endpoint_id,
            public_key_fingerprint=public_key_fingerprint,
            created_at=now,
        )
        endpoint = Endpoint(
            endpoint_id=endpoint_id,
            display_name=display_name,
            platform=platform,
            architecture=architecture,
            identity_id=identity_id,
            enrolled_at=now,
        )
        self._identities[identity_id] = identity
        self._endpoints[endpoint_id] = endpoint
        self._fingerprints[public_key_fingerprint] = identity_id
        self._audit(
            server_time=now,
            actor_type="operator",
            actor_id=actor_id,
            subject=f"endpoint:{endpoint_id}",
            action="endpoint.enroll",
            decision="accepted",
            reason="synthetic Phase 1 enrollment",
            correlation_id=uuid4(),
            metadata=(("identity_id", str(identity_id)),),
        )
        return endpoint, identity

    def ingest_heartbeat(
        self,
        *,
        authenticated_identity_id: UUID,
        message: HeartbeatMessage,
        received_at: datetime,
    ) -> Observation:
        """Accept a heartbeat only after identity, expiry, and replay checks."""

        identity = self._authorize_message(
            authenticated_identity_id=authenticated_identity_id,
            endpoint_id=message.envelope.endpoint_id,
            message_id=message.envelope.message_id,
            boot_id=message.envelope.boot_id,
            sequence=message.envelope.sequence,
            created_at=message.envelope.created_at,
            expires_at=message.envelope.expires_at,
            correlation_id=message.envelope.correlation_id,
            received_at=received_at,
            action="heartbeat.ingest",
        )
        observation = Observation(
            observation_id=uuid4(),
            endpoint_id=identity.endpoint_id,
            message_id=message.envelope.message_id,
            observation_type="heartbeat",
            schema_version=1,
            source_time=message.envelope.created_at,
            received_at=received_at,
            boot_id=message.envelope.boot_id,
            sequence=message.envelope.sequence,
            payload_digest=message.payload.digest(),
        )
        self._accept_message(
            authenticated_identity_id, message.envelope.boot_id, observation
        )
        endpoint = self.get_endpoint(identity.endpoint_id)
        self._endpoints[endpoint.endpoint_id] = replace(
            endpoint,
            last_receipt_at=max(
                received_at,
                endpoint.last_receipt_at or received_at,
            ),
            last_heartbeat_at=max(
                received_at,
                endpoint.last_heartbeat_at or received_at,
            ),
        )
        self._audit_acceptance(
            identity=identity,
            observation=observation,
            correlation_id=message.envelope.correlation_id,
        )
        return observation

    def ingest_inventory(
        self,
        *,
        authenticated_identity_id: UUID,
        message: InventoryMessage,
        received_at: datetime,
    ) -> Observation:
        """Accept independent, versioned synthetic inventory."""

        identity = self._authorize_message(
            authenticated_identity_id=authenticated_identity_id,
            endpoint_id=message.envelope.endpoint_id,
            message_id=message.envelope.message_id,
            boot_id=message.envelope.boot_id,
            sequence=message.envelope.sequence,
            created_at=message.envelope.created_at,
            expires_at=message.envelope.expires_at,
            correlation_id=message.envelope.correlation_id,
            received_at=received_at,
            action="inventory.ingest",
        )
        endpoint = self.get_endpoint(identity.endpoint_id)
        if (
            message.payload.platform is not endpoint.platform
            or message.payload.architecture != endpoint.architecture
        ):
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=identity.endpoint_id,
                action="inventory.ingest",
                reason="inventory binding does not match enrolled endpoint",
                correlation_id=message.envelope.correlation_id,
                received_at=received_at,
                error_type=ValidationError,
            )
        observation = Observation(
            observation_id=uuid4(),
            endpoint_id=identity.endpoint_id,
            message_id=message.envelope.message_id,
            observation_type="inventory",
            schema_version=message.payload.schema_version,
            source_time=message.envelope.created_at,
            received_at=received_at,
            boot_id=message.envelope.boot_id,
            sequence=message.envelope.sequence,
            payload_digest=message.payload.digest(),
        )
        self._accept_message(
            authenticated_identity_id, message.envelope.boot_id, observation
        )
        self._endpoints[endpoint.endpoint_id] = replace(
            endpoint,
            last_receipt_at=max(
                received_at,
                endpoint.last_receipt_at or received_at,
            ),
        )
        self._audit_acceptance(
            identity=identity,
            observation=observation,
            correlation_id=message.envelope.correlation_id,
        )
        return observation

    def endpoint_status(
        self,
        endpoint_id: UUID,
        *,
        now: datetime,
        policy: FreshnessPolicy | None = None,
    ) -> EndpointStatus:
        """Derive status from server receipt time; do not trust endpoint clocks."""

        require_aware(now, "now")
        endpoint = self.get_endpoint(endpoint_id)
        identity = self.get_identity(endpoint.identity_id)
        freshness = policy or FreshnessPolicy()
        last = endpoint.last_heartbeat_at
        if last is None:
            health = EndpointHealth.OFFLINE
        else:
            age = max(now - last, timedelta(0))
            if age <= freshness.online_for:
                health = EndpointHealth.ONLINE
            elif age <= freshness.stale_for:
                health = EndpointHealth.STALE
            else:
                health = EndpointHealth.OFFLINE
        return EndpointStatus(
            endpoint_id=endpoint_id,
            lifecycle=identity.lifecycle,
            health=health,
            last_heartbeat_at=last,
        )

    def revoke_identity(
        self,
        identity_id: UUID,
        *,
        reason: str,
        actor_id: str,
        now: datetime,
        correlation_id: UUID | None = None,
    ) -> EndpointIdentity:
        """Revoke immediately and preserve an idempotent audit record."""

        require_aware(now, "now")
        if not reason or len(reason) > 256:
            raise ValidationError("revocation reason is empty or too long")
        identity = self.get_identity(identity_id)
        event_correlation_id = correlation_id or uuid4()
        if identity.revoked_at is not None:
            self._audit(
                server_time=now,
                actor_type="operator",
                actor_id=actor_id,
                subject=f"identity:{identity_id}",
                action="identity.revoke",
                decision="no_change",
                reason="identity already revoked",
                correlation_id=event_correlation_id,
            )
            return identity
        revoked = replace(
            identity,
            status=EndpointLifecycle.REVOKED,
            revoked_at=now,
            revocation_reason=reason,
        )
        self._identities[identity_id] = revoked
        self._audit(
            server_time=now,
            actor_type="operator",
            actor_id=actor_id,
            subject=f"identity:{identity_id}",
            action="identity.revoke",
            decision="accepted",
            reason=reason,
            correlation_id=event_correlation_id,
        )
        return revoked

    def _authorize_message(
        self,
        *,
        authenticated_identity_id: UUID,
        endpoint_id: UUID,
        message_id: UUID,
        boot_id: UUID,
        sequence: int,
        created_at: datetime,
        expires_at: datetime,
        correlation_id: UUID,
        received_at: datetime,
        action: str,
    ) -> EndpointIdentity:
        require_aware(received_at, "received_at")
        identity = self._identities.get(authenticated_identity_id)
        if identity is None:
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=endpoint_id,
                action=action,
                reason="unknown authenticated identity",
                correlation_id=correlation_id,
                received_at=received_at,
                error_type=AuthorizationError,
            )
        if identity.revoked_at is not None:
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=identity.endpoint_id,
                action=action,
                reason="authenticated identity is revoked",
                correlation_id=correlation_id,
                received_at=received_at,
                error_type=AuthorizationError,
            )
        if endpoint_id != identity.endpoint_id:
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=endpoint_id,
                action=action,
                reason="message endpoint does not match transport identity",
                correlation_id=correlation_id,
                received_at=received_at,
                error_type=AuthorizationError,
            )
        if created_at > received_at + MAX_CLOCK_SKEW:
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=identity.endpoint_id,
                action=action,
                reason="message creation time exceeds allowed clock skew",
                correlation_id=correlation_id,
                received_at=received_at,
                error_type=ValidationError,
            )
        if received_at >= expires_at:
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=identity.endpoint_id,
                action=action,
                reason="message expired before receipt",
                correlation_id=correlation_id,
                received_at=received_at,
                error_type=ValidationError,
            )
        if message_id in self._seen_message_ids:
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=identity.endpoint_id,
                action=action,
                reason="message ID replayed",
                correlation_id=correlation_id,
                received_at=received_at,
                error_type=ReplayError,
            )
        previous = self._last_sequences.get((authenticated_identity_id, boot_id), 0)
        if sequence <= previous:
            self._reject(
                identity_id=authenticated_identity_id,
                endpoint_id=identity.endpoint_id,
                action=action,
                reason="boot sequence replayed or out of order",
                correlation_id=correlation_id,
                received_at=received_at,
                error_type=ReplayError,
            )
        return identity

    def _accept_message(
        self,
        identity_id: UUID,
        boot_id: UUID,
        observation: Observation,
    ) -> None:
        self._seen_message_ids.add(observation.message_id)
        self._last_sequences[(identity_id, boot_id)] = observation.sequence
        self._observations.append(observation)

    def _audit_acceptance(
        self,
        *,
        identity: EndpointIdentity,
        observation: Observation,
        correlation_id: UUID,
    ) -> None:
        self._audit(
            server_time=observation.received_at,
            actor_type="endpoint_identity",
            actor_id=str(identity.identity_id),
            subject=f"endpoint:{identity.endpoint_id}",
            action=f"{observation.observation_type}.ingest",
            decision="accepted",
            reason="message contract and authorization checks passed",
            correlation_id=correlation_id,
            metadata=(
                ("message_id", str(observation.message_id)),
                ("payload_digest", observation.payload_digest),
                ("sequence", str(observation.sequence)),
            ),
        )

    def _reject(
        self,
        *,
        identity_id: UUID,
        endpoint_id: UUID,
        action: str,
        reason: str,
        correlation_id: UUID,
        received_at: datetime,
        error_type: type[ValidationError | AuthorizationError | ReplayError],
    ) -> Never:
        self._audit(
            server_time=received_at,
            actor_type="endpoint_identity",
            actor_id=str(identity_id),
            subject=f"endpoint:{endpoint_id}",
            action=action,
            decision="rejected",
            reason=reason,
            correlation_id=correlation_id,
        )
        raise error_type(reason)

    def _audit(
        self,
        *,
        server_time: datetime,
        actor_type: str,
        actor_id: str,
        subject: str,
        action: str,
        decision: str,
        reason: str,
        correlation_id: UUID,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self._audit_events.append(
            AuditEvent(
                event_id=uuid4(),
                server_time=server_time,
                actor_type=actor_type,
                actor_id=actor_id,
                subject=subject,
                action=action,
                decision=decision,
                reason=reason,
                correlation_id=correlation_id,
                metadata=tuple(sorted(metadata)),
            )
        )
