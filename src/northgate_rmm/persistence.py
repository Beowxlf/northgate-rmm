"""PostgreSQL persistence for the synthetic and V1B control-plane slices.

The adapter intentionally exposes only enrollment, heartbeat, inventory,
revocation, audit, and read-model operations. It contains no job or command
execution primitive and opens no network listener.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from psycopg import Connection, Cursor, connect
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row

from northgate_rmm.domain import (
    MAX_CLOCK_SKEW,
    MAX_ENROLLMENT_GRANT_TTL,
    AuditEvent,
    Endpoint,
    EndpointHealth,
    EndpointIdentity,
    EndpointStatus,
    EnrollmentGrant,
    FreshnessPolicy,
    HeartbeatMessage,
    InventoryMessage,
    MessageEnvelope,
    Observation,
    Platform,
    require_aware,
)
from northgate_rmm.errors import (
    AuthorizationError,
    NorthGateRmmError,
    NotFoundError,
    ReplayError,
    ValidationError,
)

Row = dict[str, Any]
Failure = tuple[type[NorthGateRmmError], str]
MIGRATION_LOCK_ID = 7_104_771_001
GRANT_NAMESPACE = "ngr1_"
ENROLLMENT_TOKEN_PATTERN = re.compile(r"ngr1_[A-Za-z0-9_-]{43}\Z")
ENROLLMENT_REJECTION = "enrollment grant is invalid or unavailable"


def _default_migration_directory() -> Path:
    return Path(__file__).with_name("migrations")


def apply_migrations(dsn: str, directory: Path | None = None) -> tuple[str, ...]:
    """Apply immutable SQL migrations under a PostgreSQL advisory lock."""

    migration_directory = directory or _default_migration_directory()
    migrations = tuple(sorted(migration_directory.glob("[0-9][0-9][0-9][0-9]_*.sql")))
    if not migrations:
        raise ValidationError("no database migrations were found")

    applied_now: list[str] = []
    with (
        connect(dsn, row_factory=dict_row) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK_ID,))
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version varchar(255) PRIMARY KEY,
                sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
                applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
            )
            """
        )
        cursor.execute("SELECT version, sha256 FROM schema_migrations")
        applied = {
            cast(str, row["version"]): cast(str, row["sha256"])
            for row in cursor.fetchall()
        }
        discovered = {migration.name for migration in migrations}
        missing = sorted(set(applied) - discovered)
        if missing:
            raise ValidationError(
                f"applied migrations are missing from source: {missing}"
            )
        if applied:
            applied_head = max(applied)
            out_of_order = sorted(
                migration.name
                for migration in migrations
                if migration.name not in applied and migration.name < applied_head
            )
            if out_of_order:
                raise ValidationError(
                    "unapplied migrations precede the applied migration head "
                    f"{applied_head}: {out_of_order}"
                )
        for migration in migrations:
            script = migration.read_text(encoding="utf-8")
            checksum = hashlib.sha256(script.encode("utf-8")).hexdigest()
            previous = applied.get(migration.name)
            if previous is not None:
                if previous != checksum:
                    raise ValidationError(
                        f"applied migration checksum changed: {migration.name}"
                    )
                continue
            cursor.execute(script, prepare=False)
            cursor.execute(
                "INSERT INTO schema_migrations (version, sha256) VALUES (%s, %s)",
                (migration.name, checksum),
            )
            applied_now.append(migration.name)
    return tuple(applied_now)


class PostgresControlPlane:
    """Transactional, restart-safe Phase 1 control-plane boundary."""

    def __init__(self, dsn: str) -> None:
        if not dsn:
            raise ValidationError("PostgreSQL DSN is required")
        self._dsn = dsn

    def _connect(self) -> Connection[Row]:
        return connect(self._dsn, row_factory=dict_row)

    @property
    def observations(self) -> tuple[Observation, ...]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT observation_id, endpoint_id, message_id, observation_type,
                       schema_version, source_time, received_at, boot_id, sequence,
                       payload_digest, encoded_message_digest
                FROM observations
                ORDER BY received_at, observation_id
                """
            )
            return tuple(self._observation_from_row(row) for row in cursor.fetchall())

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT event_id, server_time, actor_type, actor_id, subject, action,
                       decision, reason, correlation_id, metadata
                FROM audit_events
                ORDER BY audit_sequence
                """
            )
            return tuple(self._audit_from_row(row) for row in cursor.fetchall())

    def list_endpoints(self) -> tuple[Endpoint, ...]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT endpoint_id, display_name, platform, architecture, identity_id,
                       enrolled_at, last_receipt_at, last_heartbeat_at
                FROM endpoints
                ORDER BY endpoint_id
                """
            )
            return tuple(self._endpoint_from_row(row) for row in cursor.fetchall())

    def get_endpoint(self, endpoint_id: UUID) -> Endpoint:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT endpoint_id, display_name, platform, architecture, identity_id,
                       enrolled_at, last_receipt_at, last_heartbeat_at
                FROM endpoints WHERE endpoint_id = %s
                """,
                (endpoint_id,),
            )
            row = cursor.fetchone()
        if row is None:
            raise NotFoundError("endpoint does not exist")
        return self._endpoint_from_row(row)

    def get_identity(self, identity_id: UUID) -> EndpointIdentity:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT identity_id, endpoint_id, public_key_fingerprint, created_at,
                       revoked_at, revocation_reason
                FROM endpoint_identities WHERE identity_id = %s
                """,
                (identity_id,),
            )
            row = cursor.fetchone()
        if row is None:
            raise NotFoundError("identity does not exist")
        return self._identity_from_row(row)

    def create_enrollment_grant(
        self,
        *,
        display_name: str,
        platform: Platform,
        architecture: str,
        now: datetime,
        actor_id: str,
        ttl: timedelta = MAX_ENROLLMENT_GRANT_TTL,
    ) -> tuple[EnrollmentGrant, str]:
        """Create one short-lived grant and return its secret exactly once."""

        require_aware(now, "now")
        server_time = now.astimezone(UTC)
        raw_token = GRANT_NAMESPACE + secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        grant = EnrollmentGrant(
            grant_id=uuid4(),
            token_sha256=token_sha256,
            display_name=display_name,
            platform=platform,
            architecture=architecture,
            created_at=server_time,
            expires_at=server_time + ttl,
            created_by=actor_id,
        )
        correlation_id = uuid4()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO enrollment_grants (
                    grant_id, token_sha256, display_name, platform, architecture,
                    created_at, expires_at, created_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    grant.grant_id,
                    grant.token_sha256,
                    grant.display_name,
                    grant.platform.value,
                    grant.architecture,
                    grant.created_at,
                    grant.expires_at,
                    grant.created_by,
                ),
            )
            self._insert_audit(
                cursor,
                server_time=server_time,
                actor_type="operator",
                actor_id=actor_id,
                subject=f"enrollment_grant:{grant.grant_id}",
                action="enrollment_grant.create",
                decision="accepted",
                reason="short-lived single-use grant created",
                correlation_id=correlation_id,
                metadata=(
                    ("architecture", grant.architecture),
                    ("display_name", grant.display_name),
                    ("expires_at", grant.expires_at.isoformat()),
                    ("platform", grant.platform.value),
                ),
            )
        return grant, raw_token

    def get_enrollment_grant(self, grant_id: UUID) -> EnrollmentGrant:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT grant_id, token_sha256, display_name, platform, architecture,
                       created_at, expires_at, created_by, consumed_at,
                       consumed_identity_id
                FROM enrollment_grants
                WHERE grant_id = %s
                """,
                (grant_id,),
            )
            row = cursor.fetchone()
        if row is None:
            raise NotFoundError("enrollment grant does not exist")
        return self._enrollment_grant_from_row(row)

    def consume_enrollment_grant(
        self,
        *,
        token: str,
        public_key_fingerprint: str,
        now: datetime,
        actor_id: str = "enrollment-service",
    ) -> tuple[Endpoint, EndpointIdentity]:
        """Atomically exchange one valid grant for one endpoint identity."""

        require_aware(now, "now")
        server_time = now.astimezone(UTC)
        if not actor_id or len(actor_id) > 256:
            raise ValidationError("actor_id is empty or too long")
        correlation_id = uuid4()
        failure_reason: str | None = None
        grant: EnrollmentGrant | None = None
        endpoint: Endpoint | None = None
        identity: EndpointIdentity | None = None
        token_sha256 = (
            hashlib.sha256(token.encode("ascii")).hexdigest()
            if ENROLLMENT_TOKEN_PATTERN.fullmatch(token) is not None
            else None
        )

        try:
            with self._connect() as connection, connection.cursor() as cursor:
                if token_sha256 is None:
                    failure_reason = "token format is invalid"
                else:
                    cursor.execute(
                        """
                        SELECT grant_id, token_sha256, display_name, platform,
                               architecture, created_at, expires_at, created_by,
                               consumed_at, consumed_identity_id
                        FROM enrollment_grants
                        WHERE token_sha256 = %s
                        FOR UPDATE
                        """,
                        (token_sha256,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        failure_reason = "token digest is unknown"
                    else:
                        grant = self._enrollment_grant_from_row(row)
                        if grant.consumed_at is not None:
                            failure_reason = "grant is already consumed"
                        elif server_time < grant.created_at:
                            failure_reason = "server time predates grant creation"
                        elif server_time >= grant.expires_at:
                            failure_reason = "grant is expired"
                        elif (
                            re.fullmatch(r"sha256:[0-9a-f]{64}", public_key_fingerprint)
                            is None
                        ):
                            failure_reason = "public key fingerprint format is invalid"

                subject = (
                    f"enrollment_grant:{grant.grant_id}"
                    if grant is not None
                    else "enrollment_grant:unknown"
                )
                if failure_reason is not None:
                    self._insert_audit(
                        cursor,
                        server_time=server_time,
                        actor_type="service",
                        actor_id=actor_id,
                        subject=subject,
                        action="enrollment_grant.consume",
                        decision="rejected",
                        reason=failure_reason,
                        correlation_id=correlation_id,
                    )
                elif grant is not None:
                    endpoint_id = uuid4()
                    identity_id = uuid4()
                    identity = EndpointIdentity(
                        identity_id=identity_id,
                        endpoint_id=endpoint_id,
                        public_key_fingerprint=public_key_fingerprint,
                        created_at=server_time,
                    )
                    endpoint = Endpoint(
                        endpoint_id=endpoint_id,
                        display_name=grant.display_name,
                        platform=grant.platform,
                        architecture=grant.architecture,
                        identity_id=identity_id,
                        enrolled_at=server_time,
                    )
                    cursor.execute("SET CONSTRAINTS ALL DEFERRED")
                    cursor.execute(
                        """
                        INSERT INTO endpoints (
                            endpoint_id, display_name, platform, architecture,
                            identity_id, enrolled_at
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            endpoint.endpoint_id,
                            endpoint.display_name,
                            endpoint.platform.value,
                            endpoint.architecture,
                            endpoint.identity_id,
                            endpoint.enrolled_at,
                        ),
                    )
                    cursor.execute(
                        """
                        INSERT INTO endpoint_identities (
                            identity_id, endpoint_id, public_key_fingerprint, created_at
                        ) VALUES (%s, %s, %s, %s)
                        """,
                        (
                            identity.identity_id,
                            identity.endpoint_id,
                            identity.public_key_fingerprint,
                            identity.created_at,
                        ),
                    )
                    cursor.execute(
                        """
                        UPDATE enrollment_grants
                        SET consumed_at = %s, consumed_identity_id = %s
                        WHERE grant_id = %s AND consumed_at IS NULL
                        """,
                        (server_time, identity.identity_id, grant.grant_id),
                    )
                    if cursor.rowcount != 1:
                        raise AssertionError("locked grant must be consumable once")
                    self._insert_audit(
                        cursor,
                        server_time=server_time,
                        actor_type="service",
                        actor_id=actor_id,
                        subject=subject,
                        action="enrollment_grant.consume",
                        decision="accepted",
                        reason="grant exchanged for one endpoint identity",
                        correlation_id=correlation_id,
                        metadata=(
                            ("endpoint_id", str(endpoint.endpoint_id)),
                            ("identity_id", str(identity.identity_id)),
                        ),
                    )
                    self._insert_audit(
                        cursor,
                        server_time=server_time,
                        actor_type="service",
                        actor_id=actor_id,
                        subject=f"endpoint:{endpoint.endpoint_id}",
                        action="endpoint.enroll",
                        decision="accepted",
                        reason="single-use enrollment grant consumed",
                        correlation_id=correlation_id,
                        metadata=(
                            ("grant_id", str(grant.grant_id)),
                            ("identity_id", str(identity.identity_id)),
                        ),
                    )
        except UniqueViolation as exc:
            subject = (
                f"enrollment_grant:{grant.grant_id}"
                if grant is not None
                else "enrollment_grant:unknown"
            )
            self._record_audit(
                server_time=server_time,
                actor_type="service",
                actor_id=actor_id,
                subject=subject,
                action="enrollment_grant.consume",
                decision="rejected",
                reason="public key fingerprint is already enrolled",
                correlation_id=correlation_id,
            )
            raise AuthorizationError(ENROLLMENT_REJECTION) from exc

        if failure_reason is not None:
            raise AuthorizationError(ENROLLMENT_REJECTION)
        if endpoint is None or identity is None:
            raise AssertionError("accepted grant consumption must create an identity")
        return endpoint, identity

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
        """Atomically enroll one endpoint and identity under database constraints."""

        require_aware(now, "now")
        endpoint_id = uuid4()
        identity_id = uuid4()
        correlation_id = uuid4()
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

        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SET CONSTRAINTS ALL DEFERRED")
                cursor.execute(
                    """
                    INSERT INTO endpoints (
                        endpoint_id, display_name, platform, architecture,
                        identity_id, enrolled_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        endpoint.endpoint_id,
                        endpoint.display_name,
                        endpoint.platform.value,
                        endpoint.architecture,
                        endpoint.identity_id,
                        endpoint.enrolled_at,
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO endpoint_identities (
                        identity_id, endpoint_id, public_key_fingerprint, created_at
                    ) VALUES (%s, %s, %s, %s)
                    """,
                    (
                        identity.identity_id,
                        identity.endpoint_id,
                        identity.public_key_fingerprint,
                        identity.created_at,
                    ),
                )
                self._insert_audit(
                    cursor,
                    server_time=now,
                    actor_type="operator",
                    actor_id=actor_id,
                    subject=f"endpoint:{endpoint_id}",
                    action="endpoint.enroll",
                    decision="accepted",
                    reason="synthetic Phase 1 enrollment",
                    correlation_id=correlation_id,
                    metadata=(("identity_id", str(identity_id)),),
                )
        except UniqueViolation as exc:
            self._record_audit(
                server_time=now,
                actor_type="operator",
                actor_id=actor_id,
                subject="endpoint:new",
                action="endpoint.enroll",
                decision="rejected",
                reason="fingerprint is already enrolled",
                correlation_id=correlation_id,
            )
            raise ValidationError("fingerprint is already enrolled") from exc
        return endpoint, identity

    def ingest_heartbeat(
        self,
        *,
        authenticated_identity_id: UUID,
        message: HeartbeatMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> Observation:
        return self._ingest(
            authenticated_identity_id=authenticated_identity_id,
            envelope=message.envelope,
            observation_type="heartbeat",
            schema_version=1,
            payload_digest=message.payload.digest(),
            received_at=received_at,
            inventory_binding=None,
            encoded_message_digest=encoded_message_digest,
        )

    def ingest_inventory(
        self,
        *,
        authenticated_identity_id: UUID,
        message: InventoryMessage,
        received_at: datetime,
        encoded_message_digest: str | None = None,
    ) -> Observation:
        return self._ingest(
            authenticated_identity_id=authenticated_identity_id,
            envelope=message.envelope,
            observation_type="inventory",
            schema_version=message.payload.schema_version,
            payload_digest=message.payload.digest(),
            received_at=received_at,
            inventory_binding=(message.payload.platform, message.payload.architecture),
            encoded_message_digest=encoded_message_digest,
        )

    def authenticate_endpoint_certificate(
        self,
        *,
        endpoint_id: UUID,
        public_key_fingerprint: str,
        authenticated_at: datetime,
        correlation_id: UUID,
    ) -> EndpointIdentity:
        """Authorize one TLS-verified certificate by endpoint and public key."""

        require_aware(authenticated_at, "authenticated_at")
        server_time = authenticated_at.astimezone(UTC)
        identity: EndpointIdentity | None = None
        failure_reason: str | None = None
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT identity_id, endpoint_id, public_key_fingerprint, created_at,
                       revoked_at, revocation_reason
                FROM endpoint_identities
                WHERE endpoint_id = %s AND public_key_fingerprint = %s
                FOR UPDATE
                """,
                (endpoint_id, public_key_fingerprint),
            )
            row = cursor.fetchone()
            if row is None:
                failure_reason = "certificate endpoint or public key is unknown"
            else:
                identity = self._identity_from_row(row)
                if identity.revoked_at is not None:
                    failure_reason = "certificate identity is revoked"
            self._insert_audit(
                cursor,
                server_time=server_time,
                actor_type="endpoint_certificate",
                actor_id=str(endpoint_id),
                subject=f"endpoint:{endpoint_id}",
                action="certificate.authenticate",
                decision="rejected" if failure_reason is not None else "accepted",
                reason=failure_reason or "verified certificate key is active",
                correlation_id=correlation_id,
            )
        if failure_reason is not None or identity is None:
            raise AuthorizationError("endpoint certificate is unauthorized")
        return identity

    def endpoint_status(
        self,
        endpoint_id: UUID,
        *,
        now: datetime,
        policy: FreshnessPolicy | None = None,
    ) -> EndpointStatus:
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
        require_aware(now, "now")
        if not reason or len(reason) > 256:
            raise ValidationError("revocation reason is empty or too long")
        event_correlation_id = correlation_id or uuid4()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT identity_id, endpoint_id, public_key_fingerprint, created_at,
                       revoked_at, revocation_reason
                FROM endpoint_identities
                WHERE identity_id = %s
                FOR UPDATE
                """,
                (identity_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise NotFoundError("identity does not exist")
            identity = self._identity_from_row(row)
            if identity.revoked_at is not None:
                self._insert_audit(
                    cursor,
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
                revoked_at=now,
                revocation_reason=reason,
            )
            cursor.execute(
                """
                UPDATE endpoint_identities
                SET revoked_at = %s, revocation_reason = %s
                WHERE identity_id = %s
                """,
                (now, reason, identity_id),
            )
            self._insert_audit(
                cursor,
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

    def _ingest(
        self,
        *,
        authenticated_identity_id: UUID,
        envelope: MessageEnvelope,
        observation_type: str,
        schema_version: int,
        payload_digest: str,
        received_at: datetime,
        inventory_binding: tuple[Platform, str] | None,
        encoded_message_digest: str | None,
    ) -> Observation:
        require_aware(received_at, "received_at")
        received_at = received_at.astimezone(UTC)
        failure: Failure | None = None
        observation: Observation | None = None
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT i.identity_id, i.endpoint_id, i.public_key_fingerprint,
                           i.created_at, i.revoked_at, i.revocation_reason,
                           e.platform, e.architecture
                    FROM endpoint_identities AS i
                    JOIN endpoints AS e ON e.endpoint_id = i.endpoint_id
                    WHERE i.identity_id = %s
                    FOR UPDATE OF i, e
                    """,
                    (authenticated_identity_id,),
                )
                row = cursor.fetchone()
                identity: EndpointIdentity | None = None
                if row is None:
                    failure = (AuthorizationError, "unknown authenticated identity")
                else:
                    identity = self._identity_from_row(row)

                if failure is None and identity is not None and identity.revoked_at:
                    failure = (AuthorizationError, "authenticated identity is revoked")
                if (
                    failure is None
                    and identity is not None
                    and envelope.endpoint_id != identity.endpoint_id
                ):
                    failure = (
                        AuthorizationError,
                        "message endpoint does not match transport identity",
                    )
                if failure is None:
                    cursor.execute(
                        """
                        SELECT observation_id, endpoint_id, identity_id, message_id,
                               observation_type, schema_version, source_time,
                               received_at, boot_id, sequence, payload_digest,
                               encoded_message_digest
                        FROM observations
                        WHERE message_id = %s
                        """,
                        (envelope.message_id,),
                    )
                    existing = cursor.fetchone()
                    if existing is not None:
                        if (
                            encoded_message_digest is not None
                            and existing["encoded_message_digest"]
                            == encoded_message_digest
                            and existing["identity_id"] == authenticated_identity_id
                            and existing["endpoint_id"] == envelope.endpoint_id
                        ):
                            observation = self._observation_from_row(existing)
                            self._insert_audit(
                                cursor,
                                server_time=received_at,
                                actor_type="endpoint_identity",
                                actor_id=str(authenticated_identity_id),
                                subject=f"endpoint:{envelope.endpoint_id}",
                                action=f"{observation_type}.ingest",
                                decision="no_change",
                                reason="exact accepted message retry acknowledged",
                                correlation_id=envelope.correlation_id,
                                metadata=(("message_id", str(envelope.message_id)),),
                            )
                        else:
                            failure = (ReplayError, "message ID reused with conflict")
                if (
                    failure is None
                    and observation is None
                    and envelope.created_at > received_at + MAX_CLOCK_SKEW
                ):
                    failure = (
                        ValidationError,
                        "message creation time exceeds allowed clock skew",
                    )
                if (
                    failure is None
                    and observation is None
                    and received_at >= envelope.expires_at
                ):
                    failure = (ValidationError, "message expired before receipt")
                if (
                    failure is None
                    and observation is None
                    and inventory_binding is not None
                    and row is not None
                ):
                    platform, architecture = inventory_binding
                    if (
                        platform.value != row["platform"]
                        or architecture != row["architecture"]
                    ):
                        failure = (
                            ValidationError,
                            "inventory binding does not match enrolled endpoint",
                        )
                if failure is None and observation is None:
                    cursor.execute(
                        """
                        INSERT INTO message_sequences (
                            identity_id, boot_id, last_sequence
                        )
                        VALUES (%s, %s, %s)
                        ON CONFLICT (identity_id, boot_id) DO UPDATE
                        SET last_sequence = EXCLUDED.last_sequence
                        WHERE message_sequences.last_sequence < EXCLUDED.last_sequence
                        RETURNING last_sequence
                        """,
                        (
                            authenticated_identity_id,
                            envelope.boot_id,
                            envelope.sequence,
                        ),
                    )
                    if cursor.fetchone() is None:
                        failure = (
                            ReplayError,
                            "boot sequence replayed or out of order",
                        )

                if failure is not None:
                    self._insert_rejection(
                        cursor,
                        identity_id=authenticated_identity_id,
                        endpoint_id=envelope.endpoint_id,
                        action=f"{observation_type}.ingest",
                        reason=failure[1],
                        correlation_id=envelope.correlation_id,
                        received_at=received_at,
                    )
                elif observation is None:
                    if identity is None:
                        raise AssertionError(
                            "authorized ingestion requires an identity"
                        )
                    observation = Observation(
                        observation_id=uuid4(),
                        endpoint_id=identity.endpoint_id,
                        message_id=envelope.message_id,
                        observation_type=observation_type,
                        schema_version=schema_version,
                        source_time=envelope.created_at,
                        received_at=received_at,
                        boot_id=envelope.boot_id,
                        sequence=envelope.sequence,
                        payload_digest=payload_digest,
                        encoded_message_digest=encoded_message_digest,
                    )
                    cursor.execute(
                        """
                        INSERT INTO observations (
                            observation_id, endpoint_id, identity_id, message_id,
                            observation_type, schema_version, source_time, received_at,
                            boot_id, sequence, payload_digest, encoded_message_digest
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        """,
                        (
                            observation.observation_id,
                            observation.endpoint_id,
                            authenticated_identity_id,
                            observation.message_id,
                            observation.observation_type,
                            observation.schema_version,
                            observation.source_time,
                            observation.received_at,
                            observation.boot_id,
                            observation.sequence,
                            observation.payload_digest,
                            observation.encoded_message_digest,
                        ),
                    )
                    if observation_type == "heartbeat":
                        cursor.execute(
                            """
                            UPDATE endpoints
                            SET last_receipt_at = GREATEST(
                                    COALESCE(last_receipt_at, %s), %s
                                ),
                                last_heartbeat_at = GREATEST(
                                    COALESCE(last_heartbeat_at, %s), %s
                                )
                            WHERE endpoint_id = %s
                            """,
                            (
                                received_at,
                                received_at,
                                received_at,
                                received_at,
                                identity.endpoint_id,
                            ),
                        )
                    else:
                        cursor.execute(
                            """
                            UPDATE endpoints
                            SET last_receipt_at = GREATEST(
                                COALESCE(last_receipt_at, %s), %s
                            )
                            WHERE endpoint_id = %s
                            """,
                            (received_at, received_at, identity.endpoint_id),
                        )
                    self._insert_audit(
                        cursor,
                        server_time=received_at,
                        actor_type="endpoint_identity",
                        actor_id=str(identity.identity_id),
                        subject=f"endpoint:{identity.endpoint_id}",
                        action=f"{observation_type}.ingest",
                        decision="accepted",
                        reason="message contract and authorization checks passed",
                        correlation_id=envelope.correlation_id,
                        metadata=(
                            ("message_id", str(observation.message_id)),
                            ("payload_digest", observation.payload_digest),
                            ("sequence", str(observation.sequence)),
                        ),
                    )
        except UniqueViolation as exc:
            failure = (ReplayError, "message ID or boot sequence replayed")
            self._record_rejection(
                identity_id=authenticated_identity_id,
                endpoint_id=envelope.endpoint_id,
                action=f"{observation_type}.ingest",
                reason=failure[1],
                correlation_id=envelope.correlation_id,
                received_at=received_at,
            )
            raise ReplayError(failure[1]) from exc

        if failure is not None:
            error_type, reason = failure
            raise error_type(reason)
        if observation is None:
            raise AssertionError("accepted ingestion must create an observation")
        return observation

    def _record_rejection(
        self,
        *,
        identity_id: UUID,
        endpoint_id: UUID,
        action: str,
        reason: str,
        correlation_id: UUID,
        received_at: datetime,
    ) -> None:
        self._record_audit(
            server_time=received_at,
            actor_type="endpoint_identity",
            actor_id=str(identity_id),
            subject=f"endpoint:{endpoint_id}",
            action=action,
            decision="rejected",
            reason=reason,
            correlation_id=correlation_id,
        )

    def _record_audit(
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
        with self._connect() as connection, connection.cursor() as cursor:
            self._insert_audit(
                cursor,
                server_time=server_time,
                actor_type=actor_type,
                actor_id=actor_id,
                subject=subject,
                action=action,
                decision=decision,
                reason=reason,
                correlation_id=correlation_id,
                metadata=metadata,
            )

    @staticmethod
    def _insert_rejection(
        cursor: Cursor[Row],
        *,
        identity_id: UUID,
        endpoint_id: UUID,
        action: str,
        reason: str,
        correlation_id: UUID,
        received_at: datetime,
    ) -> None:
        PostgresControlPlane._insert_audit(
            cursor,
            server_time=received_at,
            actor_type="endpoint_identity",
            actor_id=str(identity_id),
            subject=f"endpoint:{endpoint_id}",
            action=action,
            decision="rejected",
            reason=reason,
            correlation_id=correlation_id,
        )

    @staticmethod
    def _insert_audit(
        cursor: Cursor[Row],
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
        cursor.execute(
            """
            INSERT INTO audit_events (
                event_id, server_time, actor_type, actor_id, subject, action,
                decision, reason, correlation_id, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
            """,
            (
                uuid4(),
                server_time,
                actor_type,
                actor_id,
                subject,
                action,
                decision,
                reason,
                correlation_id,
                json.dumps(dict(sorted(metadata))),
            ),
        )

    @staticmethod
    def _endpoint_from_row(row: Row) -> Endpoint:
        return Endpoint(
            endpoint_id=cast(UUID, row["endpoint_id"]),
            display_name=cast(str, row["display_name"]),
            platform=Platform(cast(str, row["platform"])),
            architecture=cast(str, row["architecture"]),
            identity_id=cast(UUID, row["identity_id"]),
            enrolled_at=cast(datetime, row["enrolled_at"]),
            last_receipt_at=cast(datetime | None, row["last_receipt_at"]),
            last_heartbeat_at=cast(datetime | None, row["last_heartbeat_at"]),
        )

    @staticmethod
    def _identity_from_row(row: Row) -> EndpointIdentity:
        return EndpointIdentity(
            identity_id=cast(UUID, row["identity_id"]),
            endpoint_id=cast(UUID, row["endpoint_id"]),
            public_key_fingerprint=cast(str, row["public_key_fingerprint"]),
            created_at=cast(datetime, row["created_at"]),
            revoked_at=cast(datetime | None, row["revoked_at"]),
            revocation_reason=cast(str | None, row["revocation_reason"]),
        )

    @staticmethod
    def _enrollment_grant_from_row(row: Row) -> EnrollmentGrant:
        return EnrollmentGrant(
            grant_id=cast(UUID, row["grant_id"]),
            token_sha256=cast(str, row["token_sha256"]),
            display_name=cast(str, row["display_name"]),
            platform=Platform(cast(str, row["platform"])),
            architecture=cast(str, row["architecture"]),
            created_at=cast(datetime, row["created_at"]),
            expires_at=cast(datetime, row["expires_at"]),
            created_by=cast(str, row["created_by"]),
            consumed_at=cast(datetime | None, row["consumed_at"]),
            consumed_identity_id=cast(UUID | None, row["consumed_identity_id"]),
        )

    @staticmethod
    def _observation_from_row(row: Row) -> Observation:
        return Observation(
            observation_id=cast(UUID, row["observation_id"]),
            endpoint_id=cast(UUID, row["endpoint_id"]),
            message_id=cast(UUID, row["message_id"]),
            observation_type=cast(str, row["observation_type"]),
            schema_version=cast(int, row["schema_version"]),
            source_time=cast(datetime, row["source_time"]),
            received_at=cast(datetime, row["received_at"]),
            boot_id=cast(UUID, row["boot_id"]),
            sequence=cast(int, row["sequence"]),
            payload_digest=cast(str, row["payload_digest"]),
            encoded_message_digest=cast(str | None, row.get("encoded_message_digest")),
        )

    @staticmethod
    def _audit_from_row(row: Row) -> AuditEvent:
        metadata = cast(dict[str, Any], row["metadata"])
        return AuditEvent(
            event_id=cast(UUID, row["event_id"]),
            server_time=cast(datetime, row["server_time"]),
            actor_type=cast(str, row["actor_type"]),
            actor_id=cast(str, row["actor_id"]),
            subject=cast(str, row["subject"]),
            action=cast(str, row["action"]),
            decision=cast(str, row["decision"]),
            reason=cast(str, row["reason"]),
            correlation_id=cast(UUID, row["correlation_id"]),
            metadata=tuple(
                sorted((key, str(value)) for key, value in metadata.items())
            ),
        )
