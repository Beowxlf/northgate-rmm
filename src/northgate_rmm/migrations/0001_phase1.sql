CREATE TABLE endpoints (
    endpoint_id uuid PRIMARY KEY,
    display_name varchar(128) NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
    platform varchar(16) NOT NULL CHECK (platform IN ('linux', 'windows')),
    architecture varchar(32) NOT NULL CHECK (char_length(architecture) BETWEEN 1 AND 32),
    identity_id uuid NOT NULL UNIQUE,
    enrolled_at timestamptz NOT NULL,
    last_receipt_at timestamptz,
    last_heartbeat_at timestamptz
);

CREATE TABLE endpoint_identities (
    identity_id uuid PRIMARY KEY,
    endpoint_id uuid NOT NULL UNIQUE REFERENCES endpoints(endpoint_id) ON DELETE RESTRICT,
    public_key_fingerprint varchar(71) NOT NULL UNIQUE
        CHECK (public_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason varchar(256),
    CHECK (
        (revoked_at IS NULL AND revocation_reason IS NULL)
        OR
        (revoked_at IS NOT NULL AND char_length(revocation_reason) BETWEEN 1 AND 256)
    ),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

ALTER TABLE endpoints
    ADD CONSTRAINT endpoints_identity_fk
    FOREIGN KEY (identity_id)
    REFERENCES endpoint_identities(identity_id)
    ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE message_sequences (
    identity_id uuid NOT NULL REFERENCES endpoint_identities(identity_id) ON DELETE RESTRICT,
    boot_id uuid NOT NULL,
    last_sequence bigint NOT NULL CHECK (last_sequence > 0),
    PRIMARY KEY (identity_id, boot_id)
);

CREATE TABLE observations (
    observation_id uuid PRIMARY KEY,
    endpoint_id uuid NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE RESTRICT,
    identity_id uuid NOT NULL REFERENCES endpoint_identities(identity_id) ON DELETE RESTRICT,
    message_id uuid NOT NULL UNIQUE,
    observation_type varchar(32) NOT NULL CHECK (observation_type IN ('heartbeat', 'inventory')),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    source_time timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    boot_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    UNIQUE (identity_id, boot_id, sequence)
);

CREATE INDEX observations_endpoint_received_idx
    ON observations (endpoint_id, received_at DESC);

CREATE TABLE audit_events (
    audit_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id uuid NOT NULL UNIQUE,
    server_time timestamptz NOT NULL,
    actor_type varchar(64) NOT NULL,
    actor_id varchar(256) NOT NULL,
    subject varchar(256) NOT NULL,
    action varchar(128) NOT NULL,
    decision varchar(32) NOT NULL CHECK (decision IN ('accepted', 'rejected', 'no_change')),
    reason varchar(512) NOT NULL,
    correlation_id uuid NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX audit_events_correlation_idx
    ON audit_events (correlation_id, audit_sequence);

REVOKE UPDATE, DELETE, TRUNCATE ON observations FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC;
