CREATE TABLE enrollment_grants (
    grant_id uuid PRIMARY KEY,
    token_sha256 char(64) NOT NULL UNIQUE
        CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    display_name varchar(128) NOT NULL
        CHECK (char_length(display_name) BETWEEN 1 AND 128),
    platform varchar(16) NOT NULL CHECK (platform = 'linux'),
    architecture varchar(32) NOT NULL CHECK (architecture = 'amd64'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_by varchar(256) NOT NULL
        CHECK (char_length(created_by) BETWEEN 1 AND 256),
    consumed_at timestamptz,
    consumed_identity_id uuid UNIQUE
        REFERENCES endpoint_identities(identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + interval '15 minutes'),
    CHECK (
        (consumed_at IS NULL AND consumed_identity_id IS NULL)
        OR
        (
            consumed_at IS NOT NULL
            AND consumed_identity_id IS NOT NULL
            AND consumed_at >= created_at
            AND consumed_at < expires_at
        )
    )
);

CREATE INDEX enrollment_grants_pending_expiry_idx
    ON enrollment_grants (expires_at)
    WHERE consumed_at IS NULL;

REVOKE SELECT, UPDATE, DELETE, TRUNCATE ON enrollment_grants FROM PUBLIC;
