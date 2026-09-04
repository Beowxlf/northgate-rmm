ALTER TABLE endpoint_identities
    DROP CONSTRAINT endpoint_identities_endpoint_id_key;

ALTER TABLE endpoint_identities
    ADD COLUMN identity_status varchar(16) NOT NULL DEFAULT 'active',
    ADD COLUMN certificate_serial varchar(64),
    ADD COLUMN certificate_issuer varchar(256),
    ADD COLUMN certificate_not_before timestamptz,
    ADD COLUMN certificate_not_after timestamptz,
    ADD COLUMN activated_at timestamptz,
    ADD COLUMN previous_identity_id uuid
        REFERENCES endpoint_identities(identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;

UPDATE endpoint_identities
SET identity_status = 'revoked'
WHERE revoked_at IS NOT NULL;

ALTER TABLE endpoint_identities
    ADD CONSTRAINT endpoint_identities_status_check
        CHECK (
            identity_status IN ('pending', 'issued', 'active', 'retired', 'revoked')
        ),
    ADD CONSTRAINT endpoint_identities_revocation_status_check
        CHECK (
            (identity_status = 'revoked' AND revoked_at IS NOT NULL)
            OR
            (identity_status <> 'revoked' AND revoked_at IS NULL)
        ),
    ADD CONSTRAINT endpoint_identities_certificate_window_check
        CHECK (
            certificate_not_before IS NULL
            OR certificate_not_after IS NULL
            OR certificate_not_after > certificate_not_before
        ),
    ADD CONSTRAINT endpoint_identities_activation_time_check
        CHECK (activated_at IS NULL OR activated_at >= created_at),
    ADD CONSTRAINT endpoint_identities_rotation_check
        CHECK (previous_identity_id IS NULL OR previous_identity_id <> identity_id);

CREATE INDEX endpoint_identities_endpoint_created_idx
    ON endpoint_identities (endpoint_id, created_at DESC);

CREATE UNIQUE INDEX endpoint_identities_certificate_issuer_serial_key
    ON endpoint_identities (certificate_issuer, certificate_serial)
    WHERE certificate_issuer IS NOT NULL AND certificate_serial IS NOT NULL;
