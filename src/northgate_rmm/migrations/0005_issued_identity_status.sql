ALTER TABLE endpoint_identities
    DROP CONSTRAINT endpoint_identities_status_check;

ALTER TABLE endpoint_identities
    ADD CONSTRAINT endpoint_identities_status_check
        CHECK (
            identity_status IN ('pending', 'issued', 'active', 'retired', 'revoked')
        );
