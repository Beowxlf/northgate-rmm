ALTER TABLE endpoints
    DROP CONSTRAINT endpoints_identity_fk;

ALTER TABLE endpoints
    ADD CONSTRAINT endpoints_identity_endpoint_fk
        FOREIGN KEY (identity_id, endpoint_id)
        REFERENCES endpoint_identities (identity_id, endpoint_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;
