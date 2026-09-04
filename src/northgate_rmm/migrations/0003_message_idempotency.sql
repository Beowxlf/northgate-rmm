ALTER TABLE observations
    ADD COLUMN encoded_message_digest char(64)
    CHECK (
        encoded_message_digest IS NULL
        OR encoded_message_digest ~ '^[0-9a-f]{64}$'
    );

COMMENT ON COLUMN observations.encoded_message_digest IS
    'Exact encoded request digest for service-ingested idempotent acknowledgement; NULL only for legacy synthetic observations.';
