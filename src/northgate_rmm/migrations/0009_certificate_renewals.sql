CREATE TABLE certificate_renewals (
    request_id uuid PRIMARY KEY,
    identity_id uuid NOT NULL REFERENCES endpoint_identities(identity_id),
    response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at timestamptz NOT NULL
);
CREATE INDEX certificate_renewals_created_idx ON certificate_renewals(created_at);
REVOKE ALL ON certificate_renewals FROM PUBLIC;
