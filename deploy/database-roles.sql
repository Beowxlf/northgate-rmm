-- Run as the deployment/migration owner after migrations. Assign login roles
-- through separate credential custody. Application roles never own tables.
BEGIN;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='northgate_agent') THEN
        CREATE ROLE northgate_agent NOLOGIN;
        CREATE ROLE northgate_enrollment NOLOGIN;
        CREATE ROLE northgate_operator NOLOGIN;
        CREATE ROLE northgate_export NOLOGIN;
        CREATE ROLE northgate_retention NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA public TO northgate_agent,northgate_enrollment,
    northgate_operator,northgate_export,northgate_retention;
GRANT SELECT ON schema_migrations TO northgate_agent,northgate_enrollment,
    northgate_operator,northgate_export,northgate_retention;
GRANT SELECT ON endpoints,endpoint_identities,observations,message_sequences,
    certificate_renewals TO northgate_agent;
GRANT SELECT ON endpoints,endpoint_identities,enrollment_grants TO northgate_enrollment;
GRANT SELECT ON endpoints,endpoint_identities,observations TO northgate_operator;
GRANT SELECT ON audit_delivery_state,audit_outbox TO northgate_export;
GRANT SELECT ON retention_hold,observations,audit_outbox,audit_delivery_state
    TO northgate_retention;
GRANT INSERT ON audit_events TO northgate_agent,northgate_enrollment,
    northgate_operator,northgate_retention;
GRANT USAGE ON SEQUENCE audit_events_audit_sequence_seq TO northgate_agent,
    northgate_enrollment,northgate_operator,northgate_retention;
GRANT INSERT,UPDATE ON endpoints,endpoint_identities,enrollment_grants
    TO northgate_enrollment;
GRANT INSERT,UPDATE ON observations,message_sequences,certificate_renewals
    TO northgate_agent;
GRANT UPDATE ON endpoints,endpoint_identities TO northgate_agent;
GRANT UPDATE(acknowledged_sequence,acknowledged_hash,acknowledged_at)
    ON audit_delivery_state TO northgate_export;
GRANT DELETE ON observations,audit_outbox TO northgate_retention;
ALTER FUNCTION northgate_enqueue_audit() SECURITY DEFINER;
REVOKE ALL ON FUNCTION northgate_enqueue_audit() FROM PUBLIC;
-- Enable only after a verified independent checkpoint has arrived.
UPDATE audit_delivery_state SET enforce_delivery=true
WHERE singleton AND acknowledged_at > clock_timestamp() - interval '1 minute';
COMMIT;
