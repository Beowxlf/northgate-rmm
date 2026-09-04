ALTER TABLE endpoint_identities
    DROP CONSTRAINT endpoint_identities_previous_identity_id_fkey;

ALTER TABLE endpoint_identities
    ADD CONSTRAINT endpoint_identities_identity_endpoint_key
        UNIQUE (identity_id, endpoint_id),
    ADD CONSTRAINT endpoint_identities_previous_identity_endpoint_fkey
        FOREIGN KEY (previous_identity_id, endpoint_id)
        REFERENCES endpoint_identities (identity_id, endpoint_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM endpoint_identities AS current_identity
        JOIN endpoint_identities AS previous_identity
          ON previous_identity.identity_id = current_identity.previous_identity_id
        WHERE previous_identity.created_at >= current_identity.created_at
    ) THEN
        RAISE EXCEPTION 'existing identity rotation lineage is not chronological'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE FUNCTION enforce_endpoint_identity_lineage()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    predecessor_endpoint_id uuid;
    predecessor_created_at timestamptz;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.identity_id IS DISTINCT FROM OLD.identity_id
        OR NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.previous_identity_id IS DISTINCT FROM OLD.previous_identity_id
    ) THEN
        RAISE EXCEPTION 'identity rotation lineage is immutable'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.previous_identity_id IS NOT NULL THEN
        SELECT endpoint_id, created_at
        INTO predecessor_endpoint_id, predecessor_created_at
        FROM endpoint_identities
        WHERE identity_id = NEW.previous_identity_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'identity rotation predecessor must already exist'
                USING ERRCODE = '23514';
        END IF;
        IF predecessor_endpoint_id <> NEW.endpoint_id THEN
            RAISE EXCEPTION 'identity rotation predecessor belongs to another endpoint'
                USING ERRCODE = '23514';
        END IF;
        IF predecessor_created_at >= NEW.created_at THEN
            RAISE EXCEPTION 'identity rotation predecessor must be older'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER endpoint_identity_lineage_guard
BEFORE INSERT OR UPDATE OF identity_id, endpoint_id, created_at, previous_identity_id
ON endpoint_identities
FOR EACH ROW
EXECUTE FUNCTION enforce_endpoint_identity_lineage();
