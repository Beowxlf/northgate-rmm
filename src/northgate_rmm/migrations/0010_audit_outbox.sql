CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE audit_delivery_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_sequence bigint NOT NULL DEFAULT 0,
    last_hash text NOT NULL DEFAULT repeat('0',64),
    acknowledged_sequence bigint NOT NULL DEFAULT 0,
    acknowledged_hash text NOT NULL DEFAULT repeat('0',64),
    acknowledged_at timestamptz,
    enforce_delivery boolean NOT NULL DEFAULT false,
    CHECK (acknowledged_sequence <= last_sequence)
);
INSERT INTO audit_delivery_state(singleton) VALUES(true);
CREATE TABLE audit_outbox (
    chain_sequence bigint PRIMARY KEY,
    event_id uuid UNIQUE NOT NULL,
    previous_hash text NOT NULL,
    event_hash text NOT NULL,
    payload text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION northgate_enqueue_audit() RETURNS trigger
LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE
    anchor audit_delivery_state%ROWTYPE;
    encoded text;
    next_hash text;
BEGIN
    SELECT * INTO anchor FROM audit_delivery_state WHERE singleton FOR UPDATE;
    IF anchor.enforce_delivery AND (
        anchor.last_sequence - anchor.acknowledged_sequence >= 10000 OR
        anchor.acknowledged_at IS NULL OR
        anchor.acknowledged_at < clock_timestamp() - interval '5 minutes'
    ) THEN
        RAISE EXCEPTION 'independent audit delivery unavailable';
    END IF;
    encoded := jsonb_build_object(
        'event_id', NEW.event_id, 'server_time', NEW.server_time,
        'actor_type', NEW.actor_type, 'actor_id', NEW.actor_id,
        'subject', NEW.subject, 'action', NEW.action, 'decision', NEW.decision,
        'reason', NEW.reason, 'correlation_id', NEW.correlation_id,
        'metadata', NEW.metadata
    )::text;
    next_hash := encode(digest(convert_to(anchor.last_hash || encoded, 'UTF8'),'sha256'),'hex');
    INSERT INTO audit_outbox(chain_sequence,event_id,previous_hash,event_hash,payload)
    VALUES(anchor.last_sequence+1, NEW.event_id, anchor.last_hash, next_hash, encoded);
    UPDATE audit_delivery_state SET last_sequence=anchor.last_sequence+1,last_hash=next_hash WHERE singleton;
    RETURN NEW;
END;
$$;

-- Seed the independent chain with existing history without modifying old events.
DO $$
DECLARE row_record audit_events%ROWTYPE; anchor audit_delivery_state%ROWTYPE; encoded text; next_hash text;
BEGIN
    FOR row_record IN SELECT * FROM audit_events ORDER BY audit_sequence LOOP
        SELECT * INTO anchor FROM audit_delivery_state WHERE singleton FOR UPDATE;
        encoded := to_jsonb(row_record)::text;
        next_hash := encode(digest(convert_to(anchor.last_hash || encoded,'UTF8'),'sha256'),'hex');
        INSERT INTO audit_outbox(chain_sequence,event_id,previous_hash,event_hash,payload)
        VALUES(anchor.last_sequence+1,row_record.event_id,anchor.last_hash,next_hash,encoded);
        UPDATE audit_delivery_state SET last_sequence=anchor.last_sequence+1,last_hash=next_hash WHERE singleton;
    END LOOP;
END;
$$;
CREATE TRIGGER northgate_audit_delivery AFTER INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION northgate_enqueue_audit();
REVOKE ALL ON audit_delivery_state, audit_outbox FROM PUBLIC;
