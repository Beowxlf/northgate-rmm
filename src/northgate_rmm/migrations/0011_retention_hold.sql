CREATE TABLE retention_hold (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active boolean NOT NULL DEFAULT true
);
INSERT INTO retention_hold(singleton) VALUES(true);
REVOKE ALL ON retention_hold FROM PUBLIC;
