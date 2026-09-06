ALTER TABLE enrollment_grants
    DROP CONSTRAINT enrollment_grants_platform_check;

ALTER TABLE enrollment_grants
    ADD CONSTRAINT enrollment_grants_platform_check
    CHECK (platform IN ('linux', 'windows'));
