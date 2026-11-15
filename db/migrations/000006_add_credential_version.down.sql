BEGIN;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS credential_version;

ALTER TABLE users
    DROP COLUMN IF EXISTS credential_version;

COMMIT;
