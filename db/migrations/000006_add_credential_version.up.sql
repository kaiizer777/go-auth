-- Backfill boundary: pre-existing rows inherit DEFAULT 0 (no explicit
-- backfill step); pre-deploy sessions stay valid until the next credential
-- change (grandfathered). Pre-deploy resets unenforced — accepted boundary
-- (#28/#27 follow-ups out of scope).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 0;

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 0;
