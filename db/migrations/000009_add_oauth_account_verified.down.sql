-- 000009 down drops the trust flag, not the links. Re-applying the up file
-- restores the column as FALSE for every row, which is the same fail-closed
-- state the up backfill produced, so this rollback loses no identity data.
ALTER TABLE oauth_accounts DROP COLUMN IF EXISTS verified;
