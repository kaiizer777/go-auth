-- 000011 down restores the tenant-blind key as a constraint, matching 000007.
-- It refuses (fails) if two tenants now own the same provider_user_id: collapsing
-- those rows would drop or merge a real identity, so an operator must resolve the
-- duplicates first. Both drops keep a re-run, or an index left by an earlier
-- down, from colliding with the constraint name.
ALTER TABLE oauth_accounts DROP CONSTRAINT IF EXISTS uq_oauth_accounts_provider_uid;
DROP INDEX IF EXISTS uq_oauth_accounts_provider_uid;
ALTER TABLE oauth_accounts ADD CONSTRAINT uq_oauth_accounts_provider_uid
    UNIQUE (provider_id, provider_user_id);

DROP INDEX IF EXISTS uq_oauth_accounts_provider_tenant_uid;

-- Dropping the column discards the stored tenant scope. It is not recoverable
-- from provider_user_id, so a re-applied up migration cannot rebuild it.
ALTER TABLE oauth_accounts DROP COLUMN IF EXISTS provider_tenant_id;
