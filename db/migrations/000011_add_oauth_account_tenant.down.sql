-- 000011 down restores the tenant-blind key. It refuses (fails) if two tenants
-- now own the same provider_user_id: collapsing those rows would drop or merge
-- a real identity, so an operator must resolve the duplicates first.
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_uid
    ON oauth_accounts(provider_id, provider_user_id);

DROP INDEX IF EXISTS uq_oauth_accounts_provider_tenant_uid;

-- Dropping the column discards the stored tenant scope. It is not recoverable
-- from provider_user_id, so a re-applied up migration cannot rebuild it.
ALTER TABLE oauth_accounts DROP COLUMN IF EXISTS provider_tenant_id;
