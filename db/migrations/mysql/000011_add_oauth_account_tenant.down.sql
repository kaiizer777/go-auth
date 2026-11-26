-- 000011 down restores the tenant-blind key. It refuses (fails) if two tenants
-- now own the same provider_user_id: collapsing those rows would drop or merge
-- a real identity, so an operator must resolve the duplicates first.
--
-- MySQL DDL is not transactional: the CREATE below runs first so a duplicate
-- clash aborts before the tenant-qualified index or column is touched. A failure
-- after it still leaves version 11 dirty; recover by completing the two
-- remaining statements by hand and forcing version 11.
CREATE UNIQUE INDEX uq_oauth_accounts_provider_uid ON oauth_accounts (provider_id, provider_user_id);

ALTER TABLE oauth_accounts DROP INDEX uq_oauth_accounts_provider_tenant_uid;

-- Dropping the column discards the stored tenant scope. It is not recoverable
-- from provider_user_id, so a re-applied up migration cannot rebuild it.
ALTER TABLE oauth_accounts DROP COLUMN provider_tenant_id;
