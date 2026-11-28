-- 000011 down restores the tenant-blind key. It refuses (fails) if two tenants
-- now own the same provider_user_id: collapsing those rows would drop or merge
-- a real identity, so an operator must resolve the duplicates first.
--
-- MySQL DDL is not transactional: the CREATE below runs first so a duplicate
-- clash aborts before the tenant-qualified index or column is touched. migrate
-- records the down target, 10, as dirty before running this file, and MySQL
-- keeps DDL that already committed, so the two branches recover differently:
--   * CREATE aborted (Duplicate entry ... for key
--     oauth_accounts.uq_oauth_accounts_provider_uid): nothing was changed, so
--     the schema is still 000011 while version 10 is recorded dirty. Resolve
--     the duplicate identities, then `migrate force 11` and re-run this down
--     migration.
--   * Failed after the CREATE (tenant-blind index present): do NOT re-run the
--     CREATE. Inspect oauth_accounts, run the remaining statements from this
--     file, in order, by hand, then `migrate force 10`: the rollback is then
--     complete and the schema is back at 000010.
CREATE UNIQUE INDEX uq_oauth_accounts_provider_uid ON oauth_accounts (provider_id, provider_user_id);

ALTER TABLE oauth_accounts DROP INDEX uq_oauth_accounts_provider_tenant_uid;

-- Dropping the column discards the stored tenant scope. It is not recoverable
-- from provider_user_id, so a re-applied up migration cannot rebuild it.
ALTER TABLE oauth_accounts DROP COLUMN provider_tenant_id;
