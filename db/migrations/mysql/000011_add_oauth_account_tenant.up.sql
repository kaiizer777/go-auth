-- 000011 tenant-qualifies the OAuth identity key. A Microsoft sub is a pairwise
-- identifier: unique per user, per tenant, per application, not globally. The
-- old (provider_id, provider_user_id) key therefore let one tenant's row block
-- another tenant's identity, or resolve the wrong owner for it.
--
-- provider_tenant_id joins the key and is NOT NULL. There is deliberately no
-- DEFAULT: a writer that forgets the tenant must fail loudly instead of storing
-- an unknown scope that degrades back to the tenant-blind key this migration
-- removes. Providers without a tenant namespace store ''.
--
-- MySQL fills the implicit default into a NOT NULL column added without DEFAULT,
-- so the empty-table requirement is enforced explicitly: a non-empty table aborts
-- before the ALTER instead of backfilling the '' scope. A link whose tenant was
-- never recorded cannot be invented.
--
-- Guard: copying one existing link back into the table collides with the primary
-- key, so it aborts (1062) exactly when the table holds a row and inserts nothing
-- when it is empty. It needs only SELECT and INSERT on oauth_accounts — DML this
-- migration set already runs on the table — so no stored routine, temporary
-- table, or additional grant is required.
--
-- MySQL DDL is not transactional, so the two failure branches recover differently:
--   * Guard aborted (Duplicate entry ... for key 'oauth_accounts.PRIMARY'):
--     nothing was changed; the column is absent and the schema is still 000010.
--     The links block the upgrade by design — their tenant was never recorded.
--     Delete or archive them (owners re-link after the upgrade), then
--     `migrate force 10` and re-run 000011. Do not force 11: 000011 never ran.
--   * Failed after the ALTER (column present): do NOT re-run the ALTER. Check
--     information_schema for oauth_accounts.provider_tenant_id, run the CREATE
--     INDEX and DROP INDEX below by hand, then `migrate force 11`.
INSERT INTO oauth_accounts (id, user_id, provider_id, provider_user_id, email, created_at, updated_at, verified)
SELECT id, user_id, provider_id, provider_user_id, email, created_at, updated_at, verified
FROM oauth_accounts LIMIT 1;

ALTER TABLE oauth_accounts ADD COLUMN provider_tenant_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;

-- Ordering: the replacement index exists before the tenant-blind constraint is
-- dropped, so uniqueness is never unenforced in between.
CREATE UNIQUE INDEX uq_oauth_accounts_provider_tenant_uid ON oauth_accounts (provider_id, provider_tenant_id, provider_user_id);

ALTER TABLE oauth_accounts DROP INDEX uq_oauth_accounts_provider_uid;
