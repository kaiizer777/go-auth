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
-- The table is empty at this point, so the column is added strictly and no
-- backfill is needed; a link whose tenant was never recorded cannot be invented.
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS provider_tenant_id VARCHAR(64) NOT NULL;

-- Ordering: the replacement index exists before the tenant-blind constraint is
-- dropped, so uniqueness is never unenforced in between.
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_accounts_provider_tenant_uid
    ON oauth_accounts(provider_id, provider_tenant_id, provider_user_id);

ALTER TABLE oauth_accounts DROP CONSTRAINT IF EXISTS uq_oauth_accounts_provider_uid;
