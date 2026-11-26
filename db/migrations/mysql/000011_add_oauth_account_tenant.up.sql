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
-- MySQL DDL is not transactional and ADD COLUMN has no IF NOT EXISTS here, so a
-- failure after the ALTER records version 11 dirty with the column present but
-- the old constraint still enforcing. Recovery: do NOT re-run the ALTER.
-- Check information_schema for oauth_accounts.provider_tenant_id, then run the
-- CREATE INDEX and DROP INDEX below by hand, then force version 11
-- (migrate force 11) so the migrator stops retrying the ALTER.
DROP PROCEDURE IF EXISTS fail_if_oauth_accounts_not_empty;
CREATE PROCEDURE fail_if_oauth_accounts_not_empty() BEGIN
    IF EXISTS (SELECT 1 FROM oauth_accounts LIMIT 1) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = '000011 refused: oauth_accounts is not empty; provider_tenant_id cannot be invented for existing links';
    END IF;
END;
CALL fail_if_oauth_accounts_not_empty();
DROP PROCEDURE IF EXISTS fail_if_oauth_accounts_not_empty;

ALTER TABLE oauth_accounts ADD COLUMN provider_tenant_id VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL;

-- Ordering: the replacement index exists before the tenant-blind constraint is
-- dropped, so uniqueness is never unenforced in between.
CREATE UNIQUE INDEX uq_oauth_accounts_provider_tenant_uid ON oauth_accounts (provider_id, provider_tenant_id, provider_user_id);

ALTER TABLE oauth_accounts DROP INDEX uq_oauth_accounts_provider_uid;
