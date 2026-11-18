-- 000007 down is fail-closed only when linked OAuth identities exist: dropping
-- oauth_accounts destroys linked OAuth identities, and re-applying the up
-- migration recreates an empty table with no way to restore the links
-- (returning OAuth users would link fresh duplicate rows). Downgrade on a
-- database holding linked accounts requires an explicit offline data migration
-- preserving the rows instead of this file. Unlike the pre-narrowing guard,
-- mere users rows do not block rollback: users survive this down untouched,
-- so a production DB with accounts but no linked OAuth identities stays
-- reversible. Empty databases are lossless (nothing to lose) and stay
-- reversible.
-- recovery: migrate force 7 after a refused down (refusal records version
-- 6 dirty; the script itself rolls back, so force 7 re-pins clean).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM oauth_accounts LIMIT 1) THEN
        RAISE EXCEPTION '000007 down refused: dropping oauth_accounts destroys linked OAuth identities (see file comment)';
    ELSE
        DROP TABLE IF EXISTS oauth_accounts;
    END IF;
END $$;
