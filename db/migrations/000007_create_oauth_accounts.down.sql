-- 000007 down is fail-closed on data-bearing databases, mirroring 000006:
-- dropping oauth_accounts destroys linked OAuth identities, and re-applying
-- the up migration recreates an empty table with no way to restore the
-- links (returning OAuth users would link fresh duplicate rows). Downgrade
-- on a database holding users or linked accounts requires an explicit
-- offline data migration preserving the rows instead of this file. Empty
-- databases are lossless (nothing to lose) and stay reversible.
-- recovery: migrate force 7 after a refused down (refusal records version
-- 6 dirty; the script itself rolls back, so force 7 re-pins clean).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM users LIMIT 1) OR EXISTS (SELECT 1 FROM oauth_accounts LIMIT 1) THEN
        RAISE EXCEPTION '000007 down refused: dropping oauth_accounts destroys linked OAuth identities (see file comment)';
    ELSE
        DROP TABLE IF EXISTS oauth_accounts;
    END IF;
END $$;
