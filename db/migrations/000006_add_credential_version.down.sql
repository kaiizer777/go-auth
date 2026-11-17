-- 000006 down is fail-closed on data-bearing databases, unlike earlier
-- reversible downs (000005 backfills timestamps before dropping columns):
-- credential_version is security state, not just schema. Dropping these
-- columns and re-applying the up migration would reset every row to
-- DEFAULT 0, making previously revoked (version-mismatched) sessions
-- validate again. Down+up on a database holding non-zero versions is
-- therefore unsafe; downgrade requires an explicit offline data migration
-- preserving per-row versions instead of this file. All-zero databases are
-- lossless (down+up round-trips 0 to 0) and stay reversible.
-- recovery: migrate force 6 after a refused down (refusal records version
-- 5 dirty; the script itself rolls back, so force 6 re-pins clean).
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE credential_version <> 0 LIMIT 1) OR EXISTS (SELECT 1 FROM sessions WHERE credential_version <> 0 LIMIT 1) THEN
        RAISE EXCEPTION '000006 down refused: dropping credential_version resurrects revoked sessions (see file comment)';
    ELSE
        ALTER TABLE users DROP COLUMN IF EXISTS credential_version;
        ALTER TABLE sessions DROP COLUMN IF EXISTS credential_version;
    END IF;
END $$;
