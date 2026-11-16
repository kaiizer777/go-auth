BEGIN;

-- 000006 down is intentionally a fail-closed no-op, breaking from the
-- destructive convention of earlier downs (e.g. 000005): credential_version
-- is security state, not just schema. Dropping these columns and re-applying
-- the up migration would reset every row to DEFAULT 0, making previously
-- revoked (version-mismatched) sessions validate again. Down+up on a
-- data-bearing database is therefore unsafe; downgrade requires an explicit
-- offline data migration preserving per-row versions instead of this file.
DO $$ BEGIN
    RAISE EXCEPTION '000006 down refused: dropping credential_version resurrects revoked sessions (see file comment)';
END $$;

COMMIT;
