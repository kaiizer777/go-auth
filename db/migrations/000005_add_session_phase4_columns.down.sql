DROP INDEX IF EXISTS sessions_id_hash_idx;

-- Restore obsolete columns and backfill timestamps from Phase 4 columns before dropping them
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS expires_at      timestamptz,
    ADD COLUMN IF NOT EXISTS idle_expires_at timestamptz;

UPDATE sessions SET
    expires_at = COALESCE(absolute_expires_at, now() + interval '24 hours'),
    idle_expires_at = COALESCE(last_active_at + interval '30 minutes', now() + interval '30 minutes');

ALTER TABLE sessions
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN idle_expires_at SET NOT NULL;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS session_type,
    DROP COLUMN IF EXISTS ip_address,
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS last_active_at,
    DROP COLUMN IF EXISTS absolute_expires_at;

-- Rename id_hash back to token_hash if id_hash exists
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'sessions' AND column_name = 'id_hash'
    ) THEN
        ALTER TABLE sessions RENAME COLUMN id_hash TO token_hash;
        ALTER TABLE sessions ALTER COLUMN token_hash TYPE text;
    END IF;
END $$;

-- Restore unique constraint on token_hash if not present
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'sessions_token_hash_key'
    ) THEN
        ALTER TABLE sessions ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);
    END IF;
END $$;
