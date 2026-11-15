BEGIN;

DROP INDEX IF EXISTS sessions_id_hash_idx;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS session_type,
    DROP COLUMN IF EXISTS csrf_token,
    DROP COLUMN IF EXISTS ip_address,
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS last_active_at,
    DROP COLUMN IF EXISTS absolute_expires_at;

DROP TYPE IF EXISTS session_type;

-- Restore obsolete columns for Phase 1 rollback compatibility
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS expires_at      timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS idle_expires_at timestamptz NOT NULL DEFAULT now();

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

COMMIT;
