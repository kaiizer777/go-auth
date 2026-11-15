BEGIN;

-- 1. Rename token_hash to id_hash if token_hash exists
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'sessions' AND column_name = 'token_hash'
    ) THEN
        ALTER TABLE sessions RENAME COLUMN token_hash TO id_hash;
    END IF;
END $$;

-- 2. Adjust id_hash column type to char(64)
ALTER TABLE sessions ALTER COLUMN id_hash TYPE char(64);

-- 4. Drop obsolete NOT NULL timestamp columns from Phase 1 schema
ALTER TABLE sessions
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS idle_expires_at;

-- 5. Add new Phase 4 session columns
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS session_type       varchar(10)  NOT NULL DEFAULT 'cookie' CHECK (session_type IN ('cookie', 'bearer')),
    ADD COLUMN IF NOT EXISTS ip_address         varchar(45)  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_agent         text         NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_active_at     timestamptz  NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS absolute_expires_at timestamptz  NOT NULL DEFAULT now();

-- 6. Ensure exactly one unique index on id_hash: drop legacy constraint if present
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_token_hash_key;
CREATE UNIQUE INDEX IF NOT EXISTS sessions_id_hash_idx ON sessions (id_hash);

COMMIT;
