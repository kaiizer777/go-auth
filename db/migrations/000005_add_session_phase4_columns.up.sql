BEGIN;

-- 1. Create session_type enum idempotently
DO $$ BEGIN
    CREATE TYPE session_type AS ENUM ('cookie', 'bearer');
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- 2. Rename token_hash to id_hash if token_hash exists
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'sessions' AND column_name = 'token_hash'
    ) THEN
        ALTER TABLE sessions RENAME COLUMN token_hash TO id_hash;
    END IF;
END $$;

-- 3. Adjust id_hash column type to char(64)
ALTER TABLE sessions ALTER COLUMN id_hash TYPE char(64);

-- 4. Drop obsolete NOT NULL timestamp columns from Phase 1 schema
ALTER TABLE sessions
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS idle_expires_at;

-- 5. Add new Phase 4 session columns
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS session_type       session_type NOT NULL DEFAULT 'cookie',
    ADD COLUMN IF NOT EXISTS csrf_token         char(64)     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ip_address         varchar(45)  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_agent         text         NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_active_at     timestamptz  NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS absolute_expires_at timestamptz  NOT NULL DEFAULT now();

-- 6. Ensure unique index on id_hash
CREATE UNIQUE INDEX IF NOT EXISTS sessions_id_hash_idx ON sessions (id_hash);

COMMIT;
