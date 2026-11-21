CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS totp_secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret BYTEA NOT NULL,
    backup_codes JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_totp_secrets_user_id UNIQUE (user_id)
);


CREATE TABLE IF NOT EXISTS totp_used_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    used_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_totp_used_codes_user_code UNIQUE (user_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_totp_used_codes_user_used_at ON totp_used_codes(user_id, used_at);

CREATE TABLE IF NOT EXISTS two_factor_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    CONSTRAINT uq_two_factor_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_two_factor_tokens_user_id ON two_factor_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_two_factor_tokens_expires_at ON two_factor_tokens(expires_at);
