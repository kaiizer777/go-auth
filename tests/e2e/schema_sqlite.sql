-- SQLite schema for the in-process OAuth e2e stack.
--
-- The embedded migration set (db/migrations) is PostgreSQL-only: 000001 and
-- 000007/000008 run CREATE EXTENSION "uuid-ossp", every table defaults its UUID
-- to uuid_generate_v4(), timestamps are TIMESTAMPTZ, and 000005/000009 rely on
-- ALTER TABLE ... ADD COLUMN IF NOT EXISTS. db.Connect has no sqlite migration
-- branch, so these files cannot be executed by glebarez/sqlite. This file is the
-- single sqlite DDL source for this suite; 000009's oauth_accounts.verified and
-- 000011's oauth_accounts.provider_tenant_id are mirrored here and the Postgres
-- e2e journey exercises the real migration.
--
-- Drift here is silent on its own: a column missing from this file makes
-- SELECT * decode it as a zero value instead of failing, so
-- TestE2E_SQLiteSchemaMatchesModels compares each table's column set with
-- db/models.go.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT COLLATE NOCASE UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    credential_version INTEGER NOT NULL DEFAULT 0,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME,
    updated_at DATETIME
);

CREATE TABLE IF NOT EXISTS oauth_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider_id VARCHAR(32) NOT NULL,
    provider_tenant_id VARCHAR(64) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    access_token_ciphertext TEXT NOT NULL DEFAULT '',
    refresh_token_ciphertext TEXT NOT NULL DEFAULT '',
    refresh_token_fingerprint CHAR(64) NOT NULL DEFAULT '',
    token_expires_at DATETIME,
    token_scope TEXT NOT NULL DEFAULT '',
    created_at DATETIME,
    updated_at DATETIME,
    CONSTRAINT uq_oauth_accounts_provider_tenant_uid UNIQUE (provider_id, provider_tenant_id, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS verification_tokens (
    token_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    id_hash CHAR(64) UNIQUE NOT NULL,
    session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    credential_version INTEGER NOT NULL DEFAULT 0,
    last_active_at DATETIME NOT NULL,
    absolute_expires_at DATETIME NOT NULL,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS totp_secrets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    encrypted_secret BLOB NOT NULL,
    backup_codes BLOB NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME,
    updated_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS totp_used_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    code_hash BLOB NOT NULL,
    used_at DATETIME NOT NULL,
    CONSTRAINT uq_totp_used_codes_user_code UNIQUE (user_id, code_hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS two_factor_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash BLOB UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
