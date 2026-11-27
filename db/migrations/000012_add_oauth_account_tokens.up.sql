-- 000012 adds the encrypted OAuth token envelope. The ciphertext columns hold
-- opaque AES-256-GCM JSON envelopes produced and opened outside this package;
-- nothing here can read them. refresh_token_fingerprint is the hex SHA-256
-- fingerprint of the stored refresh token.
--
-- token_expires_at is nullable: a link that stores no token has no expiry, and
-- a non-NULL sentinel would render in Go as a real timestamp. A non-pointer
-- time.Time writes year 1, which MySQL DATETIME rejects at insert time.
--
-- Existing rows backfill to the empty envelope and stay valid; an empty
-- ciphertext means "no token stored", not a corrupt one.
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS access_token_ciphertext TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS refresh_token_ciphertext TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS refresh_token_fingerprint CHAR(64) NOT NULL DEFAULT '';
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS token_scope TEXT NOT NULL DEFAULT '';
