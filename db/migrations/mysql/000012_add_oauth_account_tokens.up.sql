-- 000012 adds the encrypted OAuth token envelope. The ciphertext columns hold
-- opaque AES-256-GCM JSON envelopes produced and opened outside this package;
-- nothing here can read them. refresh_token_fingerprint is the hex SHA-256 used
-- to detect a provider-side rotation without opening the envelope.
--
-- token_expires_at is nullable: a link that stores no token has no expiry, and
-- a non-NULL sentinel would render in Go as a real timestamp. A non-pointer
-- time.Time writes year 1, which MySQL DATETIME rejects at insert time.
--
-- MySQL rejects a literal DEFAULT '' on TEXT, so the three TEXT columns are
-- added bare: MySQL backfills the implicit '' into existing rows (the "no token
-- stored" state), and GORM writes the column on every insert.
--
-- MySQL DDL is not transactional and ADD COLUMN has no IF NOT EXISTS here, so a
-- failure partway records version 12 dirty with some columns present. Recovery:
-- do NOT re-run these ALTERs. Check information_schema for oauth_accounts, add
-- only the missing columns by hand, then force version 12 (migrate force 12).
ALTER TABLE oauth_accounts ADD COLUMN access_token_ciphertext TEXT NOT NULL;
ALTER TABLE oauth_accounts ADD COLUMN refresh_token_ciphertext TEXT NOT NULL;
ALTER TABLE oauth_accounts ADD COLUMN refresh_token_fingerprint CHAR(64) NOT NULL DEFAULT '';
ALTER TABLE oauth_accounts ADD COLUMN token_expires_at DATETIME(6) NULL;
ALTER TABLE oauth_accounts ADD COLUMN token_scope TEXT NOT NULL;
