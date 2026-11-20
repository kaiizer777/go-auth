DROP INDEX IF EXISTS idx_two_factor_tokens_expires_at;
DROP INDEX IF EXISTS idx_two_factor_tokens_user_id;
DROP TABLE IF EXISTS two_factor_tokens;

DROP INDEX IF EXISTS idx_totp_used_codes_user_used_at;
DROP TABLE IF EXISTS totp_used_codes;

DROP INDEX IF EXISTS idx_totp_secrets_user_id;
DROP TABLE IF EXISTS totp_secrets;
