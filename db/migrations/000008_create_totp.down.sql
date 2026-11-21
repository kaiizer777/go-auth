-- 000008 down is fail-closed only when TOTP secrets exist: dropping
-- totp_secrets destroys enrolled user 2FA credentials and backup codes.
-- Downgrade on a database holding totp_secrets requires an explicit offline
-- data migration preserving the secrets instead of this file. Empty databases
-- are lossless (nothing to lose) and stay reversible.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM totp_secrets LIMIT 1) THEN
        RAISE EXCEPTION '000008 down refused: dropping totp_secrets destroys user TOTP enrollments (see file comment)';
    ELSE
        DROP INDEX IF EXISTS idx_two_factor_tokens_expires_at;
        DROP INDEX IF EXISTS idx_two_factor_tokens_user_id;
        DROP TABLE IF EXISTS two_factor_tokens;

        DROP INDEX IF EXISTS idx_totp_used_codes_user_used_at;
        DROP TABLE IF EXISTS totp_used_codes;

        DROP TABLE IF EXISTS totp_secrets;
    END IF;
END $$;
