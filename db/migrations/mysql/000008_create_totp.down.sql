-- 000008 down is fail-closed only when TOTP secrets exist: dropping
-- totp_secrets destroys enrolled user 2FA credentials and backup codes.
-- Downgrade on a database holding totp_secrets requires an explicit offline
-- data migration preserving the secrets instead of this file. Empty databases
-- are lossless (nothing to lose) and stay reversible.
DROP PROCEDURE IF EXISTS fail_if_totp_secrets_exist;
CREATE PROCEDURE fail_if_totp_secrets_exist() BEGIN
    IF EXISTS (SELECT 1 FROM totp_secrets LIMIT 1) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = '000008 down refused: dropping totp_secrets destroys user TOTP enrollments (see file comment)';
    END IF;
END;
CALL fail_if_totp_secrets_exist();
DROP PROCEDURE IF EXISTS fail_if_totp_secrets_exist;

DROP TABLE IF EXISTS two_factor_tokens;
DROP TABLE IF EXISTS totp_used_codes;
DROP TABLE IF EXISTS totp_secrets;
