-- 000013 down drops the key-id hint only; ciphertext is untouched. Envelopes
-- stay readable through the kid they carry and legacy rows stay readable through
-- the legacy path, so a down-migrated database remains fully usable. Only the
-- rewrap sweep needs this column, and it fails loudly when the column is gone.
ALTER TABLE totp_secrets DROP COLUMN IF EXISTS secret_kid;
