-- 000013 down drops the key-id hint only; ciphertext is untouched. Envelopes
-- stay readable through the kid they carry and legacy rows stay readable through
-- the legacy path, so a down-migrated database remains fully usable. Only the
-- rewrap sweep needs this column, and it fails loudly when the column is gone.
--
-- MySQL DDL is not transactional and DROP COLUMN has no IF EXISTS here, so a
-- failure partway records version 13 dirty. Recovery: do NOT re-run this ALTER;
-- check information_schema for totp_secrets.secret_kid, drop it by hand if it is
-- still present, then force version 13 (migrate force 13).
ALTER TABLE totp_secrets DROP COLUMN secret_kid;
