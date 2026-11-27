-- 000012 down drops the stored envelopes, not the links. The tokens are not
-- restorable: a link keeps signing its owner in and simply re-acquires a token
-- the next time the provider grants one. Re-applying the up file restores the
-- columns empty, which is the "no token stored" state.
ALTER TABLE oauth_accounts DROP COLUMN access_token_ciphertext;
ALTER TABLE oauth_accounts DROP COLUMN refresh_token_ciphertext;
ALTER TABLE oauth_accounts DROP COLUMN refresh_token_fingerprint;
ALTER TABLE oauth_accounts DROP COLUMN token_expires_at;
ALTER TABLE oauth_accounts DROP COLUMN token_scope;
