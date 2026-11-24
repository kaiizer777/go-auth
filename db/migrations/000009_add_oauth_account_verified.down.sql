-- 000009 down drops the trust flag, not the links. The flag is not restorable:
-- re-applying the up file re-derives it from users.email_verified, so a link the
-- provider attested on an account without a locally verified email comes back
-- FALSE and its next callback rejects and deletes it. A down/up cycle therefore
-- loses the trust state of those links; only link rows survive it.
ALTER TABLE oauth_accounts DROP COLUMN IF EXISTS verified;
