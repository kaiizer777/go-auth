-- 000009 down drops the trust flag, not the links. The flag is not restorable:
-- re-applying the up file re-derives it from users.email_verified, so a link the
-- provider attested on an account without a locally verified email comes back
-- 0. Such a link keeps signing in its own account while that address stays
-- unproven, and is deleted once the owner proves it (email verification or
-- password reset). Attested links on verified accounts come back through the
-- backfill unchanged.
ALTER TABLE oauth_accounts DROP COLUMN IF EXISTS verified;
