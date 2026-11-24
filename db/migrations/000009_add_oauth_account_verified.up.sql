-- 000009 adds the per-link trust flag. Backfilling every legacy row to FALSE
-- would lock out existing users: oauth/service.go reads verified = FALSE as "the
-- provider never attested this address", rejects such a link on an account whose
-- address is locally verified, and deletes it on that callback. An OAuth-only
-- account holds no password, so it would be left with no login method. Re-derive
-- the flag from the owning account instead.
--
-- What this produces, per owner state:
--
--   users.email_verified = TRUE  -> verified = TRUE. The link keeps signing in,
--     merging, and recovering.
--     RESIDUAL RISK: a link planted through the old unvalidated ?link=true path
--     on a verified-email account is indistinguishable from a legitimate one, so
--     this backfill makes it trusted. The stored provider email proves nothing
--     about who created the row; affected accounts must review their links.
--
--   users.email_verified = FALSE -> verified = FALSE. The link signs in only the
--     account it was created on, and only until that owner proves the address
--     (email verification or password reset), which deletes it. A caller-set
--     password is NOT proof of ownership: it never spends the link and it never
--     authorizes attaching one.
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE oauth_accounts SET verified = TRUE
WHERE EXISTS (
    SELECT 1 FROM users
    WHERE users.id = oauth_accounts.user_id AND users.email_verified
);
