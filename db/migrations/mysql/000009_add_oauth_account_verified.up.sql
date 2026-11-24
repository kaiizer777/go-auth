-- 000009 adds the per-link trust flag. Existing rows backfill to 0: the
-- pre-000009 ?link=true route persisted a provider email without checking
-- EmailVerified, so no historical row can be proven provider-attested. An
-- unverified link still signs in the account it was created on; it can never
-- merge, recover, or resolve an account by email.
ALTER TABLE oauth_accounts ADD COLUMN verified TINYINT(1) NOT NULL DEFAULT 0;
