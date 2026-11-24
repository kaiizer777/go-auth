-- 000009 adds the per-link trust flag. Backfilling every legacy row to FALSE
-- would lock out existing users: oauth/service.go refuses an unverified link on
-- an account that holds a password, so each of those links would be rejected
-- and deleted on its next callback. Re-derive the flag from the owning account
-- instead. A link on a user whose email is locally verified was created by a
-- signup that mirrored the provider's attestation or by a merge into that
-- verified account, so it keeps signing in, merging, and recovering.
--
-- Every other legacy row backfills FALSE. Those links may predate the
-- attestation check on ?link=true, so the stored provider email proves nothing:
-- the row still signs in the account it was created on, until a password
-- signup or local verification claims that account.
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE oauth_accounts SET verified = TRUE
WHERE EXISTS (
    SELECT 1 FROM users
    WHERE users.id = oauth_accounts.user_id AND users.email_verified
);
