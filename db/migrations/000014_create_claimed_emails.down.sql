-- 000014 down drops the claim table. The data is re-derivable from users.email
-- and oauth_accounts.email, but it is not restored here: re-applying the up
-- migration creates the table empty. Run db.BackfillClaimedEmails after
-- re-applying 000014 to restore the reservations (see docs/email-claims.md);
-- until then existing accounts have no claims and the takeover safeguards do not
-- apply to them.
DROP TABLE IF EXISTS claimed_emails;
