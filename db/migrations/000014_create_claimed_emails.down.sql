-- 000014 down drops the claim table. Nothing is lost that cannot be re-derived:
-- the population is a function of users.email and oauth_accounts.email, so a
-- re-applied up migration rebuilds it.
DROP TABLE IF EXISTS claimed_emails;
