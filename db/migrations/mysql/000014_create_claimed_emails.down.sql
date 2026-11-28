-- 000014 down drops the claim table. Nothing is lost that cannot be re-derived:
-- the population is a function of users.email and oauth_accounts.email, so a
-- re-applied up migration rebuilds it.
--
-- MySQL DDL is not transactional, so a failure partway leaves migrate recording
-- the down target, 13, as dirty while the table may or may not still be there.
-- Recovery: check for claimed_emails, drop it by hand if it is still present, then
-- `migrate force 13`.
DROP TABLE IF EXISTS claimed_emails;
