-- 000014 adds the cross-table email claim. Before it, the only objects reserving
-- an address were users(UNIQUE LOWER(email)) and the many-valued
-- oauth_accounts.email, so a password signup and an OAuth link could each commit
-- the same address through a different table. Each write was guarded by a read of
-- the other table, and a read cannot serialise a write. One row per normalised
-- address, inserted inside the writer's transaction, is the lock: the second
-- insert blocks on the unique key and its whole transaction loses.
--
-- The key is db.NormalizeEmail output and is compared byte for byte, so the claim
-- never depends on a database collation: the column carries utf8mb4_bin while the
-- table default stays utf8mb4_unicode_ci. Empty and whitespace-only addresses are
-- never claimed: subject-only provider links store ''.
--
-- verified records that the holder proved the mailbox. An unverified claim is a
-- reservation by an unproved credential, so a provider that attests the address
-- may take the account over; a verified claim cannot be taken over. Existing rows
-- are backfilled as verified only when they can already be trusted: a users row is
-- verified, and a link is verified when the provider attested it.
--
-- Unlike PostgreSQL, the primary key has to exist before the backfill here: it is
-- what aborts a cross-account collision, by rejecting the second row for the key.
-- The error names the address but not both accounts; MySQL cannot raise a custom
-- diagnostic without a stored routine and extra grants, which this migration set
-- does not require.
--
-- Backfill collision policy: abort rather than pick a winner. Electing one silently
-- strips the losing account's address attribution while leaving its rows pointing
-- at an address it does not claim, which is exactly the corruption this table
-- exists to prevent. Deploy stays blocked until an operator deletes the offending
-- links. A key held by one account through several links is not a collision: the
-- GROUP BY collapses it into one row.
--
-- MySQL DDL is not transactional, so a failed run needs manual recovery:
--   * Backfill aborted (Duplicate entry ... for key 'claimed_emails.PRIMARY'):
--     the table exists but is only partially populated. Resolve the duplicate
--     links, `migrate force 13` and re-run 000014; the insert is keyed, so
--     re-running it against the surviving rows converges.
--   * Failed after the backfill: do NOT re-run this file blindly. Check the table,
--     then `migrate force 13` and re-run 000014.
CREATE TABLE IF NOT EXISTS claimed_emails (
    email         VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    owner_user_id VARCHAR(36) NOT NULL,
    verified      TINYINT(1) NOT NULL DEFAULT 0,
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (email),
    CONSTRAINT fk_claimed_emails_owner_user_id FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_claimed_emails_owner_user_id (owner_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- MAX(verified) aggregates the flag per key, never per row, so a key whose only
-- holders are unverified links stays unverified. The GROUP BY also collapses the
-- legitimate multi-provider case into one row.
INSERT INTO claimed_emails (email, owner_user_id, verified)
SELECT h.claim_key, h.owner_user_id, MAX(h.verified)
  FROM (
        SELECT LOWER(TRIM(email)) AS claim_key, id AS owner_user_id, email_verified AS verified
          FROM users
         WHERE TRIM(email) <> ''
        UNION ALL
        SELECT LOWER(TRIM(email)) AS claim_key, user_id, verified
          FROM oauth_accounts
         WHERE TRIM(email) <> ''
       ) h
 GROUP BY h.claim_key, h.owner_user_id;
