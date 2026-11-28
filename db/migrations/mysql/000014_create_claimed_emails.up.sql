-- 000014 adds the cross-table email claim. Before it, the only objects reserving
-- an address were users(UNIQUE LOWER(email)) and the many-valued
-- oauth_accounts.email, so a password signup and an OAuth link could each commit
-- the same address through a different table. Each write was guarded by a read of
-- the other table, and a read cannot serialise a write. One row per normalised
-- address, inserted inside the writer's transaction, is the lock: the second
-- insert blocks on the unique key and its whole transaction loses.
--
-- The key is db.NormalizeEmail output, so the claim never depends on case folding
-- by collation: the column carries utf8mb4_bin while the table default stays
-- utf8mb4_unicode_ci. utf8mb4_bin is PAD SPACE, so the primary key ignores
-- trailing spaces and uniqueness relies on NormalizeEmail trimming them. Empty and
-- whitespace-only addresses are never claimed: subject-only provider links store ''.
-- MySQL's collation is not involved in producing the key: the value written is
-- always the Go-normalised string.
--
-- verified records that the holder proved the mailbox. An unverified claim is a
-- reservation by an unproved credential, so a provider that attests the address
-- may take the account over; a verified claim cannot be taken over.
--
-- This migration creates the table empty. From the first write after deploy,
-- signup, OAuth registration and link attachment claim addresses inside their own
-- transactions, so the table is complete for every account created by this
-- version.
--
-- Nothing imports existing addresses automatically: booting never scans the
-- account tables. SQL LOWER() and TRIM() cannot reproduce db.NormalizeEmail
-- (LOWER() folds by collation, TRIM() strips only spaces), so a SQL backfill would
-- store keys the application can never match. An embedder upgrading a database
-- that already has users or links must call db.BackfillClaimedEmails once after
-- migrating. It pages users and oauth_accounts by primary key (500 rows per page),
-- writes one short transaction per page, is idempotent and safe to re-run. When an
-- address is held by more than one account it aborts that page before writing,
-- naming every conflicting address and account ID instead of picking a winner;
-- resolve those rows and re-run. See docs/email-claims.md.
--
-- MySQL DDL is not transactional, so a failed run needs manual recovery:
-- check for claimed_emails, then `migrate force 13` and re-run 000014.
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
