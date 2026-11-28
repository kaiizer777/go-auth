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
-- may take the account over; a verified claim cannot be taken over.
--
-- This migration is DDL only: it deliberately backfills nothing. SQL LOWER() and
-- TRIM() cannot reproduce db.NormalizeEmail. LOWER() folds by collation (here
-- utf8mb4_unicode_ci) and TRIM() strips only spaces where strings.TrimSpace also
-- drops tabs and newlines, so a row computed in SQL would be stored under a key
-- the application can never produce or match and the race would survive for the
-- addresses meant to be migrated. Importing existing rows is a one-shot Go job
-- instead: gormstore.BackfillClaimedEmails normalises with db.NormalizeEmail, is
-- idempotent, and aborts naming every address held by more than one account
-- rather than picking a winner. No production data existed when 000014 shipped.
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
