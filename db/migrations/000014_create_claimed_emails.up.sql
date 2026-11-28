-- 000014 adds the cross-table email claim. Before it, the only objects reserving
-- an address were users(UNIQUE LOWER(email)) and the many-valued
-- oauth_accounts.email, so a password signup and an OAuth link could each commit
-- the same address through a different table. Each write was guarded by a read of
-- the other table, and a read cannot serialise a write. One row per normalised
-- address, inserted inside the writer's transaction, is the lock: the second
-- insert blocks on the unique key and its whole transaction loses.
--
-- The key is db.NormalizeEmail output and is compared byte for byte, so the claim
-- never depends on a database collation. Empty and whitespace-only addresses are
-- never claimed: subject-only provider links store ''.
--
-- verified records that the holder proved the mailbox. An unverified claim is a
-- reservation by an unproved credential, so a provider that attests the address
-- may take the account over; a verified claim cannot be taken over.
--
-- This migration is DDL only: it deliberately backfills nothing. SQL lower() and
-- trim() cannot reproduce db.NormalizeEmail. lower() is collation-dependent (on a
-- C/POSIX database it leaves 'É' unchanged where Go yields 'é') and trim() strips
-- only spaces where strings.TrimSpace also drops tabs and newlines. A row computed
-- in SQL would therefore be stored under a key the application can never produce
-- or match, leaving exactly the race this table closes for the addresses meant to
-- be migrated. Importing existing rows is a one-shot Go job instead:
-- gormstore.BackfillClaimedEmails normalises with db.NormalizeEmail, is
-- idempotent, and aborts naming every address held by more than one account
-- rather than picking a winner. No production data existed when 000014 shipped.
CREATE TABLE IF NOT EXISTS claimed_emails (
    email          VARCHAR(255) NOT NULL,
    owner_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_claimed_emails_email ON claimed_emails (email);
CREATE INDEX IF NOT EXISTS idx_claimed_emails_owner_user_id ON claimed_emails (owner_user_id);
