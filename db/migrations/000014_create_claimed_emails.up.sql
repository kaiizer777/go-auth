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
-- This migration is DDL only: the table ships empty and nothing is imported here.
-- SQL lower() and trim() cannot reproduce db.NormalizeEmail. lower() is
-- collation-dependent (on a C/POSIX database it leaves 'É' unchanged where Go
-- yields 'é') and trim() strips only spaces where strings.TrimSpace also drops
-- tabs and newlines. A row computed in SQL would therefore be stored under a key
-- the application can never produce or match, leaving exactly the race this table
-- closes for the addresses meant to be migrated.
--
-- The import runs from the connection path instead: db.Connect calls
-- db.BackfillClaimedEmails on every connection. It keys with db.NormalizeEmail, is
-- idempotent, and runs all-or-nothing inside one transaction, so a failure commits
-- nothing and the next boot retries. When an address is held by more than one
-- account it aborts before writing, naming every such address instead of picking a
-- winner; the connection then fails on purpose, because starting with an
-- unimported claim table is the unprotected state this migration exists to remove.
-- There is no "already imported" gate: an address written after a run (a restore,
-- or an older instance still serving during a rollout) is picked up by the next
-- connect instead of staying unclaimed forever. Remedy: resolve the links the error
-- names, then reconnect. See docs/email-claims.md.
CREATE TABLE IF NOT EXISTS claimed_emails (
    email          VARCHAR(255) NOT NULL,
    owner_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_claimed_emails_email ON claimed_emails (email);
CREATE INDEX IF NOT EXISTS idx_claimed_emails_owner_user_id ON claimed_emails (owner_user_id);
