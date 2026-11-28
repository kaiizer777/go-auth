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
-- This migration creates the table empty. From the first write after deploy,
-- signup, OAuth registration and link attachment claim addresses inside their own
-- transactions, so the table is complete for every account created by this
-- version.
--
-- Nothing imports existing addresses automatically: booting never scans the
-- account tables. SQL lower() and trim() cannot reproduce db.NormalizeEmail
-- (lower() is collation-dependent; trim() strips only spaces), so a SQL backfill
-- would store keys the application can never match. An embedder upgrading a
-- database that already has users or links must call db.BackfillClaimedEmails
-- once after migrating. It pages users and oauth_accounts by primary key (500 rows
-- per page), writes one short transaction per page, is idempotent and safe to
-- re-run. When an address is held by more than one account it aborts that page
-- before writing, naming every conflicting address and account ID instead of
-- picking a winner; resolve those rows and re-run. See docs/email-claims.md.
CREATE TABLE IF NOT EXISTS claimed_emails (
    email          VARCHAR(255) NOT NULL,
    owner_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_claimed_emails_email ON claimed_emails (email);
CREATE INDEX IF NOT EXISTS idx_claimed_emails_owner_user_id ON claimed_emails (owner_user_id);
