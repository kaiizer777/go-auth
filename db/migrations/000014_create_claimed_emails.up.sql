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
-- may take the account over; a verified claim cannot be taken over. Existing rows
-- are backfilled as verified only when they can already be trusted: a users row
-- is verified, and a link is verified when the provider attested it. An unverified
-- signup therefore keeps an unverified claim, which is the state takeover needs.
--
-- Ordering: populate first, then create the unique index. The populated column is
-- unique by construction, so the index can never be half-applied behind a wrong
-- set of rows.
CREATE TABLE IF NOT EXISTS claimed_emails (
    email          VARCHAR(255) NOT NULL,
    owner_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Backfill collision policy: abort, naming the key and every competing account,
-- when the existing rows already disagree about who owns an address. Electing a
-- winner silently strips the losing account's address attribution while leaving
-- its rows pointing at an address it does not claim, which is exactly the
-- corruption this table exists to prevent. Deploy therefore stays blocked until
-- an operator deletes the offending links. Nothing has been inserted when the
-- exception is raised.
--
-- A key held by one account through several links is not a collision: the
-- legitimate multi-provider case collapses into one claim below.
DO $$
DECLARE
    conflict_key    TEXT;
    conflict_owners TEXT;
BEGIN -- no statement after this line may run once the guard has aborted
    SELECT h.key, string_agg(h.owner_user_id::TEXT, ', ' ORDER BY h.owner_user_id::TEXT)
      INTO conflict_key, conflict_owners
      FROM (
            SELECT LOWER(BTRIM(email)) AS key, id AS owner_user_id
              FROM users
             WHERE BTRIM(email) <> ''
            UNION
            SELECT LOWER(BTRIM(email)) AS key, user_id
              FROM oauth_accounts
             WHERE BTRIM(email) <> ''
           ) h
     GROUP BY h.key
    HAVING COUNT(DISTINCT h.owner_user_id) > 1
     LIMIT 1;

    IF conflict_key IS NOT NULL THEN
        RAISE EXCEPTION 'claimed_emails backfill aborted: % is held by accounts %', conflict_key, conflict_owners;
    END IF;
END
$$;

-- UNION (not UNION ALL) deduplicates the (key, account) pairs, so one account
-- holding the same address on several providers yields one claim row. The
-- verified flag is aggregated per key, never per row, so a key whose only holders
-- are unverified links stays unverified.
INSERT INTO claimed_emails (email, owner_user_id, verified)
SELECT h.key, h.owner_user_id, BOOL_OR(h.verified)
  FROM (
        SELECT LOWER(BTRIM(email)) AS key, id AS owner_user_id, email_verified AS verified
          FROM users
         WHERE BTRIM(email) <> ''
        UNION ALL
        SELECT LOWER(BTRIM(email)) AS key, user_id, verified
          FROM oauth_accounts
         WHERE BTRIM(email) <> ''
       ) h
 GROUP BY h.key, h.owner_user_id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_claimed_emails_email ON claimed_emails (email);
CREATE INDEX IF NOT EXISTS idx_claimed_emails_owner_user_id ON claimed_emails (owner_user_id);
