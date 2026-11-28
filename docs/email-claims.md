# Email claims

`claimed_emails` is the cross-table reservation of an email address. One row per
normalised address, `owner_user_id` records the account holding it, and `verified`
records whether that account proved the mailbox. It exists so a password signup
and an OAuth link cannot both commit the same address: whichever transaction
inserts the claim first wins, and the loser's whole transaction rolls back.

## Keys

The key is `db.NormalizeEmail(email)` (`strings.ToLower(strings.TrimSpace(...))`),
computed in Go on every read and write. No database expression derives it: SQL
`lower()` folds by collation and `trim()` strips only spaces, so a key computed in
SQL is not guaranteed to equal the Go key the application looks up.

## Writes and releases

- Signup, OAuth registration, and OAuth link attachment claim the address inside
  their existing transaction.
- Verifying an email or completing a password reset promotes the claim to
  verified.
- Deleting an account deletes every claim it held (FK cascade on SQL, explicit
  sweep on MongoDB). Deleting a link releases its address only when no other row
  of that account still holds it.

## Claim import at connect

`000014` ships the table empty and contains no data backfill. The import runs from
the connection path instead, identically for both stores, on the first connection
to a database whose claim table is empty:

- SQL: `db.Connect` calls `db.BackfillClaimedEmails` after migrations.
- MongoDB: `mongostore.Connect` runs the equivalent backfill as an init step,
  gated by the `000014_create_claimed_emails` marker in `schema_migrations`.

Both read `users.email` and `oauth_accounts.email`, key with `db.NormalizeEmail`,
and use the same claim write the runtime uses. Running twice is a no-op. SQL has
no per-data-migration marker, so an empty table is the gate: the table is created
empty and only becomes non-empty through a completed import or a write from this
version.

## Conflicts

One address held by more than one account is not resolvable automatically. The
import aborts before writing anything, lists every such address with its competing
account IDs, and the connection fails — the process does not start, so it cannot
run silently without the protection:

```
claimed_emails backfill aborted: 1 address(es) held by more than one account:
alice@example.com held by 3f...a1, 8c...02
```

Remedy:

1. Decide which account owns the address.
2. Delete the losing `oauth_accounts` rows (or correct their `email`), or correct
   the offending `users.email` if that is the stale one.
3. Reconnect. The import re-runs because the table is still empty, and converges.
