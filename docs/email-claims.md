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

## Importing existing data

`000014` creates the table empty and nothing imports automatically: booting never
scans the account tables. From the first write after deploy, signup, OAuth
registration and link attachment claim addresses as they go.

An embedder upgrading a database that already contains users or links must run the
import once, after migrating:

```go
if _, err := db.BackfillClaimedEmails(ctx, gormDB); err != nil {
	// resolve the conflicts named in the error, then re-run
}
```

- SQL: `db.BackfillClaimedEmails` pages `users` and `oauth_accounts` by primary
  key (500 rows per page), reads the page's existing claims in one statement, and
  writes each page inside one short transaction. A failed page commits nothing.
  Rows whose address `ClaimKey` rejects are counted in `Skipped`, not imported.
- MongoDB: `mongostore.BackfillClaimedEmails(ctx, database)` is the equivalent
  explicit call. It reads each collection through a cursor with an explicit batch
  size (500 documents per fetch), so cursor buffering is bounded; it is not
  keyset-paged like the SQL one: an existing account costs one read round trip and
  a new one costs three (probe, upsert, re-read). The run also retains the keys it
  inserted so a later conflict can roll them back, so that set grows with the number
  of imported accounts. It writes its own idempotent `$setOnInsert` with
  `verified=false` and promotes in a second pass; it does not call the runtime
  `Claim`, whose `verified` argument carries the caller's attestation. Rows whose
  address `ClaimKey` rejects are skipped; the MongoDB utility returns only an
  error, so the count is reported as `claims_skipped` in its completion log, not to
  the caller. It records the `000014_create_claimed_emails` marker when a run
  completes.

Both key with `db.NormalizeEmail` and are idempotent: re-running after success
changes nothing, and a re-run picks up rows added after the previous run. Neither
is called from `Connect`.

## Conflicts

One address held by more than one account is not resolvable automatically. The
run stops at the page that contains it, before writing that page, and lists every
conflicting address in the page with the competing account IDs:

```
claimed_emails backfill aborted: 1 address(es) held by more than one account:
alice@example.com held by 3f...a1, 8c...02
```

Remedy:

1. Decide which account owns the address.
2. Delete the losing `oauth_accounts` rows (or correct their `email`), or correct
   the offending `users.email` if that is the stale one.
3. Re-run `db.BackfillClaimedEmails`. Pages already imported are a no-op, and the
   run continues from there.
