# TOTP secret key management

TOTP secrets are stored as keyring envelopes: `{"v":1,"alg":"A256GCM","kid":"…","n":"…","ct":"…"}`
sealed with AES-256-GCM under the active key, bound by additional data to the
owning user id and the fixed field label `encrypted_secret`. A row sealed for
one user cannot be opened for another, and an envelope written for a different
domain (an OAuth token, say) never authenticates here.

## Configuration

Both fields live under `TOTP` and either one enables two-factor authentication:

| Field | Meaning |
|---|---|
| `EncryptionKey` | 64 hex characters (32 bytes). The legacy single key. |
| `Keyring` | `kid:base64key[,kid:base64key…]`, the same grammar as `OAuth.TokenKEK`. The first entry encrypts, every entry decrypts. |

They combine into a single ring at construction: the configured keyring first,
then the hex key appended as a decryption-only entry under the fixed kid
`legacy`. Consequences:

- `EncryptionKey` only — unchanged deployments start and read every existing row.
- `Keyring` + `EncryptionKey` — new writes use the ring head, the old key still
  opens every legacy row and every row sealed under `legacy`. This is the
  rotation path.
- `Keyring` only — the ring head encrypts. Legacy rows open only if the old key
  is included in the ring; the sweep below aborts loudly on a row it cannot
  open instead of leaving it behind.

A configured-but-unusable key surface is never a silent "2FA off": the service
is wired, startup logs `totp_crypto_config_invalid`, and every TOTP operation
fails closed.

## Stored format and the legacy read path

Rows written before the envelope existed are `nonce || ciphertext || tag` with
no key id and no additional data. The read path detects the format by parsing,
never by length or first byte, and opens legacy rows under every ring entry. That
legacy read stays in place until a field deployment has drained its rows with the
sweep; removing it is a follow-up change.

Legacy rows are unbound: because they carry no additional data, a legacy row
still opens for any user id. Rewrapping them is what closes that gap.

## Rewrapping (key rotation / first rollout of the envelope format)

`totp.RewrapSecrets(ctx, store, cfg, logger)` rewrites every row that is not
sealed under the active key and returns how many rows it changed. It is an
explicit call — there is no startup hook and no config flag.

- **Order matters.** Run it only once every instance of the fleet runs a binary
  that can read envelopes. A rewrapped row is unreadable to an older binary, so
  rolling back after a partial sweep locks out the users it already migrated.
  Deploy the whole fleet first, then rewrap.
- Resumable and idempotent: rows already on the active kid are skipped, each row
  commits on its own, and a re-run re-opens and skips migrated rows. There is no
  checkpoint table; the data is the progress.
- Per-row compare-and-swap: the ciphertext and the `secret_kid` hint are written
  by one `UPDATE … WHERE id = ? AND encrypted_secret = ?`. A concurrent
  enrolment that replaces the row makes the swap miss, and the sweep skips that
  row rather than overwriting a newer secret.
- A row no ring key can open aborts the run. That row is a future lockout, so it
  surfaces immediately, together with the number of rows already rewritten and
  the failing owner. Rows the run already migrated stay migrated and readable.

Both enabled and pending enrolments are swept: a pending row is a future login
path.

## Schema

Migration `000013` adds `totp_secrets.secret_kid VARCHAR(32) NOT NULL DEFAULT ''`
in both dialects. The column is a hint and an audit trail, never a format tag and
never read on the read path; `''` means unknown. It is deliberately not part of
`db.TotpSecret`, so a down-migrated database (column dropped) keeps serving every
read and write — only the sweep needs the column, and it fails loudly without it.
`000013` contains no key material, no ciphertext and no data `UPDATE`.
