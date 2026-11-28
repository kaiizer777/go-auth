# TOTP secret key management

New TOTP secrets are stored as keyring envelopes:
`{"v":1,"alg":"A256GCM","kid":"…","n":"…","ct":"…"}` sealed with AES-256-GCM
under the active key, bound by additional data to the owning user id and the
fixed field label `encrypted_secret`. An envelope sealed for one user cannot be
opened for another, only the ring entry named by its kid opens it, and an
envelope written for a different domain (an OAuth token, say) never authenticates
here. Rows still in the pre-envelope layout are covered below.

## Configuration

Both fields live under `TOTP`, and either one wires two-factor authentication up.
A surface that is configured but unusable fails closed instead of silently
serving 2FA-less logins (see below).

| Field | Meaning |
|---|---|
| `EncryptionKey` | 64 hex characters (32 bytes). The legacy single key. |
| `Keyring` | `kid:base64key[,kid:base64key…]`, the same grammar as `OAuth.TokenKEK`. The first entry encrypts, every entry decrypts. |

They combine into a single ring at construction: the configured keyring first,
then the hex key under the fixed kid `legacy`. That entry is decryption-only when
a `Keyring` precedes it; with no `Keyring`, it is the ring head and encrypts as
well. Consequences:

- `EncryptionKey` only — the hex key is the ring head, so it encrypts new rows
  and reads every existing row that key sealed.
- `Keyring` + `EncryptionKey` — new writes use the ring head, the old key still
  opens every legacy row it sealed and every row sealed under `legacy`. This is
  the rotation path.
- `Keyring` only - the ring head encrypts. Legacy rows open only while the key
  that sealed them is somewhere in the ring; the sweep below aborts loudly on a
  row it cannot open instead of leaving it behind.

`legacy` is a reserved kid. A `Keyring` that already defines it, combined with a
non-empty `EncryptionKey`, fails configuration validation
(`ErrTOTPKeyringInvalid`) at startup instead of passing and leaving every TOTP
operation unusable. Give the pre-existing key a different kid and list it in
`Keyring` instead. A `Keyring` that defines `legacy` with no `EncryptionKey` set
composes no duplicate and is accepted.

A configured-but-unusable key surface is never a silent "2FA off": the service
is wired, startup logs `totp_crypto_config_invalid`, and every operation that
seals or opens a secret fails closed (status reads need no key). A composed ring
that does not parse, or that defines `legacy` while a non-empty `EncryptionKey`
also joins the ring under that kid, fails `Validate` (`ErrTOTPKeyringInvalid`)
before a config-built service starts.

## Stored format and the legacy read path

Rows written before the envelope existed are `nonce || ciphertext || tag` with no
key id and no additional data. The read path detects the format by parsing, never
by length or first byte: a legacy nonce is random, so roughly 1 in 256 such rows
begins with `{` and is still attempted as a legacy blob once envelope parsing
fails. A blob larger than the 64 KiB parsing budget is refused before either
attempt, so no legacy row that size is readable.

Two gaps follow, and the rewrap closes both:

- **Not bound.** A legacy row carries no additional data, so it opens for any
  user id and any field label.
- **Not kid-authenticated.** No kid records which key sealed a legacy row, so the
  read path cannot check a claimed key id; it tries every ring entry instead.

A legacy row therefore stays readable only while the key that sealed it is still
an entry in the composed ring. Drop that key before the sweep has drained the row
and the row is unrecoverable — which is why the rewrap exists, and why the old key
must stay in the ring until the sweep has rewritten every row only it can open.

That legacy read stays in place until a field deployment has drained its rows with
the sweep; removing it is a follow-up change.

## Rewrapping (key rotation / first rollout of the envelope format)

`totp.RewrapSecrets(ctx, store, cfg, logger)` rewrites every row that is not
sealed under the active key and returns how many rows it changed. It is an
explicit call — there is no startup hook and no config flag.

- **Order matters.** Run it only once every instance of the fleet runs a binary
  that can read envelopes. A rewrapped row is unreadable to an older binary, so
  rolling back after a partial sweep locks out the users it already migrated.
  Deploy the whole fleet first, then rewrap.
- Resumable and idempotent: every row is opened, a readable row already on the
  active kid is skipped without a write, each row commits on its own, and a
  re-run re-opens and skips migrated rows. There is no checkpoint table; the
  data is the progress. Opening before skipping is what keeps a corrupt blob
  that merely claims the active kid from being counted as migrated.
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
in both dialects. The column is a non-authoritative hint, never a format tag and
never consulted on the read path: `''` means unknown, which covers every row
written before the column existed and every row an enrolment writes. The sweep
writes the kid it sealed under in the same statement as the ciphertext, and it
decides whether a row still needs rewriting from the kid inside the envelope, not
from this column. It is deliberately not part of `db.TotpSecret`, so a
down-migrated database (column dropped) keeps serving every read and write; only
the sweep selects the column and fails loudly without it. `000013` contains no
key material, no ciphertext and no data `UPDATE`.
