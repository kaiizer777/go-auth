# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- `OAuthAccountStore.GetByProvider` now takes the identity's tenant:
  `GetByProvider(ctx context.Context, providerID, providerTenantID, providerUserID string)`.
  External or custom implementations must add the parameter and include
  `provider_tenant_id` in the lookup. `oauth_accounts` is uniquely keyed on
  `(provider_id, provider_tenant_id, provider_user_id)`; the old
  `(provider_id, provider_user_id)` constraint and its Mongo index are removed.
- `OAuthAccountStore.UpdateProviderUserID(ctx context.Context, id uuid.UUID, providerUserID string) error` was added to the `OAuthAccountStore` interface. External or custom implementations of `OAuthAccountStore` must implement this method to support provider user ID updates (such as migrating legacy Microsoft OIDs to pairwise subjects).
- Facebook `graph_version` must be a `v`-prefixed `<major>.<minor>` with no
  leading zeros and a major of at least 19. `19.0`, `v19`, non-numeric forms
  such as `v0x13`, and leading-zero forms such as `v019.0` are rejected during
  config validation and at provider construction: `NewFacebookProviderChecked`
  returns the error, `NewProvider` propagates it, and `NewFacebookProvider`
  panics on an invalid version.
- `db.TotpStore` gained `ListSecretsForRewrap(ctx, afterID, limit)` and
  `UpdateSecretForRewrap(ctx, id, expectedCiphertext, newCiphertext, newKid)` for
  the TOTP rewrap sweep. External or custom store implementations must provide
  both.
- `totp.NewCrypto` now takes `config.TOTPConfig` (so it can build the keyring
  from both key surfaces), `Crypto.Encrypt`/`Crypto.Decrypt` take the owning
  `uuid.UUID`, and `totp.NewCryptoFromBytes` is removed. The stored format is the
  shared envelope; the legacy `nonce||ciphertext||tag` layout is still read.

### Added

- `oauth_accounts.provider_tenant_id` scopes OAuth identities to the tenant that
  issued them, and migration 000011 makes it part of the unique key. A Microsoft
  `sub` is pairwise: unique per user, per tenant, per application, not globally,
  so the same `sub` in two tenants is now two distinct links instead of a
  collision. MongoDB replaces the tenant-blind index at startup.
- `oauth_accounts.verified` records whether the provider attested the linked
  identity. Migration 000009 backfills it `TRUE` where the owning account's
  email was already verified locally and `FALSE` everywhere else, so links on
  existing verified accounts keep working after the upgrade. It deletes no rows.
  MongoDB gets the same backfill from a one-shot startup task (marker
  `schema_migrations/000009_oauth_account_verified`) because the driver path has
  no migration runner.
- Facebook `assert_email_verified` (default `false`) declares that a non-empty
  Graph email is trustworthy. Without it the address is stored as unverified.
- Provider access and refresh tokens are persisted encrypted on every link path.
  Each value is sealed with AES-256-GCM under a keyring key identified by its
  `kid`, and the envelope binds the provider, the account row, and the token
  field as additional authenticated data, so a ciphertext cannot be replayed onto
  another row or field. `oauth_accounts` stores no plaintext token.
- `LinkedAccountToken` returns a linked account's access token and renews an
  expired one on demand. The refresh token never leaves the library; the rotated
  pair is written back with a compare-and-swap on the stored refresh-token
  fingerprint, and concurrent renewals of one account within a process collapse
  into a single provider request.
- X renews a stored grant through `POST /2/oauth2/token` with
  `grant_type=refresh_token` and treats `invalid_grant` as a dead grant. Other
  provider errors keep the stored grant. Providers without refresh support
  report `OAUTH_REFRESH_UNSUPPORTED`.
- TOTP secrets are sealed through the same envelope as OAuth tokens, under a
  distinct AAD label and bound to the owning user id plus the
  `encrypted_secret` field, so a stored secret cannot be transplanted onto
  another user's row or another column. `TOTP.Keyring` adds an optional
  `kid:base64key[,…]` ring; `TOTP.EncryptionKey` is appended to it as a
  decryption-only `legacy` entry, so an unchanged deployment keeps reading its
  rows and rotation only needs a new ring head. Either surface enables TOTP. The
  `legacy` kid is reserved: a keyring that already defines it is rejected by
  configuration validation at startup instead of failing every TOTP operation.
- `totp.RewrapSecrets` rewrites stored secrets onto the active key: keyset-batched,
  idempotent, resumable, one CAS-guarded `UPDATE` per row that writes ciphertext
  and the new `totp_secrets.secret_kid` hint together. It is an explicit call,
  never a startup hook. Migration 000013 adds the hint column; it carries no key
  material, no ciphertext, and no data `UPDATE`. See
  `docs/totp-key-management.md` for the rollout order.

### Changed

- An unverified OAuth link signs in only the account it was created on, and only
  while that account's address is unproven. It can never merge into another
  account, recover access, or resolve an account by email.
- `?link=true` requires the target account to have a locally verified email
  (`users.email_verified`). A password alone no longer qualifies: anyone can set
  one on an unverified address, and a link attached that way outlived the real
  owner's password recovery.
- Setting a password via password-only signup deletes unverified OAuth links while
  leaving the account's email unverified (`users.email_verified = false`), preventing
  unverified third-party links from retaining access.
- Once the address is proven — email verification or a completed password reset
  — the account's unverified OAuth links are deleted and any later callback
  through one is rejected. Attested links are kept. A password reset now also
  marks the address verified, since the reset token was delivered to the mailbox.
- Links that migration 000009 leaves `FALSE` therefore stop working at the
  moment the owner proves the address, not before: until then such a link keeps
  signing in its own account. Residual risk: an unverified link planted through
  the old unvalidated `?link=true` path on an address that was already verified
  locally is backfilled `TRUE` and trusted.
- Microsoft OAuth `trusted_tenants`: an empty allowlist means no tenant
  restriction, so every tenant the configured authority admits stays trusted.
  A non-empty allowlist marks unlisted tenants untrusted: their existing
  Microsoft links are deleted on the next callback and the sign-in is refused
  with `OAUTH_TENANT_INVALID`.
- Microsoft OAuth identities are keyed by their verified tenant. The tenant is
  the issuer segment bound to the configured authority during `id_token`
  verification; every link read, write, and legacy `oid` fallback is scoped to
  it, so one tenant can no longer resolve or block another tenant's identity.
- A Microsoft token without an `id_token` no longer signs in under the
  multi-tenant `common` or `organizations` authorities, with or without an
  allowlist: the unsigned `/userinfo` payload names no tenant, so no
  tenant-qualified key can be formed. Such sign-ins fail before the userinfo
  request. A pinned tenant (GUID or domain) and the `consumers` authority still
  accept this path, keying the identity on the configured tenant.

### Fixed

- X `ExchangeCode` no longer reports success for a 2xx response whose body is an
  RFC 7807 problem document (`application/problem+json`, or a `type`/`title`/
  `detail`/`errors` body with no `access_token`). It returns
  `OAUTH_PROVIDER_ERROR` like the non-2xx path, keeping the upstream detail in
  the cause, and a 2xx body without an `access_token` is now an error instead of
  an empty token (#78).

### Upgrade notes

- `GOAUTH_TOKEN_KEK` (or `OAuth.TokenKEK`) is required whenever a provider is
  configured. Startup fails with an invalid-configuration error when the keyring
  is missing or malformed; there is no plaintext mode and no generated fallback.
- `GOAUTH_TOKEN_KEK` takes comma-separated `kid:base64key` entries, for example
  `k1:<base64 of 32 bytes>,k0:<base64 of 32 bytes>`. A kid is 1-32 characters of
  `[A-Za-z0-9._-]`; each key must decode from strict padded standard base64 to
  exactly 32 bytes. The first entry encrypts new values and every entry can
  decrypt.
- Key rotation: prepend the new entry and keep the old one until every affected
  row has been rewritten by a login or a refresh, then remove the old entry.
  There is no `kid` column, so after removing a key the only signal that a row
  still references it is the decryption error logged the first time that row is
  used.
- A provider that rejects a stored grant clears it and reports
  `OAUTH_REAUTH_REQUIRED`; the user must go through the provider again. The
  application session stays valid: a dead provider grant does not sign the user
  out.
- TOTP rotation is not automatic. Deploy a binary that can read envelopes to the
  whole fleet, verify it, and only then run `totp.RewrapSecrets`. A rewrapped row
  is unreadable to the previous binary, so rolling back after a partial sweep
  locks out the users it already migrated. Migration 000013 is additive and its
  down file drops only the key-id hint, so a rollback of the schema never changes
  a stored secret.

- Migration 000011 adds `oauth_accounts.provider_tenant_id` as `NOT NULL`
  without a default and rolls the unique key over to
  `(provider_id, provider_tenant_id, provider_user_id)`. The column add requires
  an empty `oauth_accounts` table: Postgres rejects a non-empty table because the
  `NOT NULL` column has no default, and MySQL aborts before the `ALTER` rather
  than backfilling the implicit `''` scope. MySQL, two branches: if the
  empty-table guard trips, nothing has been changed — empty the table, then
  `migrate force 10` and re-run 000011 (never force 11, which would record a
  migration that never ran); if it fails after the `ALTER`, do not re-run the
  `ALTER TABLE` — complete the remaining statements by hand and `migrate force
  11`. See the recovery note in the up file.
- Rolling 000011 back splits the same way: if the restored tenant-blind index
  clashes, nothing was changed, so the schema is untouched at 000011 while
  version 10 is recorded dirty — resolve the duplicate identities, then `migrate
  force 11` and re-run the down; if a later statement fails, the rollback is
  nearly complete — finish it by hand and `migrate force 10`. See the recovery
  note in the down file.
- MongoDB has no schema migration: on the first boot of a new schema version it
  refuses an `oauth_accounts` document whose `provider_tenant_id` is missing,
  null, or not a single string (an array that contains a string included),
  because Mongo would index it as `null` or as a multi-key value that no
  tenant-qualified lookup could reach. The verdict is recorded in
  `schema_migrations`, so the scan does not repeat on every start; backfill or
  remove such documents before upgrading.
- MySQL only: if migration 000009 fails between `ALTER TABLE` and the backfill,
  version 9 is recorded dirty with the column present but every row still `0`.
  Do not re-run it. Inspect `oauth_accounts`, run the backfill `UPDATE` from the
  up file by hand, then `migrate force 9`.
