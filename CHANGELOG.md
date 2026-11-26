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

### Upgrade notes

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
