# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- `OAuthAccountStore.UpdateProviderUserID(ctx context.Context, id uuid.UUID, providerUserID string) error` was added to the `OAuthAccountStore` interface. External or custom implementations of `OAuthAccountStore` must implement this method to support provider user ID updates (such as migrating legacy Microsoft OIDs to pairwise subjects).

### Added

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

### Upgrade notes

- MySQL only: if migration 000009 fails between `ALTER TABLE` and the backfill,
  version 9 is recorded dirty with the column present but every row still `0`.
  Do not re-run it. Inspect `oauth_accounts`, run the backfill `UPDATE` from the
  up file by hand, then `migrate force 9`.
