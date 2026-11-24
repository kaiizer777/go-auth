# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `oauth_accounts.verified` records whether the provider attested the linked
  identity. Migration 000009 backfills it `TRUE` where the owning account's
  email was already verified locally and `FALSE` everywhere else, so links on
  existing verified accounts keep working after the upgrade.
- Facebook `assert_email_verified` (default `false`) declares that a non-empty
  Graph email is trustworthy. Without it the address is stored as unverified.

### Changed

- An unverified OAuth link signs in only the account it was created on, and only
  until that account holds a password or a verified address. It can never merge
  into another account, recover access, or resolve an account by email, and it is
  deleted once the account is claimed.
- `?link=true` now requires the target account to be claimed with a password or
  a verified email before a provider identity can be attached to it.

