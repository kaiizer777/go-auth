# **Go-Auth** — A composable, modular authentication library for Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/kaiizer777/go-auth.svg)](https://pkg.go.dev/github.com/kaiizer777/go-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/kaiizer777/go-auth)](https://goreportcard.com/report/github.com/kaiizer777/go-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [!WARNING]
> **Status: Early development —**
> APIs and interfaces are undergoing initial design and scaffolding.

---

## Project Structure

`go-auth` strictly enforces separation between the public API facade and internal subsystem logic.

```
go-auth/
├── goauth.go                         # Root facade (New, Config entrypoint only)
├── session/                          # Session lifecycle & cookie handling
├── crypto/                           # Hashing, token generation & constant-time crypto
├── schema/                           # Domain models & database schema types
├── oauth/                            # OAuth2 & OIDC core logic
│   └── providers/                    # Individual OAuth provider implementations
├── ratelimit/                        # Rate limiting interfaces & implementations
├── adapters/
│   └── sql/                          # SQL database adapter (Postgres, MySQL, SQLite)
├── plugins/
│   └── credential-password/          # Email/Password authentication plugin
├── examples/
│   └── basic-nethttp/                # Standard net/http integration example
└── docs/                             # Project documentation
```

### Why this layout?
1. **Zero Logic in Root**: The project root only contains `goauth.go`, serving as the clean public entry point. This eliminates package circular dependencies and prevents the root package from becoming an unmaintainable catch-all.
2. **Modular Subpackages**: Callers can import specific subsystems or plug custom implementations (e.g. custom database adapters or rate limiters) adhering to cleanly separated interfaces.

### Store Interfaces & Custom Adapters

`go-auth` exposes interfaces in `db/store.go` (`UserStore`, `SessionStore`, `OAuthAccountStore`, `VerificationTokenStore`, `PasswordResetTokenStore`, `TotpStore`).

> [!NOTE]
> **Breaking Change:** `OAuthAccountStore` includes `UpdateProviderUserID(ctx context.Context, id uuid.UUID, providerUserID string) error`. Custom `OAuthAccountStore` implementations must implement this method to support provider user ID updates (such as migrating legacy Microsoft OIDs to pairwise subjects).

> [!NOTE]
> **Breaking Change:** `OAuthAccountStore.GetByProvider` takes the identity's tenant alongside the provider user ID: `GetByProvider(ctx context.Context, providerID, providerTenantID, providerUserID string)`. A pairwise subject is only unique within the tenant that issued it, so `oauth_accounts` is now uniquely keyed on `(provider_id, provider_tenant_id, provider_user_id)`. Custom implementations must update the signature and the lookup predicate; providers without a tenant namespace pass an empty tenant.

> [!NOTE]
> **Breaking Change:** `OAuthAccountStore` gained `SaveOAuthTokens`, `SaveOAuthTokensCAS`, `SaveOAuthTokensIfUnset`, and `SaveOAuthAccess`, and `oauth.Service` gained `LinkedAccountToken`. Custom implementations must provide them. Provider tokens are persisted only as AES-256-GCM envelopes; with any provider enabled, a missing or malformed `GOAUTH_TOKEN_KEK` keyring stops startup. X defaults to `tweet.read users.read offline.access`.

> [!NOTE]
> **Token keyring:** `GOAUTH_TOKEN_KEK` takes comma-separated `kid:base64key` entries whose keys each decode to 32 bytes (`k1:<base64>,k0:<base64>`). The first entry encrypts new values and every entry can decrypt; there is no plaintext mode and no generated fallback. To rotate, prepend the new key, keep the old one until logins and refreshes have rewritten every affected row, then remove it. There is no `kid` column, so a row still bound to a removed key surfaces only as a decryption error on first use. A dead provider grant (`OAUTH_REAUTH_REQUIRED`) does not invalidate the application session.

> [!NOTE]
> **Behavior Change:** Microsoft identities are stored with their verified tenant: the tenant segment of the `id_token` issuer, which is bound to the configured authority during verification. A token without an `id_token` can only be accepted under an authority that pins one tenant (a tenant GUID, domain, or `consumers`); the multi-tenant `common` and `organizations` authorities cannot prove a tenant from the unsigned `/userinfo` payload and reject the sign-in before the request.

> [!NOTE]
> **Behavior Change:** For Microsoft OAuth, an empty `trusted_tenants` allowlist means no tenant restriction: every tenant the configured authority admits stays trusted, including a pinned single-tenant authority. Configure `trusted_tenants` with tenant IDs or domains to restrict admission; a tenant missing from a non-empty allowlist is marked untrusted, its existing Microsoft link is deleted on its next callback, and the sign-in is refused with `OAUTH_TENANT_INVALID`.

---

## Installation

```bash
# Coming soon
go get github.com/kaiizer777/go-auth
```

---

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, code style, and architectural boundaries.
All contributors are expected to uphold the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
