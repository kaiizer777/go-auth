// Package providers contains implementations for third-party OAuth2 and OIDC identity providers.
//
// Each provider implementation encapsulates:
//   - Provider-specific authorization, token, and user info endpoints.
//   - Default and configurable OAuth scopes.
//   - Token response parsing and claims extraction (e.g. subject ID, email, name, avatar).
//   - Error translation into canonical domain errors (errors.CodeOAuthProviderError).
package providers
