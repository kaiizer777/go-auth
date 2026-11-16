// Package oauth implements OAuth2 and OpenID Connect (OIDC) authentication flows
// and third-party identity provider integrations.
//
// Core capabilities:
//   - Authorization URL construction with CSRF state and PKCE (RFC 7636) code challenge.
//   - Callback exchange: validating state, exchanging authorization code for tokens.
//   - User info retrieval and profile normalization into canonical user identity.
//   - Account linking with existing user accounts and prevention of duplicate links
//     (errors.ErrOAuthAccountAlreadyLinked, errors.ErrOAuthAccountNotLinked).
//   - Provider configuration integration via config.OAuthConfig.
package oauth
