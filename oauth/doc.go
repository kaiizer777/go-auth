// Package oauth implements the OAuth 2.0 / OpenID Connect login flow for the
// locked Big 3 providers (google, github, apple): authorization URL
// construction with PKCE (RFC 7636 S256 only), a signed single-use state
// cookie, code exchange, profile normalization, and account linking.
//
// State contract: a 32-byte CSPRNG token is signed with HMAC-SHA256 together
// with the PKCE verifier, provider slug, redirect target, and expiry.
// Validation enforces expiry, then provider binding, then single use, and
// clears the cookie before recording consumption, so a replayed callback never
// leaves a live cookie behind.
//
// Linking policy: a provider identity links to an existing account only when
// the provider asserts a verified email that matches a verified local account;
// otherwise the flow creates a verified passwordless user. An identity that is
// already linked resolves its owner without an email, because providers such
// as Apple only return one on first consent.
//
// The consumed-state record is process-local. A multi-replica deployment needs
// sticky routing per in-flight login or an external store; otherwise two
// replicas each accept the same state token once.
package oauth
