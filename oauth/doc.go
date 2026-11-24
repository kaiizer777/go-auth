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
// a verified email with no matching local account creates a verified
// passwordless user. A verified email matching an unverified local account is
// refused with a conflict (pre-hijack defense), and an unverified provider email
// is rejected outright. An identity that is already linked resolves its owner
// without an email, because providers such as Apple only return one on first
// consent.
//
// Link trust: every oauth_accounts row records whether the provider attested the
// address it carries. An unverified link may sign in the account it was created
// on, and only while that account still holds no proven credential; once a
// password signup or reset claims the address the link is deleted and refuses.
// Unverified links never merge, recover, or resolve an account by email, and
// ?link=true cannot persist an unattested address.
//
// Provider compatibility: Provider is unchanged and AuthCodeURLProvider is still
// optional. An OIDCProvider that does not implement it now receives the login
// nonce as a "nonce" query parameter on the URL returned by AuthURL, because the
// callback verifies the ID-token nonce for every OIDC provider. Adapters either
// tolerate the extra parameter (the OAuth 2.0 authorize endpoint ignores unknown
// parameters) or implement AuthCodeURL to control where the nonce is placed.
//
// The consumed-state record is process-local. A multi-replica deployment needs
// sticky routing per in-flight login or an external store; otherwise two
// replicas each accept the same state token once.
package oauth
