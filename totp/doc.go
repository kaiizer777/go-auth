// Package totp implements RFC 6238 TOTP two-factor authentication.
//
// Secrets are sealed through the shared crypto envelope and bound by additional
// data to the owning user id and the `encrypted_secret` field, so an envelope
// only opens for the user and column it was written for. Rows written before the
// envelope existed carry no additional data and no kid, so they still open for
// any owner until RewrapSecrets replaces them.
//
// Rollout order matters. Rewrap only once every instance runs a binary that can
// read envelopes: a rewrapped row is unreadable to an older binary, so rolling
// back after a partial sweep locks out the users it already migrated.
package totp
