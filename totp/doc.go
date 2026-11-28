// Package totp implements RFC 6238 TOTP two-factor authentication.
//
// Secrets are sealed through the shared crypto envelope and bound by additional
// data to the owning user id and the `encrypted_secret` field, so an envelope
// only opens for the user and column it was written for. An envelope also names
// the kid that sealed it, and opens only while that key is in the ring.
//
// Rows written before the envelope existed are not covered by either guarantee.
// They carry no additional data, so they are bound to neither owner nor field,
// and no kid, so the key that sealed them is not authenticated - the read path
// tries every ring entry instead. Such a row stays readable only while the key
// that sealed it is still present in the composed ring; drop that key and the
// row is unrecoverable. That is why RewrapSecrets exists, and why the old key
// must stay in the ring until the sweep has drained the rows only it can open.
//
// Rollout order matters. Rewrap only once every instance runs a binary that can
// read envelopes: a rewrapped row is unreadable to an older binary, so rolling
// back after a partial sweep locks out the users it already migrated.
package totp
