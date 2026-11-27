// Package totp implements RFC 6238 TOTP two-factor authentication.
//
// Secrets are sealed through the shared crypto envelope and bound to their
// owning user id, so a stored row only opens for the user it was written for.
// Rows written before the envelope existed stay readable through a legacy path;
// RewrapSecrets migrates them.
//
// Rollout order matters. Rewrap only once every instance runs a binary that can
// read envelopes: a rewrapped row is unreadable to an older binary, so rolling
// back after a partial sweep locks out the users it already migrated.
package totp
