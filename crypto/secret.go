package crypto

import "github.com/kaiizer777/go-auth/errors"

const (
	// secretEnvelopeLabel separates secret envelopes from token envelopes: a
	// token pasted into a secret column fails authentication, and vice versa.
	secretEnvelopeLabel = "goauth.totp.secret/v1"
	maxSecretPlaintext  = 1024
	maxSecretEnvelope   = 4096
	// maxSecretBlob bounds how much stored input is inspected for an envelope.
	// It sits far above the largest legacy row this library wrote, so a
	// pre-refactor blob over the envelope cap still reaches the legacy path
	// instead of being refused as an oversized envelope.
	maxSecretBlob = 64 << 10
)

// SecretSealer seals and opens secrets bound to an owning subject and a stable
// field label, under a Keyring. Every sealed value is the shared envelope.
type SecretSealer struct {
	sealer *envelopeSealer
}

// NewSecretSealer returns a sealer bound to ring. A nil or empty ring fails
// every seal and open.
func NewSecretSealer(ring *Keyring) *SecretSealer {
	return &SecretSealer{sealer: &envelopeSealer{
		ring:         ring,
		label:        secretEnvelopeLabel,
		kind:         "secret",
		maxPlaintext: maxSecretPlaintext,
		maxEnvelope:  maxSecretEnvelope,
		maxBlob:      maxSecretBlob,
	}}
}

// Seal encrypts plaintext bound to subject and field. It only ever writes the
// envelope format, under the ring's active key.
func (s *SecretSealer) Seal(subject, field string, plaintext []byte) ([]byte, error) {
	if s == nil || s.sealer == nil {
		return nil, ErrSealerUnconfigured
	}
	envelope, err := s.sealer.seal([]string{subject, field}, plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(envelope), nil
}

// Open decrypts a sealed blob bound to subject and field, accepting both the
// envelope format and the legacy nonce||ciphertext||tag layout that carries no
// kid and no AAD.
//
// Legacy blobs are only distinguished by failing envelope parsing, never by
// length or first byte: a legacy nonce is random, so roughly 1 in 256 legacy
// rows begins with '{'. They are opened under every ring entry, because the
// operator may have parked the old key under any kid.
func (s *SecretSealer) Open(subject, field string, blob []byte) ([]byte, error) {
	if s == nil || s.sealer == nil {
		return nil, ErrSealerUnconfigured
	}
	plaintext, err := s.sealer.open([]string{subject, field}, blob)
	if err == nil {
		return plaintext, nil
	}
	// Only "this is not an envelope" falls back. A well-formed envelope that
	// fails authentication is terminal (a tampered envelope must never downgrade
	// into the unauthenticated legacy path), and an envelope that parses but is
	// over the size cap or names an absent kid is reported as such instead of
	// being masked by the legacy attempt. Legacy blobs were written without a
	// size cap, so only the parse budget refuses one, never the envelope cap.
	if !errors.Is(err, ErrEnvelopeMalformed) {
		return nil, err
	}
	legacy, legacyErr := s.sealer.ring.openLegacy(blob)
	if legacyErr != nil {
		return nil, ErrAuthenticationFailed
	}
	return legacy, nil
}

// EnvelopeKeyID reports the kid recorded in a structurally valid envelope
// without authenticating it. ok is false for a legacy or corrupt blob, so
// callers must not treat a hit as proof of readability.
func (s *SecretSealer) EnvelopeKeyID(blob []byte) (string, bool) {
	if s == nil || s.sealer == nil || len(blob) > maxSecretEnvelope {
		return "", false
	}
	doc, _, _, ok := parseEnvelope(blob)
	if !ok {
		return "", false
	}
	return doc.Kid, true
}

// ActiveKeyID returns the kid Seal writes under, or "" when the ring is unset.
func (s *SecretSealer) ActiveKeyID() string {
	if s == nil || s.sealer == nil {
		return ""
	}
	return s.sealer.ring.ActiveKeyID()
}

// openLegacy opens the pre-envelope nonce||ciphertext||tag layout, trying every
// ring entry. Only package crypto can reach the ring entries.
func (k *Keyring) openLegacy(blob []byte) ([]byte, error) {
	if k == nil || len(k.entries) == 0 {
		return nil, ErrSealerUnconfigured
	}
	if len(blob) < gcmNonceSize+gcmTagSize {
		return nil, ErrAuthenticationFailed
	}

	nonce := blob[:gcmNonceSize]
	ciphertext := blob[gcmNonceSize:]
	for _, entry := range k.entries {
		aead, err := newEnvelopeAEAD(entry.key)
		if err != nil {
			continue
		}
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err == nil {
			return plaintext, nil
		}
	}
	return nil, ErrAuthenticationFailed
}
