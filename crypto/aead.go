package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/kaiizer777/go-auth/errors"
)

const (
	tokenEnvelopeVersion    = 1
	tokenEnvelopeAlg        = "A256GCM"
	tokenAADLabel           = "goauth.oauth.token/v1"
	refreshFingerprintLabel = "goauth.oauth.refresh-fingerprint/v1"
	accessTokenField        = "access_token"
	refreshTokenField       = "refresh_token"
	gcmNonceSize            = 12
	gcmTagSize              = 16
	maxTokenPlaintext       = 4096
	maxTokenEnvelope        = 8192
)

// Predefined sentinel errors for envelope operations. The texts are the
// observable surface of a public API, so they keep their original wording;
// callers branch on the sentinel, never on the message.
var (
	ErrSealerUnconfigured   = errors.New(errors.CodeInternalError, "token sealer is not configured", nil)
	ErrPlaintextTooLarge    = errors.New(errors.CodeValidationError, "token plaintext exceeds size limit", nil)
	ErrEnvelopeTooLarge     = errors.New(errors.CodeValidationError, "token envelope exceeds size limit", nil)
	ErrEnvelopeMalformed    = errors.New(errors.CodeInternalError, "token envelope is malformed", nil)
	ErrUnknownKeyID         = errors.New(errors.CodeInternalError, "token envelope references an unknown key id", nil)
	ErrAuthenticationFailed = errors.New(errors.CodeInternalError, "token envelope authentication failed", nil)
	ErrSealFailed           = errors.New(errors.CodeInternalError, "token seal failed", nil)
	ErrEmptyRefreshToken    = errors.New(errors.CodeValidationError, "refresh token is empty", nil)
)

// storedEnvelope is the one persisted envelope shape, shared by OAuth tokens and
// owner-bound secrets. The layout is a stored-data contract: do not reorder or
// rename fields.
type storedEnvelope struct {
	Version    int    `json:"v"`
	Alg        string `json:"alg"`
	Kid        string `json:"kid"`
	Nonce      string `json:"n"`
	Ciphertext string `json:"ct"`
}

// envelopeSealer is the single envelope encoder/decoder. label is the domain
// separator baked into the AAD, so an envelope sealed for one domain never
// authenticates in another.
type envelopeSealer struct {
	ring         *Keyring
	label        string
	kind         string
	maxPlaintext int
	maxEnvelope  int
}

// TokenSealer seals and opens OAuth token envelopes under a Keyring.
// The sealer owns the AAD label and field names so callers only supply row identity.
type TokenSealer struct {
	sealer *envelopeSealer
}

// NewTokenSealer returns a sealer bound to ring. A nil or empty ring fails every seal and open.
func NewTokenSealer(ring *Keyring) *TokenSealer {
	return &TokenSealer{sealer: &envelopeSealer{
		ring:         ring,
		label:        tokenAADLabel,
		kind:         "token",
		maxPlaintext: maxTokenPlaintext,
		maxEnvelope:  maxTokenEnvelope,
	}}
}

// SealAccessToken encrypts an access token bound to the given provider and account.
func (s *TokenSealer) SealAccessToken(providerID, accountID, plaintext string) (string, error) {
	return s.seal(accessTokenField, providerID, accountID, plaintext)
}

// OpenAccessToken decrypts an access token bound to the given provider and account.
func (s *TokenSealer) OpenAccessToken(providerID, accountID, envelope string) (string, error) {
	return s.open(accessTokenField, providerID, accountID, envelope)
}

// SealRefreshToken encrypts a refresh token bound to the given provider and account.
func (s *TokenSealer) SealRefreshToken(providerID, accountID, plaintext string) (string, error) {
	return s.seal(refreshTokenField, providerID, accountID, plaintext)
}

// OpenRefreshToken decrypts a refresh token bound to the given provider and account.
func (s *TokenSealer) OpenRefreshToken(providerID, accountID, envelope string) (string, error) {
	return s.open(refreshTokenField, providerID, accountID, envelope)
}

// RefreshTokenFingerprint returns the lowercase hex SHA-256 of the refresh token.
// It is key-independent so that key rotation never invalidates stored fingerprints.
func (s *TokenSealer) RefreshTokenFingerprint(token string) (string, error) {
	if token == "" {
		return "", ErrEmptyRefreshToken
	}

	input := make([]byte, 0, len(refreshFingerprintLabel)+4+len(token))
	input = append(input, refreshFingerprintLabel...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(token)))
	input = append(input, length[:]...)
	input = append(input, token...)
	defer wipeBytes(input)

	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:]), nil
}

func (s *TokenSealer) seal(field, providerID, accountID, plaintext string) (string, error) {
	if s == nil {
		return "", ErrSealerUnconfigured
	}
	plaintextBytes := []byte(plaintext)
	defer wipeBytes(plaintextBytes)
	return s.sealer.seal([]string{providerID, accountID, field}, plaintextBytes)
}

func (s *TokenSealer) open(field, providerID, accountID, envelope string) (string, error) {
	if s == nil {
		return "", ErrSealerUnconfigured
	}
	plaintext, err := s.sealer.open([]string{providerID, accountID, field}, []byte(envelope))
	if err != nil {
		return "", err
	}
	defer wipeBytes(plaintext)
	return string(plaintext), nil
}

func (e *envelopeSealer) seal(components []string, plaintext []byte) (string, error) {
	entry, err := e.active()
	if err != nil {
		return "", err
	}
	if len(plaintext) > e.maxPlaintext {
		return "", errors.New(errors.CodeValidationError,
			fmt.Sprintf("%s plaintext must not exceed %d bytes", e.kind, e.maxPlaintext), ErrPlaintextTooLarge)
	}

	aead, err := newEnvelopeAEAD(entry.key)
	if err != nil {
		return "", ErrSealFailed
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return "", ErrSealFailed
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, envelopeAAD(e.label, entry.kid, components))

	encoded, err := json.Marshal(storedEnvelope{
		Version:    tokenEnvelopeVersion,
		Alg:        tokenEnvelopeAlg,
		Kid:        entry.kid,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return "", ErrSealFailed
	}
	return string(encoded), nil
}

func (e *envelopeSealer) open(components []string, envelope []byte) ([]byte, error) {
	if _, err := e.active(); err != nil {
		return nil, err
	}
	if len(envelope) > e.maxEnvelope {
		return nil, errors.New(errors.CodeValidationError,
			fmt.Sprintf("%s envelope must not exceed %d bytes", e.kind, e.maxEnvelope), ErrEnvelopeTooLarge)
	}

	doc, nonce, ciphertext, ok := parseEnvelope(envelope)
	if !ok {
		return nil, ErrEnvelopeMalformed
	}

	key, ok := e.ring.lookup(doc.Kid)
	if !ok {
		return nil, ErrUnknownKeyID
	}

	aead, err := newEnvelopeAEAD(key)
	if err != nil {
		return nil, ErrEnvelopeMalformed
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, envelopeAAD(e.label, doc.Kid, components))
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

// active returns the key that encrypts new envelopes.
func (e *envelopeSealer) active() (keyringEntry, error) {
	if e == nil {
		return keyringEntry{}, ErrSealerUnconfigured
	}
	entry, ok := e.ring.active()
	if !ok {
		return keyringEntry{}, ErrSealerUnconfigured
	}
	return entry, nil
}

// parseEnvelope validates the envelope structure and decodes its bodies.
// It neither authenticates nor looks keys up, so a structurally valid envelope
// can be inspected without opening it.
func parseEnvelope(raw []byte) (storedEnvelope, []byte, []byte, bool) {
	var doc storedEnvelope
	if err := json.Unmarshal(raw, &doc); err != nil {
		return storedEnvelope{}, nil, nil, false
	}
	if doc.Version != tokenEnvelopeVersion || doc.Alg != tokenEnvelopeAlg || doc.Kid == "" {
		return storedEnvelope{}, nil, nil, false
	}

	// Strict decoding: the stored envelope is a canonical byte string, so a
	// re-encoded body carrying non-zero trailing bits is rejected instead of
	// normalised to the same bytes the way the default decoder does.
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(doc.Nonce)
	if err != nil || len(nonce) != gcmNonceSize {
		return storedEnvelope{}, nil, nil, false
	}

	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(doc.Ciphertext)
	if err != nil || len(ciphertext) < gcmTagSize {
		return storedEnvelope{}, nil, nil, false
	}
	return doc, nonce, ciphertext, true
}

func newEnvelopeAEAD(key keyMaterial) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// envelopeAAD builds the fixed-order length-prefixed additional data:
// label ‖ len(kid) ‖ kid ‖ len(component) ‖ component….
func envelopeAAD(label, kid string, components []string) []byte {
	size := len(label) + 4 + len(kid)
	for _, component := range components {
		size += 4 + len(component)
	}

	aad := make([]byte, 0, size)
	aad = append(aad, label...)
	aad = appendLengthPrefixed(aad, kid)
	for _, component := range components {
		aad = appendLengthPrefixed(aad, component)
	}
	return aad
}

func appendLengthPrefixed(dst []byte, value string) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}
