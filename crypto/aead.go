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

// Predefined sentinel errors for token envelope operations.
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

type tokenEnvelope struct {
	Version    int    `json:"v"`
	Alg        string `json:"alg"`
	Kid        string `json:"kid"`
	Nonce      string `json:"n"`
	Ciphertext string `json:"ct"`
}

// TokenSealer seals and opens OAuth token envelopes under a Keyring.
// The sealer owns the AAD label and field names so callers only supply row identity.
type TokenSealer struct {
	keyring *Keyring
}

// NewTokenSealer returns a sealer bound to ring. A nil or empty ring fails every seal and open.
func NewTokenSealer(ring *Keyring) *TokenSealer {
	return &TokenSealer{keyring: ring}
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
	entry, err := s.entry()
	if err != nil {
		return "", err
	}
	if len(plaintext) > maxTokenPlaintext {
		return "", errors.New(errors.CodeValidationError,
			fmt.Sprintf("token plaintext must not exceed %d bytes", maxTokenPlaintext), ErrPlaintextTooLarge)
	}

	aead, err := newTokenAEAD(entry.key)
	if err != nil {
		return "", ErrSealFailed
	}

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return "", ErrSealFailed
	}

	plaintextBytes := []byte(plaintext)
	defer wipeBytes(plaintextBytes)

	ciphertext := aead.Seal(nil, nonce, plaintextBytes, tokenAAD(entry.kid, providerID, accountID, field))

	encoded, err := json.Marshal(tokenEnvelope{
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

func (s *TokenSealer) open(field, providerID, accountID, envelope string) (string, error) {
	if _, err := s.entry(); err != nil {
		return "", err
	}
	if len(envelope) > maxTokenEnvelope {
		return "", errors.New(errors.CodeValidationError,
			fmt.Sprintf("token envelope must not exceed %d bytes", maxTokenEnvelope), ErrEnvelopeTooLarge)
	}

	var doc tokenEnvelope
	if err := json.Unmarshal([]byte(envelope), &doc); err != nil {
		return "", ErrEnvelopeMalformed
	}
	if doc.Version != tokenEnvelopeVersion || doc.Alg != tokenEnvelopeAlg || doc.Kid == "" {
		return "", ErrEnvelopeMalformed
	}

	nonce, err := base64.RawURLEncoding.DecodeString(doc.Nonce)
	if err != nil || len(nonce) != gcmNonceSize {
		return "", ErrEnvelopeMalformed
	}

	key, ok := s.keyring.lookup(doc.Kid)
	if !ok {
		return "", ErrUnknownKeyID
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(doc.Ciphertext)
	if err != nil || len(ciphertext) < gcmTagSize {
		return "", ErrEnvelopeMalformed
	}

	aead, err := newTokenAEAD(key)
	if err != nil {
		return "", ErrEnvelopeMalformed
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, tokenAAD(doc.Kid, providerID, accountID, field))
	if err != nil {
		return "", ErrAuthenticationFailed
	}
	defer wipeBytes(plaintext)
	return string(plaintext), nil
}

func (s *TokenSealer) entry() (keyringEntry, error) {
	if s == nil {
		return keyringEntry{}, ErrSealerUnconfigured
	}
	entry, ok := s.keyring.active()
	if !ok {
		return keyringEntry{}, ErrSealerUnconfigured
	}
	return entry, nil
}

func newTokenAEAD(key keyMaterial) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// tokenAAD builds the fixed-order length-prefixed additional data:
// label ‖ len(kid) ‖ kid ‖ len(providerID) ‖ providerID ‖ len(accountID) ‖ accountID ‖ len(field) ‖ field.
func tokenAAD(kid, providerID, accountID, field string) []byte {
	components := [4]string{kid, providerID, accountID, field}
	size := len(tokenAADLabel)
	for _, component := range components {
		size += 4 + len(component)
	}

	aad := make([]byte, 0, size)
	aad = append(aad, tokenAADLabel...)
	for _, component := range components {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(component)))
		aad = append(aad, length[:]...)
		aad = append(aad, component...)
	}
	return aad
}
