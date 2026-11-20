package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/pquerna/otp"
	ptotp "github.com/pquerna/otp/totp"

	"github.com/kaiizer777/go-auth/errors"
)

// Crypto provides AES-256-GCM symmetric encryption for TOTP secrets,
// along with RFC 6238 TOTP generation and verification helpers.
type Crypto struct {
	key []byte
}

// NewCrypto creates a new Crypto instance from a 64-character hex-encoded string (32 bytes).
func NewCrypto(hexKey string) (*Crypto, error) {
	if len(hexKey) != 64 {
		return nil, errors.ErrTOTPEncryptionKeyInvalid
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return nil, errors.ErrTOTPEncryptionKeyInvalid
	}
	return &Crypto{key: key}, nil
}

// NewCryptoFromBytes creates a new Crypto instance from a 32-byte AES key.
func NewCryptoFromBytes(key []byte) (*Crypto, error) {
	if len(key) != 32 {
		return nil, errors.ErrTOTPEncryptionKeyInvalid
	}
	k := make([]byte, 32)
	copy(k, key)
	return &Crypto{key: k}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a fresh 12-byte CSPRNG nonce.
// Returns a byte slice formatted as: nonce (12B) || ciphertext || tag (16B).
func (c *Crypto) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("totp: failed to create cipher block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("totp: failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("totp: failed to generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts an AES-256-GCM encrypted blob formatted as: nonce (12B) || ciphertext || tag (16B).
func (c *Crypto) Decrypt(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("totp: failed to create cipher block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("totp: failed to create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, errors.New(errors.CodeInternalError, "totp: ciphertext too short", nil)
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("totp: decryption failed: %w", err)
	}
	return plaintext, nil
}

// GenerateSecret generates an RFC 6238 compliant base32 TOTP secret and otpauth URI.
func GenerateSecret(issuer, accountName string) (secret string, uri string, err error) {
	key, err := ptotp.Generate(ptotp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp: failed to generate secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// ValidateCode validates a 6-digit TOTP code against a base32 secret at the current UTC time with Skew=1.
func ValidateCode(code, secret string) (bool, error) {
	return ValidateCodeAtTime(code, secret, time.Now().UTC())
}

// ValidateCodeAtTime validates a 6-digit TOTP code against a base32 secret at time t with Skew=1 (±30s drift).
func ValidateCodeAtTime(code, secret string, t time.Time) (bool, error) {
	return ptotp.ValidateCustom(code, secret, t, ptotp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// CodeHash calculates a SHA-256 digest of (code + ":" + userID) to prevent cross-user replay attacks.
// It returns the 32-byte raw hash suitable for storage in totp_used_codes.code_hash (BYTEA).
func CodeHash(code, userID string) []byte {
	h := sha256.Sum256([]byte(code + ":" + userID))
	return h[:]
}

// CodeHashString calculates a SHA-256 digest of code and returns the hex-encoded string.
func CodeHashString(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}
