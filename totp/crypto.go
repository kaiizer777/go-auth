package totp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/png"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	ptotp "github.com/pquerna/otp/totp"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/errors"
)

// secretKeyField is the stable AAD field binding a sealed secret to the
// totp_secrets.encrypted_secret column.
const secretKeyField = "encrypted_secret"

// Crypto seals TOTP secrets through the shared crypto envelope, and provides
// RFC 6238 TOTP generation and verification helpers.
type Crypto struct {
	sealer *crypto.SecretSealer
}

// NewCrypto builds the secret sealer from cfg. The ring is cfg.Keyring followed
// by the hex EncryptionKey under kid "legacy": the first entry encrypts, every
// entry decrypts.
func NewCrypto(cfg config.TOTPConfig) (*Crypto, error) {
	ring, err := parseTOTPKeyring(cfg)
	if err != nil {
		return nil, err
	}
	return &Crypto{sealer: crypto.NewSecretSealer(ring)}, nil
}

func parseTOTPKeyring(cfg config.TOTPConfig) (*crypto.Keyring, error) {
	spec, err := cfg.KeyringSpec()
	if err != nil {
		return nil, err
	}
	if spec == "" {
		return nil, errors.ErrTOTPEncryptionKeyInvalid
	}

	ring, err := crypto.ParseKeyring(spec)
	if err != nil {
		return nil, errors.ErrTOTPKeyringInvalid
	}
	return ring, nil
}

// ActiveKeyID returns the kid new secrets are sealed under.
func (c *Crypto) ActiveKeyID() string {
	if c == nil {
		return ""
	}
	return c.sealer.ActiveKeyID()
}

// Encrypt seals plaintext for its owner. It only ever writes the envelope
// format, bound to ownerID and the encrypted_secret field.
func (c *Crypto) Encrypt(ownerID uuid.UUID, plaintext []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.ErrTOTPEncryptionKeyInvalid
	}
	return c.sealer.Seal(ownerID.String(), secretKeyField, plaintext)
}

// Decrypt opens a stored secret for its owner, accepting both the envelope
// format and the legacy nonce||ciphertext||tag layout. A legacy row carries no
// AAD, so it still opens for any owner until the rewrap drains it.
func (c *Crypto) Decrypt(ownerID uuid.UUID, blob []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.ErrTOTPEncryptionKeyInvalid
	}
	return c.sealer.Open(ownerID.String(), secretKeyField, blob)
}

// EnvelopeKeyID reports the kid a stored blob is already sealed under. It is
// false for a legacy row, and it never proves the blob decrypts.
func (c *Crypto) EnvelopeKeyID(blob []byte) (string, bool) {
	if c == nil {
		return "", false
	}
	return c.sealer.EnvelopeKeyID(blob)
}

// GenerateKey generates an RFC 6238 compliant base32 TOTP key.
func GenerateKey(issuer, accountName string) (*otp.Key, error) {
	return ptotp.Generate(ptotp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

// GenerateSecret generates an RFC 6238 compliant base32 TOTP secret and otpauth URI.
func GenerateSecret(issuer, accountName string) (secret string, uri string, err error) {
	key, err := GenerateKey(issuer, accountName)
	if err != nil {
		return "", "", fmt.Errorf("totp: failed to generate secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// GenerateQRCodeDataURI generates a PNG QR code data URI from a TOTP key.
func GenerateQRCodeDataURI(key *otp.Key, width, height int) (string, error) {
	img, err := key.Image(width, height)
	if err != nil {
		return "", fmt.Errorf("totp: failed to generate qr image: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("totp: failed to encode qr png: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
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
