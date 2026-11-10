package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/kaiizer777/go-auth/errors"
)

// HashParams defines the parameters for Argon2id hashing.
type HashParams struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultHashParams returns the RFC 9106 §4 recommended defaults.
func DefaultHashParams() HashParams {
	return HashParams{
		Memory:      65536,
		Time:        3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// ErrInvalidHashFormat is returned when a hash string does not conform to the Argon2id PHC format.
var ErrInvalidHashFormat = errors.New(errors.CodeInternalError, "invalid argon2id hash format", nil)

// HashPassword hashes a plain text password using Argon2id and returns a standard PHC formatted string.
func HashPassword(password string, params HashParams) (string, error) {
	if params.Time < 1 || params.Parallelism < 1 || params.Memory < 1 || params.SaltLength == 0 || params.KeyLength == 0 {
		return "", errors.New(errors.CodeInternalError, "invalid argon2 hash parameters", nil)
	}

	salt := make([]byte, params.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", errors.New(errors.CodeInternalError, "failed to generate crypto salt", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	phc := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Time,
		params.Parallelism,
		b64Salt,
		b64Hash,
	)

	return phc, nil
}

// VerifyPassword verifies a plain text password against an Argon2id PHC formatted hash in constant time.
func VerifyPassword(password, phcHash string) (bool, error) {
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHashFormat
	}

	if parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidHashFormat
	}

	var version int
	if n, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || n != 1 || version != argon2.Version {
		return false, ErrInvalidHashFormat
	}

	var memory, time uint32
	var parallelism uint8
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &parallelism); err != nil || n != 3 {
		return false, ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHashFormat
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHashFormat
	}

	if time < 1 || parallelism < 1 || memory < 1 || len(salt) < 16 || len(expectedHash) == 0 {
		return false, ErrInvalidHashFormat
	}

	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		time,
		memory,
		parallelism,
		uint32(len(expectedHash)),
	)

	match := subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
	return match, nil
}

// GenerateDummyHash generates a valid Argon2id PHC string with a random secret for anti-enumeration timing parity.
func GenerateDummyHash(params HashParams) (string, error) {
	dummySecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dummySecret); err != nil {
		return "", errors.New(errors.CodeInternalError, "failed to generate dummy secret", err)
	}
	return HashPassword(base64.RawStdEncoding.EncodeToString(dummySecret), params)
}
