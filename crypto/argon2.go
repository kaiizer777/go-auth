package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"runtime"
	"strconv"
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

// wipeBytes securely clears sensitive bytes in memory and prevents compiler dead-store elimination.
func wipeBytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// HashPassword hashes a plain text password using Argon2id and returns a standard PHC formatted string.
func HashPassword(password string, params HashParams) (string, error) {
	if params.Time < 1 || params.Parallelism < 1 || params.Memory < 1 || params.SaltLength < 16 || params.KeyLength == 0 {
		return "", errors.New(errors.CodeInternalError, "invalid argon2 hash parameters", nil)
	}

	salt := make([]byte, params.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", errors.New(errors.CodeInternalError, "failed to generate crypto salt", err)
	}

	pwdBytes := []byte(password)
	defer wipeBytes(pwdBytes)

	hash := argon2.IDKey(
		pwdBytes,
		salt,
		params.Time,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)
	defer wipeBytes(hash)

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

	if !strings.HasPrefix(parts[2], "v=") {
		return false, ErrInvalidHashFormat
	}
	vStr := parts[2][2:]
	versionVal, err := strconv.ParseUint(vStr, 10, 32)
	if err != nil || versionVal != argon2.Version || strconv.FormatUint(versionVal, 10) != vStr {
		return false, ErrInvalidHashFormat
	}

	var (
		memory      uint32
		time        uint32
		parallelism uint8
		hasM        bool
		hasT        bool
		hasP        bool
	)

	for _, param := range strings.Split(parts[3], ",") {
		k, v, found := strings.Cut(param, "=")
		if !found || len(v) == 0 {
			return false, ErrInvalidHashFormat
		}
		val, err := strconv.ParseUint(v, 10, 32)
		if err != nil || strconv.FormatUint(val, 10) != v {
			return false, ErrInvalidHashFormat
		}
		switch k {
		case "m":
			if hasM {
				return false, ErrInvalidHashFormat
			}
			hasM = true
			memory = uint32(val)
		case "t":
			if hasT {
				return false, ErrInvalidHashFormat
			}
			hasT = true
			time = uint32(val)
		case "p":
			if hasP || val > 255 {
				return false, ErrInvalidHashFormat
			}
			hasP = true
			parallelism = uint8(val)
		default:
			return false, ErrInvalidHashFormat
		}
	}

	if !hasM || !hasT || !hasP {
		return false, ErrInvalidHashFormat
	}

	if memory > 262144 || time > 10 {
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
	defer wipeBytes(expectedHash)

	if time < 1 || parallelism < 1 || memory < 1 || len(salt) < 16 || len(expectedHash) == 0 {
		return false, ErrInvalidHashFormat
	}

	pwdBytes := []byte(password)
	defer wipeBytes(pwdBytes)

	computedHash := argon2.IDKey(
		pwdBytes,
		salt,
		time,
		memory,
		parallelism,
		uint32(len(expectedHash)),
	)
	defer wipeBytes(computedHash)

	match := subtle.ConstantTimeCompare(computedHash, expectedHash) == 1
	return match, nil
}

// GenerateDummyHash generates a valid Argon2id PHC string with a random secret for anti-enumeration timing parity.
func GenerateDummyHash(params HashParams) (string, error) {
	dummySecret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dummySecret); err != nil {
		return "", errors.New(errors.CodeInternalError, "failed to generate dummy secret", err)
	}
	defer wipeBytes(dummySecret)
	return HashPassword(base64.RawStdEncoding.EncodeToString(dummySecret), params)
}
