package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/kaiizer777/go-auth/errors"
)

// GenerateToken generates 32 bytes of CSPRNG entropy, returning a 64-character lowercase
// hex string and the SHA-256 digest of the RAW 32 bytes.
func GenerateToken() (rawHex string, hash [32]byte, err error) {
	rawBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, rawBytes); err != nil {
		return "", [32]byte{}, errors.New(errors.CodeInternalError, "failed to generate token entropy", err)
	}

	rawHex = hex.EncodeToString(rawBytes)
	hash = sha256.Sum256(rawBytes)
	return rawHex, hash, nil
}

// HashToken decodes a 64-character hex token and returns the SHA-256 digest of the raw 32 bytes.
func HashToken(rawHex string) ([32]byte, error) {
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return [32]byte{}, errors.New(errors.CodeInvalidToken, "invalid token hex encoding", err)
	}

	if len(rawBytes) != 32 {
		return [32]byte{}, errors.New(errors.CodeInvalidToken, "invalid token length: must be 32 raw bytes (64 hex characters)", nil)
	}

	return sha256.Sum256(rawBytes), nil
}
