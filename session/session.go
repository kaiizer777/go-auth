package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// generateRawID creates a cryptographically random 128-bit session ID.
// 16 bytes from crypto/rand -> hex-encoded -> 32-character string.
func generateRawID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: rand.Read: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashID returns the SHA-256 hex digest of rawID.
// Output is always exactly 64 hex characters.
func hashID(rawID string) string {
	sum := sha256.Sum256([]byte(rawID))
	return hex.EncodeToString(sum[:])
}
