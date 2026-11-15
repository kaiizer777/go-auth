package session

import (
	"encoding/hex"
	"net/http"
	"strings"

	apperrors "github.com/kaiizer777/go-auth/errors"
)

// ReadBearerToken extracts the raw session ID from the Authorization header.
// Expected format: "Authorization: Bearer <rawSessionID>"
// Returns ErrSessionNotFound if the Authorization header is absent entirely.
// Returns ErrSessionInvalid if the header is present but malformed, wrong length, or invalid hex.
func ReadBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", apperrors.ErrSessionNotFound
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", apperrors.ErrSessionInvalid
	}

	rawID := strings.TrimSpace(parts[1])
	if rawID == "" {
		return "", apperrors.ErrSessionInvalid
	}

	// Validate format: must be exactly a 32-character hex string (128 bits = 16 bytes hex-encoded)
	if len(rawID) != 32 {
		return "", apperrors.ErrSessionInvalid
	}
	if _, err := hex.DecodeString(rawID); err != nil {
		return "", apperrors.ErrSessionInvalid
	}

	return rawID, nil
}
