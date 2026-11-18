package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

// PKCEChallenge encapsulates the code verifier and its S256 code challenge.
type PKCEChallenge struct {
	Verifier  string // 43-character URL-safe unpadded base64 string
	Challenge string // SHA-256 digest URL-safe unpadded base64 string
	Method    string // Strictly "S256"
}

// GeneratePKCE generates a 32-byte CSPRNG verifier and computes its S256 challenge.
func GeneratePKCE() (*PKCEChallenge, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, ErrOAuthEntropyReadFailed
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)

	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &PKCEChallenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}
