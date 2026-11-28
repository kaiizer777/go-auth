package oauthmock

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// GenerateRSAKey creates a 2048-bit RSA private key and returns the key along with base64url-encoded modulus (n) and exponent (e).
func GenerateRSAKey() (*rsa.PrivateKey, string, string, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", "", err
	}
	nRaw := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	eBytes := big.NewInt(int64(privKey.E)).Bytes()
	eRaw := base64.RawURLEncoding.EncodeToString(eBytes)
	return privKey, nRaw, eRaw, nil
}

// BuildJWK builds a JSON Web Key map from an RSA private key.
func BuildJWK(kid, nRaw, eRaw string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   nRaw,
		"e":   eRaw,
	}
}

// SignRS256JWT signs claims using RS256 and the provided private key and kid.
func SignRS256JWT(privKey *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	headerBytes, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": kid,
	})
	if err != nil {
		return "", err
	}

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	hB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	pB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := hB64 + "." + pB64

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
