package totp

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/kaiizer777/go-auth/crypto"
)

const (
	BackupCodeCount   = 10
	BackupCodeLength  = 8
	BackupCodeCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// GenerateBackupCodes generates 10 unique 8-character uppercase alphanumeric backup codes using CSPRNG.
func GenerateBackupCodes() ([]string, error) {
	codes := make([]string, 0, BackupCodeCount)
	seen := make(map[string]bool, BackupCodeCount)
	charsetLen := big.NewInt(int64(len(BackupCodeCharset)))

	for len(codes) < BackupCodeCount {
		var sb strings.Builder
		sb.Grow(BackupCodeLength)
		for i := 0; i < BackupCodeLength; i++ {
			n, err := rand.Int(rand.Reader, charsetLen)
			if err != nil {
				return nil, fmt.Errorf("totp: failed to generate backup code entropy: %w", err)
			}
			sb.WriteByte(BackupCodeCharset[n.Int64()])
		}
		code := sb.String()
		if !seen[code] {
			seen[code] = true
			codes = append(codes, code)
		}
	}
	return codes, nil
}

// HashBackupCodes hashes each plaintext backup code using Argon2id and marshals the resulting PHC string slice to JSON.
func HashBackupCodes(codes []string) ([]byte, error) {
	hashes := make([]string, len(codes))
	params := crypto.DefaultHashParams()
	for i, code := range codes {
		normalized := strings.ToUpper(strings.TrimSpace(code))
		h, err := crypto.HashPassword(normalized, params)
		if err != nil {
			return nil, fmt.Errorf("totp: failed to hash backup code: %w", err)
		}
		hashes[i] = h
	}
	return json.Marshal(hashes)
}

// VerifyAndConsumeBackupCode checks if candidate code matches any hashed backup code in storedJSON.
// If a match is found, the matched code hash is atomically removed and the updated JSON array is returned with matched=true.
// If no code matches, it returns (nil, false, nil).
func VerifyAndConsumeBackupCode(storedJSON []byte, code string) ([]byte, bool, error) {
	if len(storedJSON) == 0 {
		return nil, false, nil
	}

	var hashes []string
	if err := json.Unmarshal(storedJSON, &hashes); err != nil {
		return nil, false, fmt.Errorf("totp: invalid backup codes json: %w", err)
	}

	if len(hashes) == 0 {
		return nil, false, nil
	}

	normalized := strings.ToUpper(strings.TrimSpace(code))
	matchIndex := -1

	for i, h := range hashes {
		matched, err := crypto.VerifyPassword(normalized, h)
		// INVARIANT: Check err == nil && matched. A mismatched password returns false, nil.
		if err == nil && matched {
			matchIndex = i
			break
		}
	}

	if matchIndex == -1 {
		return nil, false, nil
	}

	// Remove consumed backup code hash preserving slice
	updatedHashes := make([]string, 0, len(hashes)-1)
	updatedHashes = append(updatedHashes, hashes[:matchIndex]...)
	updatedHashes = append(updatedHashes, hashes[matchIndex+1:]...)

	updatedJSON, err := json.Marshal(updatedHashes)
	if err != nil {
		return nil, false, fmt.Errorf("totp: failed to marshal updated backup codes: %w", err)
	}

	return updatedJSON, true, nil
}
