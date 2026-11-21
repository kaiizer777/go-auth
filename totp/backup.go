package totp

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

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

// FastTestHashParams returns reduced Argon2id parameters for quick test execution.
func FastTestHashParams() crypto.HashParams {
	return crypto.HashParams{
		Memory:      19456,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

var (
	backupHashParamsMu sync.RWMutex
	backupHashParams   = crypto.DefaultHashParams()

	dummyBackupHashMu sync.RWMutex
	dummyBackupHash   string
)

// SetBackupHashParamsForTesting sets custom Argon2id parameters for testing and invalidates the cached dummy hash.
// It returns a cleanup function that restores previous parameters.
func SetBackupHashParamsForTesting(params crypto.HashParams) func() {
	backupHashParamsMu.Lock()
	old := backupHashParams
	backupHashParams = params
	backupHashParamsMu.Unlock()

	dummyBackupHashMu.Lock()
	dummyBackupHash = ""
	dummyBackupHashMu.Unlock()

	return func() {
		backupHashParamsMu.Lock()
		backupHashParams = old
		backupHashParamsMu.Unlock()

		dummyBackupHashMu.Lock()
		dummyBackupHash = ""
		dummyBackupHashMu.Unlock()
	}
}

func getBackupHashParams() crypto.HashParams {
	backupHashParamsMu.RLock()
	defer backupHashParamsMu.RUnlock()
	return backupHashParams
}

// HashBackupCodes hashes each plaintext backup code using Argon2id and marshals the resulting PHC string slice to JSON.
func HashBackupCodes(codes []string) ([]byte, error) {
	hashes := make([]string, len(codes))
	params := getBackupHashParams()
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

func getDummyBackupHash() string {
	dummyBackupHashMu.RLock()
	if dummyBackupHash != "" {
		h := dummyBackupHash
		dummyBackupHashMu.RUnlock()
		return h
	}
	dummyBackupHashMu.RUnlock()

	params := getBackupHashParams()

	dummyBackupHashMu.Lock()
	defer dummyBackupHashMu.Unlock()
	if dummyBackupHash == "" {
		h, err := crypto.GenerateDummyHash(params)
		if err == nil {
			dummyBackupHash = h
		}
	}
	return dummyBackupHash
}

func isValidBackupCodeFormat(code string) bool {
	if len(code) != BackupCodeLength {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
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
	if !isValidBackupCodeFormat(normalized) {
		return nil, false, nil
	}

	matchIndex := -1
	for i, h := range hashes {
		matched, err := crypto.VerifyPassword(normalized, h)
		if err != nil {
			return nil, false, fmt.Errorf("totp: failed to verify backup code hash: %w", err)
		}
		if matched && matchIndex == -1 {
			matchIndex = i
		}
	}

	dummyHash := getDummyBackupHash()
	if dummyHash != "" {
		for i := len(hashes); i < BackupCodeCount; i++ {
			_, _ = crypto.VerifyPassword(normalized, dummyHash)
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
