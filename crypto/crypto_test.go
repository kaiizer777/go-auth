package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kaiizer777/go-auth/errors"
)

// fastTestParams returns reduced Argon2 parameters for quick unit test execution.
func fastTestParams() HashParams {
	return HashParams{
		Memory:      19456,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestArgon2HashAndVerify(t *testing.T) {
	params := fastTestParams()
	password := "SecretP@ssw0rd!"

	phc, err := HashPassword(password, params)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(phc, "$argon2id$v=19$") {
		t.Fatalf("unexpected PHC header in %q", phc)
	}

	// Verify valid password
	match, err := VerifyPassword(password, phc)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !match {
		t.Fatalf("expected password to match hash")
	}

	// Verify wrong password
	wrongMatch, err := VerifyPassword("WrongPassword!", phc)
	if err != nil {
		t.Fatalf("VerifyPassword failed on wrong password: %v", err)
	}
	if wrongMatch {
		t.Fatalf("expected wrong password to not match")
	}
}

func TestVerifyPassword_MalformedHashes(t *testing.T) {
	// Base64 encoding of 16 bytes: "c2FsdHNhbHQxNmJ5dGVzIQ" (16 bytes: "saltsalt16bytes!")
	validSaltB64 := "c2FsdHNhbHQxNmJ5dGVzIQ"
	malformed := []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=4$" + validSaltB64 + "$aGFzaA", // argon2i instead of argon2id
		"$argon2id$v=18$m=65536,t=3,p=4$" + validSaltB64 + "$aGFzaA", // unsupported version
		"$argon2id$v=19extra$m=65536,t=3,p=4$" + validSaltB64 + "$aGFzaA", // trailing version chars
		"$argon2id$v=19$badparams$" + validSaltB64 + "$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$invalid-base64!$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$" + validSaltB64 + "$invalid-base64!",
		"$argon2id$v=19$m=65536,t=0,p=4$" + validSaltB64 + "$aGFzaA",  // t=0
		"$argon2id$v=19$m=65536,t=3,p=0$" + validSaltB64 + "$aGFzaA",  // p=0
		"$argon2id$v=19$m=0,t=3,p=4$" + validSaltB64 + "$aGFzaA",      // m=0
		"$argon2id$v=19$m=262145,t=3,p=4$" + validSaltB64 + "$aGFzaA",  // memory > 262144
		"$argon2id$v=19$m=65536,t=11,p=4$" + validSaltB64 + "$aGFzaA",  // time > 10
		"$argon2id$v=19$m=65536,t=3,p=4$" + validSaltB64 + "$",        // empty hash
		"$argon2id$v=19$m=65536,t=3,p=4$$aGFzaA",                      // empty salt
		"bad$argon2id$v=19$m=65536,t=3,p=4$" + validSaltB64 + "$aGFzaA", // no leading $
		"$argon2id$v=19$m=65536,t=3,p=4extra$" + validSaltB64 + "$aGFzaA", // trailing param chars
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",                // salt < 16 bytes ("salt" = 4 bytes)
	}

	for _, hash := range malformed {
		match, err := VerifyPassword("password", hash)
		if match || err == nil {
			t.Errorf("expected error and false for malformed hash %q, got match=%v err=%v", hash, match, err)
		}
	}
}

func TestHashPassword_InvalidParams(t *testing.T) {
	invalidParams := []HashParams{
		{Memory: 0, Time: 3, Parallelism: 4, SaltLength: 16, KeyLength: 32},
		{Memory: 65536, Time: 0, Parallelism: 4, SaltLength: 16, KeyLength: 32},
		{Memory: 65536, Time: 3, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		{Memory: 65536, Time: 3, Parallelism: 4, SaltLength: 0, KeyLength: 32},
		{Memory: 65536, Time: 3, Parallelism: 4, SaltLength: 15, KeyLength: 32},
		{Memory: 65536, Time: 3, Parallelism: 4, SaltLength: 16, KeyLength: 0},
	}

	for _, p := range invalidParams {
		_, err := HashPassword("testpass", p)
		if err == nil {
			t.Errorf("expected error for invalid params %+v, got nil", p)
		}
	}

	// Boundary test: SaltLength 16 passes
	validParams := HashParams{Memory: 19456, Time: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	if _, err := HashPassword("testpass", validParams); err != nil {
		t.Fatalf("expected SaltLength 16 to succeed, got %v", err)
	}
}

func TestGenerateDummyHash(t *testing.T) {
	params := fastTestParams()

	dummy, err := GenerateDummyHash(params)
	if err != nil {
		t.Fatalf("GenerateDummyHash failed: %v", err)
	}

	if !strings.HasPrefix(dummy, "$argon2id$v=19$") {
		t.Fatalf("unexpected dummy PHC header: %q", dummy)
	}

	match, err := VerifyPassword("any-password", dummy)
	if err != nil {
		t.Fatalf("VerifyPassword on dummy hash returned unexpected error: %v", err)
	}
	if match {
		t.Fatalf("dummy hash unexpectedly matched password")
	}
}

func TestGenerateToken(t *testing.T) {
	const count = 1000
	tokens := make(map[string]struct{}, count)

	for i := 0; i < count; i++ {
		rawHex, hash, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken failed: %v", err)
		}

		if len(rawHex) != 64 {
			t.Fatalf("expected 64 hex characters, got %d", len(rawHex))
		}

		if rawHex != strings.ToLower(rawHex) {
			t.Fatalf("expected lowercase hex token, got %q", rawHex)
		}

		rawBytes, err := hex.DecodeString(rawHex)
		if err != nil {
			t.Fatalf("failed to decode hex token: %v", err)
		}

		// Invariant: SHA-256 MUST be of raw 32 bytes, NEVER the hex string
		expectedRawHash := sha256.Sum256(rawBytes)
		if hash != expectedRawHash {
			t.Fatalf("hash != sha256(rawBytes)")
		}

		wrongStringHash := sha256.Sum256([]byte(rawHex))
		if hash == wrongStringHash {
			t.Fatalf("CRITICAL SECURITY INVARIANT VIOLATION: hash is sha256(rawHex) instead of sha256(rawBytes)")
		}

		if _, exists := tokens[rawHex]; exists {
			t.Fatalf("duplicate token generated: collision detected")
		}
		tokens[rawHex] = struct{}{}
	}
}

func TestHashToken(t *testing.T) {
	rawHex, expectedHash, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	computedHash, err := HashToken(rawHex)
	if err != nil {
		t.Fatalf("HashToken failed on valid hex: %v", err)
	}
	if computedHash != expectedHash {
		t.Fatalf("computed hash %x does not match expected hash %x", computedHash, expectedHash)
	}

	// Malformed hex (64 non-hex characters)
	_, err = HashToken(strings.Repeat("z", 64))
	if err == nil {
		t.Fatalf("expected error for non-hex characters")
	}

	// Invalid lengths
	shortHex := strings.Repeat("a", 63)
	_, err = HashToken(shortHex)
	if err == nil {
		t.Fatalf("expected error for short hex token (63 chars)")
	}
	if !errors.Is(err, errors.New(errors.CodeInvalidToken, "", nil)) {
		t.Errorf("expected CodeInvalidToken, got %v", err)
	}

	longHex := strings.Repeat("a", 65)
	_, err = HashToken(longHex)
	if err == nil {
		t.Fatalf("expected error for long hex token (65 chars)")
	}
	if !errors.Is(err, errors.New(errors.CodeInvalidToken, "", nil)) {
		t.Errorf("expected CodeInvalidToken, got %v", err)
	}
}

func TestCommonPasswordBlocklist(t *testing.T) {
	commonSamples := []string{
		"password",
		"12345678",
		"qwertyuiop",
		"admin123",
		"welcome123",
		"iloveyou",
		"sunshine",
	}

	for _, p := range commonSamples {
		if !IsCommonPassword(p) {
			t.Errorf("expected %q to be identified as common password", p)
		}
		// Case insensitive check
		if !IsCommonPassword(strings.ToUpper(p)) {
			t.Errorf("expected uppercase %q to be identified as common password", p)
		}
	}

	uncommonSamples := []string{
		"Tr0ub4dor&3-SecureUniqueKey",
		"xK9#vL2$mQ8!zP4*",
		"Correct-Horse-Battery-Staple-2026",
	}

	for _, p := range uncommonSamples {
		if IsCommonPassword(p) {
			t.Errorf("uncommon password %q was falsely identified as common", p)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		minLen   uint
		maxLen   uint
		wantErr  errors.Code
	}{
		{
			name:     "valid password",
			password: "MySecurePassword2026!",
			minLen:   8,
			maxLen:   128,
			wantErr:  "",
		},
		{
			name:     "password too short",
			password: "short",
			minLen:   8,
			maxLen:   128,
			wantErr:  errors.CodePasswordTooShort,
		},
		{
			name:     "password too long",
			password: strings.Repeat("a", 129),
			minLen:   8,
			maxLen:   128,
			wantErr:  errors.CodePasswordTooLong,
		},
		{
			name:     "password too common",
			password: "password",
			minLen:   8,
			maxLen:   128,
			wantErr:  errors.CodePasswordTooCommon,
		},
		{
			name:     "common password case-insensitive rejection",
			password: "PASSWORD",
			minLen:   8,
			maxLen:   128,
			wantErr:  errors.CodePasswordTooCommon,
		},
		{
			name:     "unicode 8 emoji password valid (ASVS code points, not bytes)",
			password: "🔒🔑🧱💻🎉🚀✨🎯",
			minLen:   8,
			maxLen:   128,
			wantErr:  "",
		},
		{
			name:     "unicode 7 emoji password too short",
			password: "🔒🔑🧱💻🎉🚀✨",
			minLen:   8,
			maxLen:   128,
			wantErr:  errors.CodePasswordTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, tt.minLen, tt.maxLen)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				// Verify rune count vs byte count for unicode test
				if strings.Contains(tt.name, "unicode 8 emoji") {
					runeCount := utf8.RuneCountInString(tt.password)
					byteCount := len(tt.password)
					if runeCount != 8 {
						t.Errorf("expected 8 runes, got %d", runeCount)
					}
					if byteCount <= 8 {
						t.Errorf("expected multi-byte emojis with byteCount > 8, got %d", byteCount)
					}
				}
			} else {
				if err == nil {
					t.Fatalf("expected error code %s, got nil", tt.wantErr)
				}
				var appErr *errors.Error
				if !errors.As(err, &appErr) {
					t.Fatalf("expected *errors.Error, got %T: %v", err, err)
				}
				if appErr.Code() != tt.wantErr {
					t.Errorf("got code %s, want %s", appErr.Code(), tt.wantErr)
				}
			}
		})
	}
}
