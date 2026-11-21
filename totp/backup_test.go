package totp

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/crypto"
)

var codeRegex = regexp.MustCompile("^[A-Z0-9]{8}$")

func init() {
	SetBackupHashParamsForTesting(FastTestHashParams())
}

func TestGenerateBackupCodes(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	if len(codes) != BackupCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), BackupCodeCount)
	}

	seen := make(map[string]bool, len(codes))
	for _, code := range codes {
		if !codeRegex.MatchString(code) {
			t.Errorf("code %q does not match expected format ^[A-Z0-9]{8}$", code)
		}
		if seen[code] {
			t.Errorf("duplicate code generated: %q", code)
		}
		seen[code] = true
	}
}

func TestHashAndVerifyBackupCode(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("failed to generate codes: %v", err)
	}

	storedJSON, err := HashBackupCodes(codes)
	if err != nil {
		t.Fatalf("HashBackupCodes failed: %v", err)
	}

	// Verify candidate code matches
	targetCode := codes[3]
	updatedJSON, matched, err := VerifyAndConsumeBackupCode(storedJSON, targetCode)
	if err != nil {
		t.Fatalf("unexpected verification error: %v", err)
	}
	if !matched {
		t.Fatalf("expected code %q to match", targetCode)
	}
	if len(updatedJSON) == 0 {
		t.Fatal("expected non-empty updated JSON")
	}

	// Unmarshal updated JSON and verify length is 9
	var remaining []string
	if err := json.Unmarshal(updatedJSON, &remaining); err != nil {
		t.Fatalf("failed to unmarshal updated JSON: %v", err)
	}
	if len(remaining) != BackupCodeCount-1 {
		t.Fatalf("got %d remaining codes, want %d", len(remaining), BackupCodeCount-1)
	}
}

func TestVerifyBackupCodeWrong(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("failed to generate codes: %v", err)
	}

	storedJSON, err := HashBackupCodes(codes)
	if err != nil {
		t.Fatalf("HashBackupCodes failed: %v", err)
	}

	// Candidate code that was not generated
	updatedJSON, matched, err := VerifyAndConsumeBackupCode(storedJSON, "ZZZZ9999")
	if err != nil {
		t.Fatalf("unexpected error for wrong code: %v", err)
	}
	if matched {
		t.Fatal("wrong code matched unexpectedly")
	}
	if updatedJSON != nil {
		t.Errorf("expected nil updatedJSON on mismatch, got %s", updatedJSON)
	}
}

func TestVerifyBackupCode_InvalidFormat(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("failed to generate codes: %v", err)
	}

	storedJSON, err := HashBackupCodes(codes)
	if err != nil {
		t.Fatalf("HashBackupCodes failed: %v", err)
	}

	invalidCodes := []string{
		"",
		"   ",
		"ABC",
		"1234567",
		"123456789",
		"ABCDEFGH123",
		"ABCD!234",
		"ABCD-123",
		"ABCD 123",
		"@@@@@@@@",
	}

	for _, invalid := range invalidCodes {
		updated, matched, err := VerifyAndConsumeBackupCode(storedJSON, invalid)
		if err != nil {
			t.Errorf("expected nil error for invalid format %q, got: %v", invalid, err)
		}
		if matched {
			t.Errorf("invalid format %q unexpectedly matched", invalid)
		}
		if updated != nil {
			t.Errorf("expected nil updatedJSON for invalid format %q, got: %s", invalid, updated)
		}
	}
}

func TestVerifyBackupCode_CorruptedHash(t *testing.T) {
	t.Parallel()

	corruptedJSON := []byte(`["$argon2id$v=19$m=65536,t=3,p=4$corrupted$hash"]`)
	updated, matched, err := VerifyAndConsumeBackupCode(corruptedJSON, "ABCD1234")
	if err == nil {
		t.Fatal("expected error for corrupted PHC hash, got nil")
	}
	if matched {
		t.Fatal("matched unexpectedly on corrupted hash")
	}
	if updated != nil {
		t.Errorf("expected nil updatedJSON on error, got: %s", updated)
	}
}

func TestVerifyBackupCode_PaddedAndPositions(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("failed to generate codes: %v", err)
	}

	storedJSON, err := HashBackupCodes(codes)
	if err != nil {
		t.Fatalf("HashBackupCodes failed: %v", err)
	}

	// Match last code (index 9)
	lastCode := codes[len(codes)-1]
	updatedJSON, matched, err := VerifyAndConsumeBackupCode(storedJSON, lastCode)
	if err != nil || !matched {
		t.Fatalf("failed to match last code: err=%v, matched=%v", err, matched)
	}

	// Verify remaining has 9 items
	var remaining []string
	if err := json.Unmarshal(updatedJSON, &remaining); err != nil {
		t.Fatalf("failed to unmarshal remaining: %v", err)
	}
	if len(remaining) != BackupCodeCount-1 {
		t.Fatalf("got %d remaining, want %d", len(remaining), BackupCodeCount-1)
	}

	// Verify dummy hash padding works when remaining < BackupCodeCount
	updatedJSON2, matched2, err := VerifyAndConsumeBackupCode(updatedJSON, codes[0])
	if err != nil || !matched2 {
		t.Fatalf("failed to match first code with padded dummy hashes: err=%v, matched=%v", err, matched2)
	}
	if len(updatedJSON2) == 0 {
		t.Fatal("expected non-empty updatedJSON2")
	}
}

func TestConsumeBackupCodeSingleUse(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("failed to generate codes: %v", err)
	}

	storedJSON, err := HashBackupCodes(codes)
	if err != nil {
		t.Fatalf("HashBackupCodes failed: %v", err)
	}

	codeToConsume := codes[0]

	// First consumption: should succeed
	updatedJSON1, matched1, err := VerifyAndConsumeBackupCode(storedJSON, codeToConsume)
	if err != nil || !matched1 {
		t.Fatalf("first consumption failed: err=%v, matched=%v", err, matched1)
	}

	// Second consumption with same code against updatedJSON: must fail
	updatedJSON2, matched2, err := VerifyAndConsumeBackupCode(updatedJSON1, codeToConsume)
	if err != nil {
		t.Fatalf("unexpected error on second consumption attempt: %v", err)
	}
	if matched2 {
		t.Fatal("consumed backup code was accepted a second time (single-use invariant violated)")
	}
	if updatedJSON2 != nil {
		t.Errorf("expected nil updatedJSON on second attempt, got %s", updatedJSON2)
	}
}

func TestConsumeBackupCodePreservesOthers(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("failed to generate codes: %v", err)
	}

	storedJSON, err := HashBackupCodes(codes)
	if err != nil {
		t.Fatalf("HashBackupCodes failed: %v", err)
	}

	// Consume code 0
	updatedJSON, matched, err := VerifyAndConsumeBackupCode(storedJSON, codes[0])
	if err != nil || !matched {
		t.Fatalf("consumption of code 0 failed: %v", err)
	}

	// Verify remaining array length is 9
	var remaining []string
	if err := json.Unmarshal(updatedJSON, &remaining); err != nil {
		t.Fatalf("failed to unmarshal remaining: %v", err)
	}
	if len(remaining) != BackupCodeCount-1 {
		t.Fatalf("got %d remaining codes, want %d", len(remaining), BackupCodeCount-1)
	}

	// Consumed code 0 must fail on second attempt
	_, matchedAgain, err := VerifyAndConsumeBackupCode(updatedJSON, codes[0])
	if err != nil || matchedAgain {
		t.Fatalf("expected consumed code 0 to not match, matched=%v, err=%v", matchedAgain, err)
	}

	// Spot-check remaining codes at boundary positions (index 1 and last index)
	for _, idx := range []int{1, len(codes) - 1} {
		_, matchedOther, err := VerifyAndConsumeBackupCode(updatedJSON, codes[idx])
		if err != nil {
			t.Fatalf("error checking remaining code %d: %v", idx, err)
		}
		if !matchedOther {
			t.Errorf("remaining code %d (%s) failed to match", idx, codes[idx])
		}
	}
}

func TestConsumeBackupCodeCaseInsensitiveAndTrimmed(t *testing.T) {
	t.Parallel()

	codes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("failed to generate codes: %v", err)
	}

	storedJSON, err := HashBackupCodes(codes)
	if err != nil {
		t.Fatalf("HashBackupCodes failed: %v", err)
	}

	// Pass lowercase and padded input
	candidate := "  " + strings.ToLower(codes[5]) + "  "
	_, matched, err := VerifyAndConsumeBackupCode(storedJSON, candidate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Errorf("lowercase/padded backup code failed to match: %q", candidate)
	}
}

func TestConsumeBackupCodeEmptyJSON(t *testing.T) {
	t.Parallel()

	tests := [][]byte{
		nil,
		{},
		[]byte("[]"),
		[]byte("invalid-json"),
	}

	for _, tc := range tests {
		updated, matched, err := VerifyAndConsumeBackupCode(tc, "ABCD1234")
		if matched {
			t.Errorf("empty/invalid json unexpectedly matched: %s", tc)
		}
		if updated != nil {
			t.Errorf("expected nil updated json, got %s", updated)
		}
		_ = err
	}
}

func TestSetBackupHashParamsForTesting(t *testing.T) {
	initial := getBackupHashParams()

	custom := crypto.HashParams{
		Memory:      19456,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	cleanup := SetBackupHashParamsForTesting(custom)
	defer cleanup()

	params := getBackupHashParams()
	if params.Memory != custom.Memory || params.Time != custom.Time {
		t.Fatalf("expected custom params, got %+v", params)
	}

	dummy := getDummyBackupHash()
	if !strings.HasPrefix(dummy, "$argon2id$") {
		t.Fatalf("expected valid argon2id dummy hash, got %q", dummy)
	}

	cleanup()
	restored := getBackupHashParams()
	if restored != initial {
		t.Fatalf("expected restored initial params %+v, got %+v", initial, restored)
	}
}
