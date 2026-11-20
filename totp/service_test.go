package totp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	ptotp "github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/ratelimit"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:mem_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS totp_secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT UNIQUE NOT NULL,
		encrypted_secret BLOB NOT NULL,
		backup_codes TEXT NOT NULL DEFAULT '[]',
		enabled INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS totp_used_codes (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		code_hash BLOB NOT NULL,
		used_at DATETIME NOT NULL,
		CONSTRAINT uq_totp_used_codes_user_code UNIQUE (user_id, code_hash)
	);
	CREATE TABLE IF NOT EXISTS two_factor_tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		token_hash BLOB UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0
	);
	`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	return database
}

func TestNewService_NilDBPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected panic on nil DB, got none")
		}
	}()

	cfg := config.DefaultTOTPConfig()
	_ = NewService(nil, cfg, nil, nil)
}

func TestNewService_Defaults(t *testing.T) {
	t.Parallel()

	db := setupTestDB(t)
	cfg := config.TOTPConfig{
		EncryptionKey: validTestHexKey(),
	}

	svc := NewService(db, cfg, nil, nil)
	concrete, ok := svc.(*totpService)
	if !ok {
		t.Fatalf("expected *totpService, got %T", svc)
	}

	if concrete.cfg.Issuer != "go-auth" {
		t.Errorf("expected default issuer go-auth, got %s", concrete.cfg.Issuer)
	}
	if concrete.cfg.ChallengeTokenTTL != 10*time.Minute {
		t.Errorf("expected default challenge ttl 10m, got %v", concrete.cfg.ChallengeTokenTTL)
	}
	if concrete.cfg.MaxAttemptsPerWindow != 5 {
		t.Errorf("expected default max attempts 5, got %d", concrete.cfg.MaxAttemptsPerWindow)
	}
	if concrete.logger == nil || concrete.logger != slog.Default() {
		t.Errorf("expected default logger slog.Default()")
	}
}

func createTestUser(t *testing.T, database *gorm.DB, email string, verified bool) db.User {
	t.Helper()
	user := db.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  "dummy-hash",
		EmailVerified: verified,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user
}

func TestEnroll_UserNotFound(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	_, err := svc.Enroll(context.Background(), uuid.New().String())
	if !errors.Is(err, apperrors.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestEnroll_EmailNotVerified(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "unverified@example.com", false)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	_, err := svc.Enroll(context.Background(), user.ID.String())
	if !errors.Is(err, apperrors.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}
}

func TestEnroll_SuccessAndPendingOverwrite(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "alice@example.com", true)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	resp1, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if resp1.Secret == "" || resp1.OTPURI == "" || resp1.QRCode == "" {
		t.Fatalf("unexpected empty enrollment response fields: %+v", resp1)
	}

	enabled, err := svc.Status(context.Background(), user.ID.String())
	if err != nil || enabled {
		t.Fatalf("expected enabled=false for pending enrollment, got enabled=%v, err=%v", enabled, err)
	}

	// Idempotent re-enrollment clears previous pending
	resp2, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("re-enrollment failed: %v", err)
	}
	if resp2.Secret == "" {
		t.Fatal("expected non-empty secret on re-enrollment")
	}

	var count int64
	database.Model(&db.TotpSecret{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 totp_secret record, got %d", count)
	}
}

func TestConfirmEnrollment_Lifecycle(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "bob@example.com", true)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	// Confirm without enrollment -> ErrTOTPNotEnrolled
	_, err := svc.ConfirmEnrollment(context.Background(), user.ID.String(), "123456")
	if !errors.Is(err, apperrors.ErrTOTPNotEnrolled) {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
	}

	// Enroll
	resp, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}

	// Invalid code -> ErrTOTPCodeInvalid
	_, err = svc.ConfirmEnrollment(context.Background(), user.ID.String(), "000000")
	if !errors.Is(err, apperrors.ErrTOTPCodeInvalid) {
		t.Fatalf("expected ErrTOTPCodeInvalid, got %v", err)
	}

	// Generate valid code
	validCode, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	backupCodes, err := svc.ConfirmEnrollment(context.Background(), user.ID.String(), validCode)
	if err != nil {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}
	if len(backupCodes) != 10 {
		t.Fatalf("expected 10 backup codes, got %d", len(backupCodes))
	}

	// Status must now be true
	enabled, err := svc.Status(context.Background(), user.ID.String())
	if err != nil || !enabled {
		t.Fatalf("expected enabled=true, got %v, err=%v", enabled, err)
	}

	// Attempt to re-confirm when already enabled -> ErrTOTPAlreadyEnabled
	_, err = svc.ConfirmEnrollment(context.Background(), user.ID.String(), validCode)
	if !errors.Is(err, apperrors.ErrTOTPAlreadyEnabled) {
		t.Fatalf("expected ErrTOTPAlreadyEnabled, got %v", err)
	}

	// Attempt to re-enroll when already enabled -> ErrTOTPAlreadyEnabled
	_, err = svc.Enroll(context.Background(), user.ID.String())
	if !errors.Is(err, apperrors.ErrTOTPAlreadyEnabled) {
		t.Fatalf("expected ErrTOTPAlreadyEnabled, got %v", err)
	}
}

func TestChallengeToken_Lifecycle(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "charlie@example.com", true)
	cfg := config.TOTPConfig{
		EncryptionKey:        validTestHexKey(),
		ChallengeTokenTTL:    5 * time.Minute,
		MaxAttemptsPerWindow: 3,
	}
	svc := NewService(database, cfg, nil, nil)

	rawToken, err := svc.CreateChallengeToken(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("CreateChallengeToken failed: %v", err)
	}
	if len(rawToken) != 64 {
		t.Fatalf("expected 64 hex char token, got len %d", len(rawToken))
	}

	// Non-destructive validation
	tok, err := svc.ValidateChallengeToken(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("ValidateChallengeToken failed: %v", err)
	}
	if tok.UserID != user.ID {
		t.Fatalf("expected token user %s, got %s", user.ID, tok.UserID)
	}
	if tok.Attempts != 0 {
		t.Fatalf("expected 0 attempts, got %d", tok.Attempts)
	}

	// Record attempt
	attempts, err := svc.RecordTokenAttempt(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("RecordTokenAttempt failed: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected attempt 1, got %d", attempts)
	}

	// Validate again: token still present, attempts is 1
	tok2, err := svc.ValidateChallengeToken(context.Background(), rawToken)
	if err != nil || tok2.Attempts != 1 {
		t.Fatalf("expected token attempts=1, got attempts=%d, err=%v", tok2.Attempts, err)
	}

	// Consume token
	consumedUser, err := svc.ConsumeChallengeToken(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("ConsumeChallengeToken failed: %v", err)
	}
	if consumedUser.ID != user.ID {
		t.Fatalf("expected user %s, got %s", user.ID, consumedUser.ID)
	}

	// Subsequent validation must fail because token was hard-deleted
	_, err = svc.ValidateChallengeToken(context.Background(), rawToken)
	if !errors.Is(err, apperrors.ErrTwoFactorTokenInvalid) {
		t.Fatalf("expected ErrTwoFactorTokenInvalid after consume, got %v", err)
	}
}

func TestChallengeToken_Expiry(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "expired@example.com", true)
	cfg := config.TOTPConfig{
		EncryptionKey:        validTestHexKey(),
		ChallengeTokenTTL:    5 * time.Minute,
		MaxAttemptsPerWindow: 3,
	}
	svc := NewService(database, cfg, nil, nil)

	rawToken, err := svc.CreateChallengeToken(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("CreateChallengeToken failed: %v", err)
	}

	// Manually set expiration to past
	if err := database.Model(&db.TwoFactorToken{}).Where("user_id = ?", user.ID).Update("expires_at", time.Now().Add(-1*time.Minute)).Error; err != nil {
		t.Fatalf("failed to update expires_at: %v", err)
	}

	_, err = svc.ValidateChallengeToken(context.Background(), rawToken)
	if !errors.Is(err, apperrors.ErrTwoFactorTokenExpired) {
		t.Fatalf("expected ErrTwoFactorTokenExpired, got %v", err)
	}

	// Subsequent check must return ErrTwoFactorTokenInvalid as token was hard-deleted
	_, err = svc.ValidateChallengeToken(context.Background(), rawToken)
	if !errors.Is(err, apperrors.ErrTwoFactorTokenInvalid) {
		t.Fatalf("expected ErrTwoFactorTokenInvalid, got %v", err)
	}
}

func TestChallengeToken_AttemptExhaustion(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "attempts@example.com", true)
	cfg := config.TOTPConfig{
		EncryptionKey:        validTestHexKey(),
		ChallengeTokenTTL:    5 * time.Minute,
		MaxAttemptsPerWindow: 2,
	}
	svc := NewService(database, cfg, nil, nil)

	rawToken, err := svc.CreateChallengeToken(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("CreateChallengeToken failed: %v", err)
	}

	att1, err := svc.RecordTokenAttempt(context.Background(), rawToken)
	if err != nil || att1 != 1 {
		t.Fatalf("expected att=1, got att=%d, err=%v", att1, err)
	}

	att2, err := svc.RecordTokenAttempt(context.Background(), rawToken)
	if !errors.Is(err, apperrors.ErrTwoFactorMaxAttemptsExceeded) {
		t.Fatalf("expected ErrTwoFactorMaxAttemptsExceeded on reaching max, got %v", err)
	}
	if att2 != 2 {
		t.Fatalf("expected att=2, got %d", att2)
	}

	// Token must have been hard deleted
	_, err = svc.ValidateChallengeToken(context.Background(), rawToken)
	if !errors.Is(err, apperrors.ErrTwoFactorTokenInvalid) {
		t.Fatalf("expected ErrTwoFactorTokenInvalid after exhaustion, got %v", err)
	}
}

func TestVerifyCode_LifecycleAndReplay(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "verify@example.com", true)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	// User not enrolled -> ErrTOTPNotEnrolled
	err := svc.VerifyCode(context.Background(), user.ID.String(), "123456", "127.0.0.1")
	if !errors.Is(err, apperrors.ErrTOTPNotEnrolled) {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
	}

	// Enroll & confirm
	resp, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	code, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}
	_, err = svc.ConfirmEnrollment(context.Background(), user.ID.String(), code)
	if err != nil {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}

	// Generate a fresh code (or same code if within window)
	// Because confirm recorded 'code' into used_codes, using the exact same code should trigger replay!
	err = svc.VerifyCode(context.Background(), user.ID.String(), code, "127.0.0.1")
	if !errors.Is(err, apperrors.ErrTOTPCodeReplayed) {
		t.Fatalf("expected ErrTOTPCodeReplayed for confirmed code, got %v", err)
	}

	// Invalid code -> ErrTOTPCodeInvalid
	err = svc.VerifyCode(context.Background(), user.ID.String(), "000000", "127.0.0.1")
	if !errors.Is(err, apperrors.ErrTOTPCodeInvalid) {
		t.Fatalf("expected ErrTOTPCodeInvalid, got %v", err)
	}

	// Drift code: generate code for t + 25s (within skew=1 window of 30s)
	driftCode, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC().Add(25*time.Second))
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// If driftCode happens to equal initial code (same 30s bucket), add 30s
	if driftCode == code {
		driftCode, err = ptotp.GenerateCode(resp.Secret, time.Now().UTC().Add(30*time.Second))
		if err != nil {
			t.Fatalf("GenerateCode failed: %v", err)
		}
	}

	err = svc.VerifyCode(context.Background(), user.ID.String(), driftCode, "127.0.0.1")
	if err != nil {
		t.Fatalf("VerifyCode failed on drift code: %v", err)
	}

	// Replay drift code
	err = svc.VerifyCode(context.Background(), user.ID.String(), driftCode, "127.0.0.1")
	if !errors.Is(err, apperrors.ErrTOTPCodeReplayed) {
		t.Fatalf("expected ErrTOTPCodeReplayed on replay, got %v", err)
	}
}

func TestVerifyCode_DualRateLimit(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "ratelimit@example.com", true)
	// Limiter allowing 2 requests
	limiter := ratelimit.NewLimiter(time.Minute, 2)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, limiter, nil)

	// IP rate limit trigger: 2 attempts succeed/fail normally, 3rd blocked
	ip := "192.168.1.100"
	_ = svc.VerifyCode(context.Background(), user.ID.String(), "000001", ip)
	_ = svc.VerifyCode(context.Background(), user.ID.String(), "000002", ip)

	err := svc.VerifyCode(context.Background(), user.ID.String(), "000003", ip)
	if !errors.Is(err, apperrors.ErrTOTPRateLimitExceeded) {
		t.Fatalf("expected ErrTOTPRateLimitExceeded on 3rd attempt from same IP, got %v", err)
	}
}

func TestVerifyBackupCode_Lifecycle(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "backup_user@example.com", true)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	// User not enrolled -> ErrTOTPNotEnrolled
	err := svc.VerifyBackupCode(context.Background(), user.ID.String(), "ABCDEF12", "127.0.0.1")
	if !errors.Is(err, apperrors.ErrTOTPNotEnrolled) {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
	}

	// Enroll & confirm
	resp, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	code, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}
	backupCodes, err := svc.ConfirmEnrollment(context.Background(), user.ID.String(), code)
	if err != nil || len(backupCodes) != 10 {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}

	// Invalid backup code -> ErrBackupCodeInvalid
	err = svc.VerifyBackupCode(context.Background(), user.ID.String(), "INVALID1", "127.0.0.1")
	if !errors.Is(err, apperrors.ErrBackupCodeInvalid) {
		t.Fatalf("expected ErrBackupCodeInvalid, got %v", err)
	}

	// Consume first code -> success
	err = svc.VerifyBackupCode(context.Background(), user.ID.String(), backupCodes[0], "127.0.0.1")
	if err != nil {
		t.Fatalf("VerifyBackupCode failed on code 0: %v", err)
	}

	// Re-verify first code -> ErrBackupCodeInvalid (already consumed!)
	err = svc.VerifyBackupCode(context.Background(), user.ID.String(), backupCodes[0], "127.0.0.1")
	if !errors.Is(err, apperrors.ErrBackupCodeInvalid) {
		t.Fatalf("expected ErrBackupCodeInvalid on re-using consumed code, got %v", err)
	}

	// Consume second code with lowercase/trim -> success
	err = svc.VerifyBackupCode(context.Background(), user.ID.String(), " "+strings.ToLower(backupCodes[1])+" ", "127.0.0.1")
	if err != nil {
		t.Fatalf("VerifyBackupCode failed on normalized code 1: %v", err)
	}
}

func TestDisableTOTP_WithPassword(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	plainPassword := "SecretPass#1234"
	hash, err := crypto.HashPassword(plainPassword, crypto.DefaultHashParams())
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	user := db.User{
		ID:            uuid.New(),
		Email:         "disable_pw@example.com",
		PasswordHash:  hash,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	// Disable when not enrolled -> ErrTOTPNotEnrolled
	err = svc.DisableTOTP(context.Background(), user.ID.String(), plainPassword, "")
	if !errors.Is(err, apperrors.ErrTOTPNotEnrolled) {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
	}

	// Enroll & confirm
	resp, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	code, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}
	_, err = svc.ConfirmEnrollment(context.Background(), user.ID.String(), code)
	if err != nil {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}

	// Also create a challenge token to verify cascade deletion
	_, err = svc.CreateChallengeToken(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("CreateChallengeToken failed: %v", err)
	}

	// Disable with wrong password -> ErrInvalidCredentials
	err = svc.DisableTOTP(context.Background(), user.ID.String(), "WrongPassword#9999", "")
	if !errors.Is(err, apperrors.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// Disable with correct password -> success
	err = svc.DisableTOTP(context.Background(), user.ID.String(), plainPassword, "")
	if err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}

	// Status should be false
	enabled, err := svc.Status(context.Background(), user.ID.String())
	if err != nil || enabled {
		t.Fatalf("expected enabled=false, got %v, err=%v", enabled, err)
	}

	// Records deleted
	var count int64
	database.Model(&db.TotpSecret{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 totp_secrets, got %d", count)
	}
	database.Model(&db.TwoFactorToken{}).Where("user_id = ?", user.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 two_factor_tokens, got %d", count)
	}
}

func TestDisableTOTP_WithCode(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "disable_code@example.com", true)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)

	resp, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	code, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}
	_, err = svc.ConfirmEnrollment(context.Background(), user.ID.String(), code)
	if err != nil {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}

	// Generate fresh code for disabling
	freshCode, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Empty credentials -> ErrInvalidCredentials
	err = svc.DisableTOTP(context.Background(), user.ID.String(), "", "")
	if !errors.Is(err, apperrors.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on empty auth, got %v", err)
	}

	// Disable with valid TOTP code -> success
	err = svc.DisableTOTP(context.Background(), user.ID.String(), "", freshCode)
	if err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}

	enabled, err := svc.Status(context.Background(), user.ID.String())
	if err != nil || enabled {
		t.Fatalf("expected enabled=false, got %v, err=%v", enabled, err)
	}
}

func TestDisableTOTP_BothCredentialsValid(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	plainPassword := "StrongPassword#2026"
	hash, err := crypto.HashPassword(plainPassword, crypto.DefaultHashParams())
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	user := db.User{
		ID:            uuid.New(),
		Email:         "both_auth@example.com",
		PasswordHash:  hash,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)
	resp, err := svc.Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	code, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}
	_, err = svc.ConfirmEnrollment(context.Background(), user.ID.String(), code)
	if err != nil {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}

	// Disable with both valid password AND valid fresh code
	freshCode, err := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	err = svc.DisableTOTP(context.Background(), user.ID.String(), plainPassword, freshCode)
	if err != nil {
		t.Fatalf("DisableTOTP failed with both valid credentials: %v", err)
	}

	enabled, err := svc.Status(context.Background(), user.ID.String())
	if err != nil || enabled {
		t.Fatalf("expected enabled=false, got %v, err=%v", enabled, err)
	}
}

func TestVerifyBackupCode_DualRateLimit(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "backup_rl@example.com", true)
	limiter := ratelimit.NewLimiter(time.Minute, 2)
	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, limiter, nil)

	ip := "10.0.0.1"
	_ = svc.VerifyBackupCode(context.Background(), user.ID.String(), "INVALID1", ip)
	_ = svc.VerifyBackupCode(context.Background(), user.ID.String(), "INVALID2", ip)

	err := svc.VerifyBackupCode(context.Background(), user.ID.String(), "INVALID3", ip)
	if !errors.Is(err, apperrors.ErrTOTPRateLimitExceeded) {
		t.Fatalf("expected ErrTOTPRateLimitExceeded, got %v", err)
	}
}

func TestEnroll_InvalidEncryptionKey(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	user := createTestUser(t, database, "bad_key@example.com", true)
	// Invalid 16-hex key
	svc := NewService(database, config.TOTPConfig{EncryptionKey: "bad-key"}, nil, nil)

	_, err := svc.Enroll(context.Background(), user.ID.String())
	if !errors.Is(err, apperrors.ErrTOTPEncryptionKeyInvalid) {
		t.Fatalf("expected ErrTOTPEncryptionKeyInvalid, got %v", err)
	}
}

func TestHelperAliases(t *testing.T) {
	t.Parallel()

	database := setupTestDB(t)
	plainPassword := "SecretPass#4321"
	hash, _ := crypto.HashPassword(plainPassword, crypto.DefaultHashParams())
	user := db.User{
		ID:            uuid.New(),
		Email:         "alias_test@example.com",
		PasswordHash:  hash,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	svc := NewService(database, config.TOTPConfig{EncryptionKey: validTestHexKey()}, nil, nil)
	concrete := svc.(*totpService)

	// IsTotpEnabled alias
	enabled, err := concrete.IsTotpEnabled(context.Background(), user.ID)
	if err != nil || enabled {
		t.Fatalf("expected enabled=false, got %v, err=%v", enabled, err)
	}

	// EnrollTotp alias
	resp, err := concrete.EnrollTotp(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("EnrollTotp failed: %v", err)
	}

	// Confirm
	code, _ := ptotp.GenerateCode(resp.Secret, time.Now().UTC())
	_, err = svc.ConfirmEnrollment(context.Background(), user.ID.String(), code)
	if err != nil {
		t.Fatalf("ConfirmEnrollment failed: %v", err)
	}

	// VerifyTotp alias with drift
	driftCode, _ := ptotp.GenerateCode(resp.Secret, time.Now().UTC().Add(25*time.Second))
	if driftCode == code {
		driftCode, _ = ptotp.GenerateCode(resp.Secret, time.Now().UTC().Add(30*time.Second))
	}
	err = concrete.VerifyTotp(context.Background(), user.ID, driftCode)
	if err != nil {
		t.Fatalf("VerifyTotp alias failed: %v", err)
	}

	// GenerateTwoFactorToken & ValidateTwoFactorToken aliases
	rawToken, err := concrete.GenerateTwoFactorToken(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GenerateTwoFactorToken failed: %v", err)
	}
	valUID, err := concrete.ValidateTwoFactorToken(context.Background(), rawToken)
	if err != nil || valUID != user.ID {
		t.Fatalf("ValidateTwoFactorToken failed: valUID=%s, err=%v", valUID, err)
	}

	// ConsumeTwoFactorToken alias
	err = concrete.ConsumeTwoFactorToken(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("ConsumeTwoFactorToken failed: %v", err)
	}

	// DisableTotp alias
	err = concrete.DisableTotp(context.Background(), user.ID, plainPassword, "")
	if err != nil {
		t.Fatalf("DisableTotp alias failed: %v", err)
	}
}




