package integration_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	ptotp "github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/totp"
)

func setupTotpIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	name := fmt.Sprintf("file:totp_e2e_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(name), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
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
	);`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("create totp schema: %v", err)
	}
	return database
}

func TestTotpService_EndToEndLifecycle(t *testing.T) {
	t.Parallel()

	database := setupTotpIntegrationDB(t)
	rawPassword := "SecurePassword#2026"
	hash, err := crypto.HashPassword(rawPassword, crypto.DefaultHashParams())
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := db.User{
		ID:            uuid.New(),
		Email:         "integration_totp@example.com",
		PasswordHash:  hash,
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := database.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := config.TOTPConfig{
		EncryptionKey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Issuer:               "IntegrationApp",
		ChallengeTokenTTL:    10 * time.Minute,
		MaxAttemptsPerWindow: 3,
		AttemptWindow:        5 * time.Minute,
	}
	limiter := ratelimit.NewLimiter(time.Minute, 10)
	svc := totp.NewService(database, cfg, limiter, nil)

	ctx := context.Background()

	// 1. Unverified user rejected
	_, err = svc.Enroll(ctx, user.ID.String())
	if !errors.Is(err, apperrors.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	// Verify email
	if err := database.Model(&user).Update("email_verified", true).Error; err != nil {
		t.Fatalf("update email_verified: %v", err)
	}

	// 2. Initial status: false
	status, err := svc.Status(ctx, user.ID.String())
	if err != nil || status {
		t.Fatalf("expected status=false, got status=%v, err=%v", status, err)
	}

	// 3. Enroll user
	enrollResp, err := svc.Enroll(ctx, user.ID.String())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if !strings.HasPrefix(enrollResp.QRCode, "data:image/png;base64,") {
		t.Fatalf("expected QR code data URI, got: %s", enrollResp.QRCode[:30])
	}
	if !strings.Contains(enrollResp.OTPURI, "IntegrationApp") {
		t.Fatalf("expected issuer in OTPURI: %s", enrollResp.OTPURI)
	}

	// Status still false while pending
	status, err = svc.Status(ctx, user.ID.String())
	if err != nil || status {
		t.Fatalf("expected status=false while pending, got %v", status)
	}

	// 4. Confirm enrollment with valid code
	validCode, err := ptotp.GenerateCode(enrollResp.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	backupCodes, err := svc.ConfirmEnrollment(ctx, user.ID.String(), validCode)
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	if len(backupCodes) != 10 {
		t.Fatalf("expected 10 backup codes, got %d", len(backupCodes))
	}

	// Status now true
	status, err = svc.Status(ctx, user.ID.String())
	if err != nil || !status {
		t.Fatalf("expected status=true after confirm, got %v", status)
	}

	// 5. Code replay prevention
	err = svc.VerifyCode(ctx, user.ID.String(), validCode, "127.0.0.1")
	if !errors.Is(err, apperrors.ErrTOTPCodeReplayed) {
		t.Fatalf("expected ErrTOTPCodeReplayed, got %v", err)
	}

	// 6. Valid drift code verification
	driftCode, err := ptotp.GenerateCode(enrollResp.Secret, time.Now().UTC().Add(25*time.Second))
	if err != nil {
		t.Fatalf("generate drift code: %v", err)
	}
	if driftCode == validCode {
		driftCode, err = ptotp.GenerateCode(enrollResp.Secret, time.Now().UTC().Add(30*time.Second))
		if err != nil {
			t.Fatalf("generate drift code step: %v", err)
		}
	}
	if err := svc.VerifyCode(ctx, user.ID.String(), driftCode, "127.0.0.1"); err != nil {
		t.Fatalf("verify drift code: %v", err)
	}

	// 7. Challenge Token Flow
	rawToken, err := svc.CreateChallengeToken(ctx, user.ID.String())
	if err != nil {
		t.Fatalf("create challenge token: %v", err)
	}

	tokRecord, err := svc.ValidateChallengeToken(ctx, rawToken)
	if err != nil || tokRecord.Attempts != 0 {
		t.Fatalf("validate challenge token: %v", err)
	}

	// Increment attempt
	att, err := svc.RecordTokenAttempt(ctx, rawToken)
	if err != nil || att != 1 {
		t.Fatalf("record token attempt: att=%d, err=%v", att, err)
	}

	// Consume challenge token
	consumedUser, err := svc.ConsumeChallengeToken(ctx, rawToken)
	if err != nil || consumedUser.ID != user.ID {
		t.Fatalf("consume challenge token: %v", err)
	}

	// Token must be hard-deleted
	_, err = svc.ValidateChallengeToken(ctx, rawToken)
	if !errors.Is(err, apperrors.ErrTwoFactorTokenInvalid) {
		t.Fatalf("expected ErrTwoFactorTokenInvalid after consume, got %v", err)
	}

	// 8. Backup Code Consumption
	if err := svc.VerifyBackupCode(ctx, user.ID.String(), backupCodes[0], "127.0.0.1"); err != nil {
		t.Fatalf("consume backup code 0: %v", err)
	}
	// Re-consumption fails
	if err := svc.VerifyBackupCode(ctx, user.ID.String(), backupCodes[0], "127.0.0.1"); !errors.Is(err, apperrors.ErrBackupCodeInvalid) {
		t.Fatalf("expected ErrBackupCodeInvalid on consumed backup code, got %v", err)
	}

	// 9. Disable TOTP with fresh password
	if err := svc.DisableTOTP(ctx, user.ID.String(), rawPassword, ""); err != nil {
		t.Fatalf("disable totp: %v", err)
	}

	status, err = svc.Status(ctx, user.ID.String())
	if err != nil || status {
		t.Fatalf("expected status=false after disable, got %v", status)
	}

	var secretCount int64
	database.Model(&db.TotpSecret{}).Where("user_id = ?", user.ID).Count(&secretCount)
	if secretCount != 0 {
		t.Fatalf("expected 0 totp secrets remaining, got %d", secretCount)
	}
}
