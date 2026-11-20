package totp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	ptotp "github.com/pquerna/otp/totp"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
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

