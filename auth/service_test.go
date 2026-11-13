package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

func testConfig() config.Config {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://test:test@localhost:5432/test"
	cfg.BaseURL = "http://localhost:8080"
	cfg.Argon2 = config.Argon2Config{
		Memory:      19456, // Fast RFC 9106 test floor
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	cfg.VerificationTokenExpiry = 30 * time.Minute
	cfg.PasswordResetTokenExpiry = 30 * time.Minute
	return cfg
}

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:mem_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS verification_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return database
}

func TestNewService(t *testing.T) {
	database := setupTestDB(t)

	t.Run("invalid config", func(t *testing.T) {
		cfg := testConfig()
		cfg.DatabaseURL = ""
		_, err := New(cfg, database, email.Hooks{})
		if err == nil {
			t.Fatal("expected error with missing DatabaseURL, got nil")
		}
		if !errors.Is(err, errors.ErrDatabaseURLRequired) {
			t.Fatalf("expected ErrDatabaseURLRequired, got %v", err)
		}
	})

	t.Run("nil database", func(t *testing.T) {
		cfg := testConfig()
		_, err := New(cfg, nil, email.Hooks{})
		if err == nil {
			t.Fatal("expected error with nil database, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})

	t.Run("valid initialization", func(t *testing.T) {
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("unexpected error creating service: %v", err)
		}
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})
}

func TestService_Signup(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	type hookData struct {
		recipient string
		token     string
	}
	hookCh := make(chan hookData, 10)

	hooks := email.Hooks{
		SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
			hookCh <- hookData{recipient: recipient, token: token}
			return nil
		},
	}

	svc, err := New(cfg, database, hooks)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()

	t.Run("invalid email", func(t *testing.T) {
		_, _, err := svc.Signup(ctx, db.SignupRequest{Email: "invalid-email", Password: "SecureAlpha#2026!"})
		if err == nil {
			t.Fatal("expected error for invalid email, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidEmail {
			t.Fatalf("expected CodeInvalidEmail, got %v", err)
		}
	})

	t.Run("weak password too short", func(t *testing.T) {
		_, _, err := svc.Signup(ctx, db.SignupRequest{Email: "user@example.com", Password: "short"})
		if err == nil {
			t.Fatal("expected error for short password, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodePasswordTooShort {
			t.Fatalf("expected CodePasswordTooShort, got %v", err)
		}
	})

	t.Run("common password blocklist", func(t *testing.T) {
		_, _, err := svc.Signup(ctx, db.SignupRequest{Email: "user@example.com", Password: "password"})
		if err == nil {
			t.Fatal("expected error for common password, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodePasswordTooCommon {
			t.Fatalf("expected CodePasswordTooCommon, got %v", err)
		}
	})

	t.Run("successful signup", func(t *testing.T) {
		user, token, err := svc.Signup(ctx, db.SignupRequest{Email: "User@Example.com", Password: "SecureAlpha#2026!"})
		if err != nil {
			t.Fatalf("unexpected error on signup: %v", err)
		}
		if user == nil {
			t.Fatal("expected user to be returned, got nil")
		}
		if len(token) != 64 {
			t.Fatalf("expected 64-char token, got len %d: %q", len(token), token)
		}
		if user.EmailVerified {
			t.Fatal("expected EmailVerified to be false initially")
		}

		select {
		case data := <-hookCh:
			if data.recipient != "User@Example.com" || data.token != token {
				t.Fatalf("hook received wrong args: recipient=%s, token=%s", data.recipient, data.token)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for verification email hook")
		}

		// Verify DB persistence
		var dbUser db.User
		if err := database.Where("LOWER(email) = LOWER(?)", "user@example.com").First(&dbUser).Error; err != nil {
			t.Fatalf("failed to query user in db: %v", err)
		}

		rawBytes, _ := hex.DecodeString(token)
		expectedHash := sha256.Sum256(rawBytes)
		var dbTok db.VerificationToken
		if err := database.Where("token_hash = ?", expectedHash[:]).First(&dbTok).Error; err != nil {
			t.Fatalf("failed to query verification token in db: %v", err)
		}
		if dbTok.UserID != dbUser.ID {
			t.Fatalf("token UserID = %v, want %v", dbTok.UserID, dbUser.ID)
		}
	})

	t.Run("duplicate email silent success anti-enumeration", func(t *testing.T) {
		user, token, err := svc.Signup(ctx, db.SignupRequest{Email: "user@example.com", Password: "SecureAlpha#2026!"})
		if err != nil {
			t.Fatalf("unexpected error on duplicate signup: %v", err)
		}
		if user != nil || token != "" {
			t.Fatalf("expected nil user and empty token for duplicate email, got user=%v, token=%s", user, token)
		}

		// Verify no duplicate row was created
		var count int64
		database.Model(&db.User{}).Where("LOWER(email) = LOWER(?)", "user@example.com").Count(&count)
		if count != 1 {
			t.Fatalf("expected 1 user row, found %d", count)
		}
	})

	t.Run("duplicate email race condition during insertion returns silent success", func(t *testing.T) {
		raceEmail := "race_user@example.com"
		var wg sync.WaitGroup
		type signupResult struct {
			user  *db.User
			token string
			err   error
		}
		results := make([]signupResult, 2)

		wg.Add(2)
		for i := 0; i < 2; i++ {
			go func(idx int) {
				defer wg.Done()
				u, tok, err := svc.Signup(ctx, db.SignupRequest{
					Email:    raceEmail,
					Password: "SecureAlpha#2026!",
				})
				results[idx] = signupResult{user: u, token: tok, err: err}
			}(i)
		}
		wg.Wait()

		for i, res := range results {
			if res.err != nil {
				t.Fatalf("goroutine %d returned unexpected error: %v", i, res.err)
			}
		}

		var successCount int
		for _, res := range results {
			if res.user != nil {
				successCount++
				if res.token == "" {
					t.Fatalf("expected non-empty token for created user")
				}
			} else if res.token != "" {
				t.Fatalf("expected empty token for silent success duplicate")
			}
		}

		if successCount != 1 {
			t.Fatalf("expected exactly 1 signup call to create user, got %d", successCount)
		}

		var count int64
		if err := database.Model(&db.User{}).Where("LOWER(email) = LOWER(?)", raceEmail).Count(&count).Error; err != nil {
			t.Fatalf("failed to count users in db: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 user row in db, got %d", count)
		}
	})
}

func TestService_Login(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc, err := New(cfg, database, email.Hooks{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()
	_, _, err = svc.Signup(ctx, db.SignupRequest{Email: "login@example.com", Password: "SecretPassword#2026!"})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	t.Run("non-existent user anti-enumeration", func(t *testing.T) {
		user, err := svc.Login(ctx, db.LoginRequest{Email: "unknown@example.com", Password: "SecretPassword#2026!"})
		if err == nil {
			t.Fatal("expected error for non-existent user, got nil")
		}
		if user != nil {
			t.Fatalf("expected nil user, got %v", user)
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidCredentials {
			t.Fatalf("expected CodeInvalidCredentials, got %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		user, err := svc.Login(ctx, db.LoginRequest{Email: "login@example.com", Password: "WrongPassword#2026!"})
		if err == nil {
			t.Fatal("expected error for wrong password, got nil")
		}
		if user != nil {
			t.Fatalf("expected nil user, got %v", user)
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidCredentials {
			t.Fatalf("expected CodeInvalidCredentials, got %v", err)
		}
	})

	t.Run("successful login with unverified email allowed when requireEmailVerification is false", func(t *testing.T) {
		user, err := svc.Login(ctx, db.LoginRequest{Email: "login@example.com", Password: "SecretPassword#2026!"})
		if err != nil {
			t.Fatalf("unexpected login error: %v", err)
		}
		if user == nil || user.Email != "login@example.com" {
			t.Fatalf("expected user login@example.com, got %v", user)
		}
	})

	t.Run("unverified email blocked when requireEmailVerification is true", func(t *testing.T) {
		cfgRequired := cfg
		cfgRequired.RequireEmailVerification = true
		svcRequired, err := New(cfgRequired, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		user, err := svcRequired.Login(ctx, db.LoginRequest{Email: "login@example.com", Password: "SecretPassword#2026!"})
		if err == nil {
			t.Fatal("expected error for unverified account, got nil")
		}
		if user != nil {
			t.Fatalf("expected nil user, got %v", user)
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeEmailNotVerified {
			t.Fatalf("expected CodeEmailNotVerified, got %v", err)
		}

		// Mark verified in DB and retry
		if err := database.Model(&db.User{}).Where("email = ?", "login@example.com").Update("email_verified", true).Error; err != nil {
			t.Fatalf("failed to update user: %v", err)
		}

		user, err = svcRequired.Login(ctx, db.LoginRequest{Email: "login@example.com", Password: "SecretPassword#2026!"})
		if err != nil {
			t.Fatalf("expected successful login after verification, got %v", err)
		}
		if user == nil {
			t.Fatal("expected user after verification, got nil")
		}
	})
}

func TestService_VerifyEmail(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc, err := New(cfg, database, email.Hooks{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()

	t.Run("invalid token format", func(t *testing.T) {
		err := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: "tooshort"})
		if err == nil {
			t.Fatal("expected error for invalid token, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("expected CodeInvalidToken, got %v", err)
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		unknownToken, _, _ := crypto.GenerateToken()
		err := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: unknownToken})
		if err == nil {
			t.Fatal("expected error for unknown token, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("expected CodeInvalidToken, got %v", err)
		}
	})

	t.Run("expired token deletes token and returns CodeTokenExpired", func(t *testing.T) {
		user, rawToken, err := svc.Signup(ctx, db.SignupRequest{Email: "expired@example.com", Password: "SecurePassword#2026!"})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		rawBytes, _ := hex.DecodeString(rawToken)
		tokenHash := sha256.Sum256(rawBytes)

		// Set expires_at in the past
		past := time.Now().UTC().Add(-1 * time.Hour)
		if err := database.Model(&db.VerificationToken{}).Where("token_hash = ?", tokenHash[:]).Update("expires_at", past).Error; err != nil {
			t.Fatalf("failed to expire token in db: %v", err)
		}

		err = svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: rawToken})
		if err == nil {
			t.Fatal("expected error for expired token, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeTokenExpired {
			t.Fatalf("expected CodeTokenExpired, got %v", err)
		}

		// Verify token was deleted from DB
		var count int64
		database.Model(&db.VerificationToken{}).Where("token_hash = ?", tokenHash[:]).Count(&count)
		if count != 0 {
			t.Fatalf("expected expired token to be deleted, count = %d", count)
		}

		// Replay attempt must now return CodeInvalidToken because row was deleted
		err = svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: rawToken})
		if err == nil {
			t.Fatal("expected error on replay, got nil")
		}
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("expected CodeInvalidToken on replay, got %v", err)
		}

		// User remains unverified
		var dbUser db.User
		database.Where("id = ?", user.ID).First(&dbUser)
		if dbUser.EmailVerified {
			t.Fatal("user should not be marked verified on expired token")
		}
	})

	t.Run("successful verification and single-use enforcement", func(t *testing.T) {
		user, rawToken, err := svc.Signup(ctx, db.SignupRequest{Email: "verify@example.com", Password: "SecurePassword#2026!"})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		err = svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: rawToken})
		if err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}

		// Verify user email_verified flag is true
		var dbUser db.User
		database.Where("id = ?", user.ID).First(&dbUser)
		if !dbUser.EmailVerified {
			t.Fatal("expected user to be verified, got false")
		}

		// Verify token row was deleted
		rawBytes, _ := hex.DecodeString(rawToken)
		tokenHash := sha256.Sum256(rawBytes)
		var count int64
		database.Model(&db.VerificationToken{}).Where("token_hash = ?", tokenHash[:]).Count(&count)
		if count != 0 {
			t.Fatalf("expected token to be deleted after use, count = %d", count)
		}

		// Replay must fail with CodeInvalidToken
		err = svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: rawToken})
		if err == nil {
			t.Fatal("expected replay to fail, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("expected CodeInvalidToken on replay, got %v", err)
		}
	})
}

func TestService_PasswordReset(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	type hookData struct {
		recipient string
		token     string
	}
	hookCh := make(chan hookData, 10)

	hooks := email.Hooks{
		SendPasswordResetEmail: func(ctx context.Context, recipient, token string) error {
			hookCh <- hookData{recipient: recipient, token: token}
			return nil
		},
	}

	svc, err := New(cfg, database, hooks)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()
	user, _, err := svc.Signup(ctx, db.SignupRequest{Email: "reset@example.com", Password: "OriginalPassword#2026!"})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	t.Run("non-existent user reset request returns silent success anti-enumeration", func(t *testing.T) {
		token, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{Email: "unknown@example.com"})
		if err != nil {
			t.Fatalf("unexpected error on unknown email reset request: %v", err)
		}
		if token != "" {
			t.Fatalf("expected empty token for unknown email, got %q", token)
		}
	})

	var lastToken string
	t.Run("existing user reset request dispatches hook and saves token", func(t *testing.T) {
		token, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{Email: "reset@example.com"})
		if err != nil {
			t.Fatalf("unexpected error on reset request: %v", err)
		}
		if len(token) != 64 {
			t.Fatalf("expected 64-char token, got len %d: %q", len(token), token)
		}
		lastToken = token

		select {
		case data := <-hookCh:
			if data.recipient != "reset@example.com" || data.token != token {
				t.Fatalf("hook received wrong args: recipient=%s, token=%s", data.recipient, data.token)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for reset email hook")
		}

		// Verify token stored in DB
		rawBytes, _ := hex.DecodeString(token)
		tokenHash := sha256.Sum256(rawBytes)
		var dbTok db.PasswordResetToken
		if err := database.Where("token_hash = ?", tokenHash[:]).First(&dbTok).Error; err != nil {
			t.Fatalf("failed to query reset token in db: %v", err)
		}
		if dbTok.UserID != user.ID {
			t.Fatalf("reset token UserID = %v, want %v", dbTok.UserID, user.ID)
		}
	})

	t.Run("reset password pre-DB weak password checks", func(t *testing.T) {
		err := svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{Token: lastToken, NewPassword: "short"})
		if err == nil {
			t.Fatal("expected error for short password, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodePasswordTooShort {
			t.Fatalf("expected CodePasswordTooShort, got %v", err)
		}

		err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{Token: lastToken, NewPassword: "password"})
		if err == nil {
			t.Fatal("expected error for common password, got nil")
		}
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodePasswordTooCommon {
			t.Fatalf("expected CodePasswordTooCommon, got %v", err)
		}
	})

	t.Run("reset password expired token deleted and returns CodeTokenExpired", func(t *testing.T) {
		token, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{Email: "reset@example.com"})
		if err != nil {
			t.Fatalf("reset request failed: %v", err)
		}
		// drain hookCh
		select {
		case <-hookCh:
		case <-time.After(time.Second):
		}

		rawBytes, _ := hex.DecodeString(token)
		tokenHash := sha256.Sum256(rawBytes)

		past := time.Now().UTC().Add(-1 * time.Hour)
		database.Model(&db.PasswordResetToken{}).Where("token_hash = ?", tokenHash[:]).Update("expires_at", past)

		err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{Token: token, NewPassword: "BrandNewPassword#2026!"})
		if err == nil {
			t.Fatal("expected error for expired token, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeTokenExpired {
			t.Fatalf("expected CodeTokenExpired, got %v", err)
		}

		// Verify token deleted
		var count int64
		database.Model(&db.PasswordResetToken{}).Where("token_hash = ?", tokenHash[:]).Count(&count)
		if count != 0 {
			t.Fatalf("expected token row to be deleted, count = %d", count)
		}

		// Replay returns CodeInvalidToken
		err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{Token: token, NewPassword: "BrandNewPassword#2026!"})
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("expected CodeInvalidToken on replay, got %v", err)
		}
	})

	t.Run("successful password reset and ASVS L1 purging of all user tokens", func(t *testing.T) {
		// Generate two valid tokens for the same user
		tok1, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{Email: "reset@example.com"})
		if err != nil {
			t.Fatalf("reset request 1 failed: %v", err)
		}
		tok2, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{Email: "reset@example.com"})
		if err != nil {
			t.Fatalf("reset request 2 failed: %v", err)
		}

		var countBefore int64
		database.Model(&db.PasswordResetToken{}).Where("user_id = ?", user.ID).Count(&countBefore)
		if countBefore < 2 {
			t.Fatalf("expected at least 2 tokens before reset, got %d", countBefore)
		}

		// Reset password using tok1
		newPassword := "BrandNewPassword#2026!"
		err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{Token: tok1, NewPassword: newPassword})
		if err != nil {
			t.Fatalf("unexpected reset error: %v", err)
		}

		// Verify login with old password fails
		_, err = svc.Login(ctx, db.LoginRequest{Email: "reset@example.com", Password: "OriginalPassword#2026!"})
		if err == nil {
			t.Fatal("expected login with old password to fail, got nil")
		}

		// Verify login with new password succeeds
		updatedUser, err := svc.Login(ctx, db.LoginRequest{Email: "reset@example.com", Password: newPassword})
		if err != nil {
			t.Fatalf("expected login with new password to succeed, got %v", err)
		}
		if updatedUser == nil {
			t.Fatal("expected user to be returned on login with new password")
		}

		// ASVS L1 Check: ALL reset tokens for this user must be purged
		var countAfter int64
		database.Model(&db.PasswordResetToken{}).Where("user_id = ?", user.ID).Count(&countAfter)
		if countAfter != 0 {
			t.Fatalf("expected 0 reset tokens after reset (ASVS L1 purge), got %d", countAfter)
		}

		// Both tok1 (consumed) and tok2 (purged) must now fail on replay
		for _, tok := range []string{tok1, tok2} {
			err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{Token: tok, NewPassword: "AnotherNewPassword#2026!"})
			var appErr *errors.Error
			if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
				t.Fatalf("expected CodeInvalidToken for token %s, got %v", tok, err)
			}
		}
	})
}

func TestEmailHooks_NilSafe(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	// Initialized with completely nil hooks
	svc, err := New(cfg, database, email.Hooks{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()

	// Signup without hooks should not panic
	user, token, err := svc.Signup(ctx, db.SignupRequest{Email: "nohooks@example.com", Password: "SecurePassword#2026!"})
	if err != nil {
		t.Fatalf("signup failed: %v", err)
	}
	if user == nil || token == "" {
		t.Fatal("expected user and token on signup")
	}

	// RequestPasswordReset without hooks should not panic
	resetToken, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{Email: "nohooks@example.com"})
	if err != nil {
		t.Fatalf("request password reset failed: %v", err)
	}
	if resetToken == "" {
		t.Fatal("expected reset token")
	}
}

func TestService_Logout(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc, err := New(cfg, database, email.Hooks{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()
	if err := svc.Logout(ctx, "session-12345"); err != nil {
		t.Fatalf("logout returned non-nil err: %v", err)
	}
}

func TestDispatchVerificationEmail_SaturatedSemaphoreRetries(t *testing.T) {
	cfg := testConfig()
	called := make(chan string, 1)
	svc := &authService{
		cfg: cfg,
		hooks: email.Hooks{
			SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
				called <- recipient
				return nil
			},
		},
		emailSem: make(chan struct{}, 1),
	}
	svc.emailSem <- struct{}{}

	svc.dispatchVerificationEmail(context.Background(), "retry@example.com", "tok")

	time.AfterFunc(100*time.Millisecond, func() { <-svc.emailSem })

	select {
	case got := <-called:
		if got != "retry@example.com" {
			t.Fatalf("hook got recipient %q, want retry@example.com", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hook not called after semaphore capacity returned")
	}
}

func TestTryAcquireEmailSlot(t *testing.T) {
	t.Run("nil semaphore returns false", func(t *testing.T) {
		svc := &authService{}
		if svc.tryAcquireEmailSlot("user@example.com") {
			t.Fatal("expected false for nil semaphore, got true")
		}
	})

	t.Run("available slot acquires and returns true", func(t *testing.T) {
		svc := &authService{
			emailSem: make(chan struct{}, 1),
		}
		if !svc.tryAcquireEmailSlot("user@example.com") {
			t.Fatal("expected true when slot is available, got false")
		}
		if len(svc.emailSem) != 1 {
			t.Fatalf("expected 1 item in emailSem, got %d", len(svc.emailSem))
		}
	})

	t.Run("saturated semaphore returns false", func(t *testing.T) {
		svc := &authService{
			emailSem: make(chan struct{}, 1),
		}
		svc.emailSem <- struct{}{}
		if svc.tryAcquireEmailSlot("user@example.com") {
			t.Fatal("expected false when semaphore is saturated, got true")
		}
	})
}

func TestEmailHookTimeout(t *testing.T) {
	t.Run("default timeout when unset or zero", func(t *testing.T) {
		svc := &authService{
			cfg: config.Config{},
		}
		if got := svc.emailHookTimeout(); got != 10*time.Second {
			t.Fatalf("expected 10s default timeout, got %v", got)
		}
	})

	t.Run("default timeout when negative", func(t *testing.T) {
		svc := &authService{
			cfg: config.Config{
				EmailDispatchTimeout: -5 * time.Second,
			},
		}
		if got := svc.emailHookTimeout(); got != 10*time.Second {
			t.Fatalf("expected 10s default timeout for negative value, got %v", got)
		}
	})

	t.Run("custom positive timeout", func(t *testing.T) {
		svc := &authService{
			cfg: config.Config{
				EmailDispatchTimeout: 3 * time.Second,
			},
		}
		if got := svc.emailHookTimeout(); got != 3*time.Second {
			t.Fatalf("expected 3s timeout, got %v", got)
		}
	})
}

func TestDispatchEmailAsync_ExecutionBranches(t *testing.T) {
	t.Run("nil emailSem directly spawns goroutine and executes hook", func(t *testing.T) {
		done := make(chan struct{})
		svc := &authService{
			cfg:      config.Config{EmailDispatchTimeout: time.Second},
			emailSem: nil,
		}
		svc.dispatchEmailAsync(context.Background(), "nilsem@example.com", "tok1", "test", func(ctx context.Context, recipient, token string) error {
			if recipient != "nilsem@example.com" || token != "tok1" {
				t.Errorf("unexpected args: recipient=%s, token=%s", recipient, token)
			}
			close(done)
			return nil
		})

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("hook was not executed when emailSem is nil")
		}
	})

	t.Run("context detachment preserves hook execution with canceled parent ctx", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		done := make(chan struct{})
		svc := &authService{
			cfg:      config.Config{EmailDispatchTimeout: time.Second},
			emailSem: make(chan struct{}, 1),
		}

		svc.dispatchEmailAsync(canceledCtx, "detached@example.com", "tok2", "test", func(ctx context.Context, recipient, token string) error {
			if err := ctx.Err(); err != nil {
				t.Errorf("expected detached context without cancel error, got: %v", err)
			}
			close(done)
			return nil
		})

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("hook was not executed")
		}
	})

	t.Run("nil parent context executes cleanly", func(t *testing.T) {
		done := make(chan struct{})
		svc := &authService{
			cfg:      config.Config{EmailDispatchTimeout: time.Second},
			emailSem: make(chan struct{}, 1),
		}

		var nilCtx context.Context
		//nolint:staticcheck // SA1012 intentionally testing nil context fallback
		svc.dispatchEmailAsync(nilCtx, "nilctx@example.com", "tok3", "test", func(ctx context.Context, recipient, token string) error {
			if ctx == nil {
				t.Error("expected non-nil timeout context in hook")
			}
			close(done)
			return nil
		})

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("hook was not executed")
		}
	})

	t.Run("hook error is logged and semaphore is released", func(t *testing.T) {
		done := make(chan struct{})
		sem := make(chan struct{}, 1)
		svc := &authService{
			cfg:      config.Config{EmailDispatchTimeout: time.Second},
			emailSem: sem,
		}

		svc.dispatchEmailAsync(context.Background(), "err@example.com", "tok4", "test", func(ctx context.Context, recipient, token string) error {
			defer close(done)
			return fmt.Errorf("simulated delivery failure")
		})

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("hook was not executed")
		}

		select {
		case sem <- struct{}{}:
			<-sem
		case <-time.After(1 * time.Second):
			t.Fatal("semaphore slot was not released after hook error")
		}
	})

	t.Run("hook panic is recovered and semaphore is released", func(t *testing.T) {
		done := make(chan struct{})
		sem := make(chan struct{}, 1)
		svc := &authService{
			cfg:      config.Config{EmailDispatchTimeout: time.Second},
			emailSem: sem,
		}

		svc.dispatchEmailAsync(context.Background(), "panic@example.com", "tok5", "test", func(ctx context.Context, recipient, token string) error {
			defer close(done)
			panic("simulated fatal hook crash")
		})

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("hook was not executed")
		}

		select {
		case sem <- struct{}{}:
			<-sem
		case <-time.After(1 * time.Second):
			t.Fatal("semaphore slot was not released after hook panic")
		}
	})
}

func TestDispatchEmailAsync_SaturationAndOverflow(t *testing.T) {
	t.Run("pending queue overflow drops request without executing hook", func(t *testing.T) {
		emailSem := make(chan struct{}, 1)
		emailSem <- struct{}{}

		emailPendingSem := make(chan struct{}, 1)
		emailPendingSem <- struct{}{}

		hookCalled := make(chan struct{}, 1)
		svc := &authService{
			cfg:             config.Config{EmailDispatchTimeout: 50 * time.Millisecond},
			emailSem:        emailSem,
			emailPendingSem: emailPendingSem,
		}

		svc.dispatchEmailAsync(context.Background(), "overflow@example.com", "tok", "verification", func(ctx context.Context, recipient, token string) error {
			hookCalled <- struct{}{}
			return nil
		})

		select {
		case <-hookCalled:
			t.Fatal("hook should not have been called on overflow drop")
		case <-time.After(150 * time.Millisecond):
		}

		<-emailSem
		<-emailPendingSem
	})

	t.Run("wait timeout gives up and releases pending slot when emailSem never frees", func(t *testing.T) {
		emailSem := make(chan struct{}, 1)
		emailSem <- struct{}{}

		emailPendingSem := make(chan struct{}, 1)

		hookCalled := make(chan struct{}, 1)
		svc := &authService{
			cfg:             config.Config{EmailDispatchTimeout: 50 * time.Millisecond},
			emailSem:        emailSem,
			emailPendingSem: emailPendingSem,
		}

		svc.dispatchEmailAsync(context.Background(), "timeout@example.com", "tok", "password reset", func(ctx context.Context, recipient, token string) error {
			hookCalled <- struct{}{}
			return nil
		})

		select {
		case <-hookCalled:
			t.Fatal("hook should not have been called after wait timeout")
		case <-time.After(150 * time.Millisecond):
		}

		select {
		case emailPendingSem <- struct{}{}:
			<-emailPendingSem
		case <-time.After(500 * time.Millisecond):
			t.Fatal("emailPendingSem was not released after wait timeout give-up")
		}

		<-emailSem
	})
}

func TestService_Signup_UnverifiedAccountRecovery(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	type hookData struct {
		recipient string
		token     string
	}
	hookCh := make(chan hookData, 10)

	hooks := email.Hooks{
		SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
			hookCh <- hookData{recipient: recipient, token: token}
			return nil
		},
	}

	svc, err := New(cfg, database, hooks)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()

	initialPass := "InitialPass#12345"
	user, origToken, err := svc.Signup(ctx, db.SignupRequest{Email: "recover@example.com", Password: initialPass})
	if err != nil {
		t.Fatalf("initial signup failed: %v", err)
	}
	if user == nil || origToken == "" {
		t.Fatal("expected user and token on initial signup")
	}

	select {
	case <-hookCh:
	case <-time.After(2 * time.Second):
		t.Fatal("initial verification email hook not received")
	}

	var dbUserBefore db.User
	if err := database.Where("id = ?", user.ID).First(&dbUserBefore).Error; err != nil {
		t.Fatalf("failed to query user before recovery: %v", err)
	}
	oldHash := dbUserBefore.PasswordHash

	newPass := "RecoveredPass#67890"
	recUser, recToken, err := svc.Signup(ctx, db.SignupRequest{Email: "recover@example.com", Password: newPass})
	if err != nil {
		t.Fatalf("unverified recovery signup failed: %v", err)
	}
	if recUser != nil || recToken != "" {
		t.Fatalf("expected nil user and empty token for unverified recovery anti-enumeration, got user=%v token=%s", recUser, recToken)
	}

	var newHookData hookData
	select {
	case newHookData = <-hookCh:
		if newHookData.recipient != "recover@example.com" {
			t.Fatalf("expected recipient recover@example.com, got %s", newHookData.recipient)
		}
		if newHookData.token == "" || newHookData.token == origToken {
			t.Fatalf("expected new verification token, got %s", newHookData.token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery verification email hook not received")
	}

	oldTokenHash, err := crypto.HashToken(origToken)
	if err != nil {
		t.Fatalf("failed to hash origToken: %v", err)
	}
	var countOld int64
	database.Model(&db.VerificationToken{}).Where("token_hash = ?", oldTokenHash[:]).Count(&countOld)
	if countOld != 0 {
		t.Fatalf("expected old verification token to be deleted, found %d", countOld)
	}

	newTokenHash, err := crypto.HashToken(newHookData.token)
	if err != nil {
		t.Fatalf("failed to hash newHookData.token: %v", err)
	}
	var countNew int64
	database.Model(&db.VerificationToken{}).Where("token_hash = ?", newTokenHash[:]).Count(&countNew)
	if countNew != 1 {
		t.Fatalf("expected new verification token in DB, found %d", countNew)
	}

	var dbUserAfter db.User
	if err := database.Where("id = ?", user.ID).First(&dbUserAfter).Error; err != nil {
		t.Fatalf("failed to query user after recovery: %v", err)
	}
	if dbUserAfter.PasswordHash == oldHash {
		t.Fatal("expected password hash to be updated in DB after unverified recovery")
	}

	if err := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: origToken}); err == nil {
		t.Fatal("expected old token verification to fail, got nil")
	}

	if err := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: newHookData.token}); err != nil {
		t.Fatalf("expected new token verification to succeed, got %v", err)
	}

	loggedIn, err := svc.Login(ctx, db.LoginRequest{Email: "recover@example.com", Password: newPass})
	if err != nil {
		t.Fatalf("expected login with new password to succeed, got %v", err)
	}
	if loggedIn == nil {
		t.Fatal("expected non-nil logged-in user")
	}
}

func TestService_Signup_UnverifiedRecovery_ConcurrentVerificationRace(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	type hookData struct {
		recipient string
		token     string
	}
	hookCh := make(chan hookData, 10)
	hooks := email.Hooks{
		SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
			hookCh <- hookData{recipient: recipient, token: token}
			return nil
		},
	}

	authSvc, err := New(cfg, database, hooks)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	svc := authSvc.(*authService)

	ctx := context.Background()
	origPass := "OriginalPassword#12345"
	user, _, err := svc.Signup(ctx, db.SignupRequest{Email: "race@example.com", Password: origPass})
	if err != nil {
		t.Fatalf("initial signup failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}

	select {
	case <-hookCh:
	case <-time.After(2 * time.Second):
		t.Fatal("initial verification hook not received")
	}

	recoveryLookupDone := make(chan struct{})
	svc.onPreRecoveryLock = func() {
		close(recoveryLookupDone)
	}

	svc.recoveryMu.Lock()

	signupDone := make(chan struct{})
	var signupErr error
	var signupUser *db.User
	var signupToken string

	go func() {
		defer close(signupDone)
		signupUser, signupToken, signupErr = svc.Signup(ctx, db.SignupRequest{
			Email:    "race@example.com",
			Password: "AttemptedNewPassword#67890",
		})
	}()

	select {
	case <-recoveryLookupDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for signup initial unverified lookup")
	}

	if err := database.Model(&db.User{}).Where("id = ?", user.ID).Update("email_verified", true).Error; err != nil {
		t.Fatalf("failed to concurrently verify user: %v", err)
	}

	svc.recoveryMu.Unlock()

	select {
	case <-signupDone:
	case <-time.After(3 * time.Second):
		t.Fatal("signup did not complete after releasing recovery lock")
	}

	if signupErr != nil {
		t.Fatalf("expected silent success for duplicate email, got: %v", signupErr)
	}
	if signupUser != nil || signupToken != "" {
		t.Fatalf("expected nil user and empty token, got user=%v, token=%s", signupUser, signupToken)
	}

	select {
	case h := <-hookCh:
		t.Fatalf("unexpected verification email sent to %s during race", h.recipient)
	default:
	}

	var dbUser db.User
	if err := database.Where("id = ?", user.ID).First(&dbUser).Error; err != nil {
		t.Fatalf("failed to query user: %v", err)
	}
	match, err := crypto.VerifyPassword(origPass, dbUser.PasswordHash)
	if err != nil || !match {
		t.Fatalf("expected original password to remain valid when recovery was bypassed by concurrent verification: match=%v, err=%v", match, err)
	}
	matchNew, _ := crypto.VerifyPassword("AttemptedNewPassword#67890", dbUser.PasswordHash)
	if matchNew {
		t.Fatal("attempted new password should not have been set")
	}
}

func TestService_Signup_UnverifiedRecovery_TransactionFailure(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	svc, err := New(cfg, database, email.Hooks{})
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	ctx := context.Background()

	user, _, err := svc.Signup(ctx, db.SignupRequest{Email: "txfail@example.com", Password: "OriginalPassword#12345"})
	if err != nil {
		t.Fatalf("initial signup failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}

	if err := database.Exec("DROP TABLE verification_tokens").Error; err != nil {
		t.Fatalf("failed to drop verification_tokens table: %v", err)
	}

	_, _, err = svc.Signup(ctx, db.SignupRequest{Email: "txfail@example.com", Password: "NewPassword#67890"})
	if err == nil {
		t.Fatal("expected transaction failure error, got nil")
	}

	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
		t.Fatalf("expected CodeDatabaseError, got: %v", err)
	}
}

func TestService_Signup_UnverifiedRecovery_AttackerCredentialBinding(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	type hookData struct {
		recipient string
		token     string
	}
	hookCh := make(chan hookData, 10)
	hooks := email.Hooks{
		SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
			hookCh <- hookData{recipient: recipient, token: token}
			return nil
		},
	}

	authSvc, err := New(cfg, database, hooks)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	svc := authSvc.(*authService)
	ctx := context.Background()

	targetEmail := "victim@example.com"
	attackerPass := "AttackerPass#12345"
	victimPass := "VictimPass#67890"

	// 1. Attacker registers victim's email with attackerPass.
	attackerUser, attackerToken, err := svc.Signup(ctx, db.SignupRequest{
		Email:    targetEmail,
		Password: attackerPass,
	})
	if err != nil {
		t.Fatalf("attacker signup failed: %v", err)
	}
	if attackerUser == nil || attackerToken == "" {
		t.Fatal("expected user and token on initial attacker signup")
	}

	var attackerHook hookData
	select {
	case attackerHook = <-hookCh:
		if attackerHook.token != attackerToken {
			t.Fatalf("expected token %s, got %s", attackerToken, attackerHook.token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("attacker verification email hook not received")
	}

	// 2. Before verification, victim registers with their own password.
	recUser, recToken, err := svc.Signup(ctx, db.SignupRequest{
		Email:    targetEmail,
		Password: victimPass,
	})
	if err != nil {
		t.Fatalf("victim recovery signup failed: %v", err)
	}
	// Anti-enumeration: returns (nil, "", nil) on unverified recovery.
	if recUser != nil || recToken != "" {
		t.Fatalf("expected nil user and empty token for anti-enumeration, got user=%v token=%s", recUser, recToken)
	}

	var victimHook hookData
	select {
	case victimHook = <-hookCh:
		if victimHook.token == "" || victimHook.token == attackerToken {
			t.Fatalf("expected fresh victim token, got: %s", victimHook.token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("victim recovery verification email hook not received")
	}

	// 3. Attacker token must be purged from database; verifying with it must fail.
	oldTokenHash, err := crypto.HashToken(attackerToken)
	if err != nil {
		t.Fatalf("failed to hash attackerToken: %v", err)
	}
	var oldCount int64
	database.Model(&db.VerificationToken{}).Where("token_hash = ?", oldTokenHash[:]).Count(&oldCount)
	if oldCount != 0 {
		t.Fatalf("expected attacker verification token to be deleted, found %d", oldCount)
	}

	if err := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: attackerToken}); err == nil {
		t.Fatal("expected attacker token verification to fail, got nil")
	}

	// 4. Victim token must verify successfully and mark account verified.
	if err := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: victimHook.token}); err != nil {
		t.Fatalf("expected victim token verification to succeed, got %v", err)
	}

	var verifiedUser db.User
	if err := database.Where("id = ?", attackerUser.ID).First(&verifiedUser).Error; err != nil {
		t.Fatalf("failed to load user from db: %v", err)
	}
	if !verifiedUser.EmailVerified {
		t.Fatal("expected user email_verified to be true")
	}

	// 5. Attacker login with attackerPass MUST fail.
	_, err = svc.Login(ctx, db.LoginRequest{
		Email:    targetEmail,
		Password: attackerPass,
	})
	if err == nil {
		t.Fatal("expected attacker login to fail with invalid credentials, got nil")
	}
	var loginErr *errors.Error
	if !errors.As(err, &loginErr) || loginErr.Code() != errors.CodeInvalidCredentials {
		t.Fatalf("expected CodeInvalidCredentials for attacker login, got: %v", err)
	}

	// 6. Victim login with victimPass MUST succeed.
	loggedInUser, err := svc.Login(ctx, db.LoginRequest{
		Email:    targetEmail,
		Password: victimPass,
	})
	if err != nil {
		t.Fatalf("expected victim login to succeed, got: %v", err)
	}
	if loggedInUser == nil || loggedInUser.ID != attackerUser.ID {
		t.Fatalf("expected logged in user ID %s, got %v", attackerUser.ID, loggedInUser)
	}

	// 7. Post-verification: subsequent signups MUST NOT overwrite victim credentials or issue tokens.
	intruderPass := "IntruderPass#99999"
	dupUser, dupToken, err := svc.Signup(ctx, db.SignupRequest{
		Email:    targetEmail,
		Password: intruderPass,
	})
	if err != nil {
		t.Fatalf("expected silent success on duplicate signup, got: %v", err)
	}
	if dupUser != nil || dupToken != "" {
		t.Fatalf("expected nil user and empty token on verified duplicate signup")
	}

	select {
	case h := <-hookCh:
		t.Fatalf("unexpected verification email sent after verified duplicate signup: %v", h)
	default:
	}

	var postUser db.User
	if err := database.Where("id = ?", attackerUser.ID).First(&postUser).Error; err != nil {
		t.Fatalf("failed to query user post-verification: %v", err)
	}
	victimMatch, err := crypto.VerifyPassword(victimPass, postUser.PasswordHash)
	if err != nil || !victimMatch {
		t.Fatalf("expected victim password to remain unchanged post-verification: match=%v err=%v", victimMatch, err)
	}
}

func TestService_Signup_UnverifiedRecovery_AttackerCredentialBinding_ConcurrentRace(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()

	type hookData struct {
		recipient string
		token     string
	}
	hookCh := make(chan hookData, 10)
	hooks := email.Hooks{
		SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
			hookCh <- hookData{recipient: recipient, token: token}
			return nil
		},
	}

	authSvc, err := New(cfg, database, hooks)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	svc := authSvc.(*authService)
	ctx := context.Background()

	targetEmail := "victim_race@example.com"
	attackerPass := "AttackerPass#12345"
	victimPass := "VictimPass#67890"

	user, attackerToken, err := svc.Signup(ctx, db.SignupRequest{
		Email:    targetEmail,
		Password: attackerPass,
	})
	if err != nil {
		t.Fatalf("initial attacker signup failed: %v", err)
	}
	if user == nil || attackerToken == "" {
		t.Fatal("expected attacker user and token")
	}

	select {
	case <-hookCh:
	case <-time.After(2 * time.Second):
		t.Fatal("attacker verification email hook not received")
	}

	// Concurrently attempt multiple victim registrations (recovery)
	const concurrentAttempts = 5
	var wg sync.WaitGroup
	wg.Add(concurrentAttempts)

	for i := 0; i < concurrentAttempts; i++ {
		go func(idx int) {
			defer wg.Done()
			_, _, _ = svc.Signup(ctx, db.SignupRequest{
				Email:    targetEmail,
				Password: fmt.Sprintf("%s_%d", victimPass, idx),
			})
		}(i)
	}

	wg.Wait()

	// Drain hookCh and collect verification tokens sent
	var tokensInDB []db.VerificationToken
	if err := database.Where("user_id = ?", user.ID).Find(&tokensInDB).Error; err != nil {
		t.Fatalf("failed to query tokens: %v", err)
	}

	var latestUser db.User
	if err := database.Where("id = ?", user.ID).First(&latestUser).Error; err != nil {
		t.Fatalf("failed to query user: %v", err)
	}

	if latestUser.EmailVerified {
		t.Fatal("user should still be unverified before token verification")
	}

	// Exactly 1 active verification token must exist in DB (each recovery deletes prior tokens)
	if len(tokensInDB) != 1 {
		t.Fatalf("expected exactly 1 verification token for unverified user, found %d", len(tokensInDB))
	}

	// Attacker old token must not match the remaining token in DB
	oldHash, _ := crypto.HashToken(attackerToken)
	if string(tokensInDB[0].TokenHash) == string(oldHash[:]) {
		t.Fatal("attacker old token unexpectedly remained in database")
	}

	// Attacker old token verification must fail
	if err := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: attackerToken}); err == nil {
		t.Fatal("expected attacker token verification to fail, got nil")
	}

	// Attacker login must fail
	_, err = svc.Login(ctx, db.LoginRequest{
		Email:    targetEmail,
		Password: attackerPass,
	})
	if err == nil {
		t.Fatal("expected attacker login to fail")
	}
}

