package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// TestService_ResetPassword_DBErrors covers DB errors on cheap-gate lookup,
// RowsAffected==0 sub-branches (expired count>0 and count==0), and password
// hash update error in the transaction.
func TestService_ResetPassword_DBErrors(t *testing.T) {
	t.Run("cheap-gate lookup DB error returns CodeDatabaseError", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		rawToken, _, gerr := crypto.GenerateToken()
		if gerr != nil {
			t.Fatalf("failed to generate token: %v", gerr)
		}

		if err := database.Exec("DROP TABLE password_reset_tokens").Error; err != nil {
			t.Fatalf("failed to drop password_reset_tokens: %v", err)
		}

		err = svc.ResetPassword(context.Background(), db.PasswordResetConfirmRequest{
			Token:       rawToken,
			NewPassword: "BrandNewPassword#2026!",
		})
		if err == nil {
			t.Fatal("expected error on table drop, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})

	t.Run("expired token (count>0 path) returns CodeTokenExpired", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		ctx := context.Background()

		_, _, err = svc.Signup(ctx, db.SignupRequest{
			Email:    "expiredtx@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		rawToken, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{
			Email: "expiredtx@example.com",
		})
		if err != nil {
			t.Fatalf("RequestPasswordReset failed: %v", err)
		}

		rawBytes, _ := hex.DecodeString(rawToken)
		tokenHash := sha256.Sum256(rawBytes)

		// Expire the token: cheap gate's time.Now().After(tok.ExpiresAt) fires →
		// deletes token and returns CodeTokenExpired (count>0 branch).
		past := time.Now().UTC().Add(-1 * time.Hour)
		if err := database.Exec(
			"UPDATE password_reset_tokens SET expires_at = ? WHERE token_hash = ?",
			past, tokenHash[:],
		).Error; err != nil {
			t.Fatalf("failed to expire token: %v", err)
		}

		err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{
			Token:       rawToken,
			NewPassword: "BrandNewPassword#2026!",
		})
		if err == nil {
			t.Fatal("expected CodeTokenExpired, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeTokenExpired {
			t.Fatalf("expected CodeTokenExpired, got %v", err)
		}
	})

	t.Run("consumed token (count==0 path) returns CodeInvalidToken", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		ctx := context.Background()

		_, _, err = svc.Signup(ctx, db.SignupRequest{
			Email:    "concurrentreset@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		rawToken, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{
			Email: "concurrentreset@example.com",
		})
		if err != nil {
			t.Fatalf("RequestPasswordReset failed: %v", err)
		}

		// First ResetPassword succeeds and purges the token.
		if err := svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{
			Token:       rawToken,
			NewPassword: "BrandNewPassword#2026!",
		}); err != nil {
			t.Fatalf("first ResetPassword failed: %v", err)
		}

		// Second attempt: cheap-gate First() finds no row → CodeInvalidToken
		// (observable outcome of concurrent token consumption / count==0 path).
		err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{
			Token:       rawToken,
			NewPassword: "AnotherNewPassword#2026!",
		})
		if err == nil {
			t.Fatal("expected CodeInvalidToken on replay, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("expected CodeInvalidToken, got %v", err)
		}
	})

	t.Run("password hash update error in transaction returns CodeDatabaseError", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		ctx := context.Background()

		_, _, err = svc.Signup(ctx, db.SignupRequest{
			Email:    "hashupdateerr@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		rawToken, err := svc.RequestPasswordReset(ctx, db.PasswordResetRequest{
			Email: "hashupdateerr@example.com",
		})
		if err != nil {
			t.Fatalf("RequestPasswordReset failed: %v", err)
		}

		// Drop users table: cheap-gate First() on password_reset_tokens succeeds,
		// transaction DELETE on password_reset_tokens succeeds (RowsAffected>0),
		// then UPDATE on users fails → wrapped CodeDatabaseError.
		if err := database.Exec("DROP TABLE users").Error; err != nil {
			t.Fatalf("failed to drop users table: %v", err)
		}

		err = svc.ResetPassword(ctx, db.PasswordResetConfirmRequest{
			Token:       rawToken,
			NewPassword: "BrandNewPassword#2026!",
		})
		if err == nil {
			t.Fatal("expected error when users table is dropped, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})
}
