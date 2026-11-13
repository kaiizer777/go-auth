package auth

import (
	"context"
	"testing"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// TestService_RequestPasswordReset_DBErrors covers DB errors on user lookup
// and token creation.
func TestService_RequestPasswordReset_DBErrors(t *testing.T) {
	t.Run("user lookup DB error returns CodeDatabaseError", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		if err := database.Exec("DROP TABLE users").Error; err != nil {
			t.Fatalf("failed to drop users table: %v", err)
		}

		_, err = svc.RequestPasswordReset(context.Background(), db.PasswordResetRequest{
			Email: "anyone@example.com",
		})
		if err == nil {
			t.Fatal("expected error on users table drop, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})

	t.Run("token create DB error returns CodeDatabaseError", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		ctx := context.Background()

		_, _, err = svc.Signup(ctx, db.SignupRequest{
			Email:    "tokcreateerr@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		// Drop the reset tokens table so Create(&resetToken) fails.
		if err := database.Exec("DROP TABLE password_reset_tokens").Error; err != nil {
			t.Fatalf("failed to drop password_reset_tokens: %v", err)
		}

		_, err = svc.RequestPasswordReset(ctx, db.PasswordResetRequest{
			Email: "tokcreateerr@example.com",
		})
		if err == nil {
			t.Fatal("expected error on password_reset_tokens drop, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})
}
