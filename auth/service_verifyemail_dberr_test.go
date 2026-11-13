package auth

import (
	"context"
	"testing"

	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// TestService_VerifyEmail_DBErrors covers DB error on lookup, user update error,
// and RowsAffected==0 (concurrent token consumption).
func TestService_VerifyEmail_DBErrors(t *testing.T) {
	t.Run("token lookup DB error returns CodeDatabaseError", func(t *testing.T) {
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

		if err := database.Exec("DROP TABLE verification_tokens").Error; err != nil {
			t.Fatalf("failed to drop verification_tokens: %v", err)
		}

		err = svc.VerifyEmail(context.Background(), db.VerifyEmailRequest{Token: rawToken})
		if err == nil {
			t.Fatal("expected error on table drop, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})

	t.Run("user update DB error returns CodeDatabaseError", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		ctx := context.Background()

		_, rawToken, err := svc.Signup(ctx, db.SignupRequest{
			Email:    "updateerr@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		// Drop users so the UPDATE email_verified call inside the transaction fails.
		// The token still exists, so First() finds it, Delete succeeds, then Update fails.
		if err := database.Exec("DROP TABLE users").Error; err != nil {
			t.Fatalf("failed to drop users table: %v", err)
		}

		err = svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: rawToken})
		if err == nil {
			t.Fatal("expected error when users table is dropped, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})

	t.Run("RowsAffected==0 on delete returns CodeInvalidToken (token pre-consumed)", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		ctx := context.Background()

		_, rawToken, err := svc.Signup(ctx, db.SignupRequest{
			Email:    "concurrentverify@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err != nil {
			t.Fatalf("signup failed: %v", err)
		}

		// Verify once: succeeds, token deleted.
		if verr := svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: rawToken}); verr != nil {
			t.Fatalf("first VerifyEmail failed unexpectedly: %v", verr)
		}

		// Second attempt: token is gone → CodeInvalidToken (observable outcome of
		// concurrent token consumption / RowsAffected==0 path).
		err = svc.VerifyEmail(ctx, db.VerifyEmailRequest{Token: rawToken})
		if err == nil {
			t.Fatal("expected CodeInvalidToken on replay, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
			t.Fatalf("expected CodeInvalidToken, got %v", err)
		}
	})
}
