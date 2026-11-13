package auth

import (
	"context"
	"testing"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// TestService_Signup_DBErrors covers the DB-error and transaction-failure branches
// in Signup that are not reachable via happy-path or validation tests.
func TestService_Signup_DBErrors(t *testing.T) {
	t.Run("initial lookup DB error returns CodeDatabaseError", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		// Corrupt the users table so queries fail with a real DB error.
		if err := database.Exec("DROP TABLE users").Error; err != nil {
			t.Fatalf("failed to drop users table: %v", err)
		}

		_, _, err = svc.Signup(context.Background(), db.SignupRequest{
			Email:    "dberr@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err == nil {
			t.Fatal("expected error on users table drop, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})

	t.Run("transaction failure with no concurrent user returns CodeDatabaseError", func(t *testing.T) {
		database := setupTestDB(t)
		cfg := testConfig()
		svc, err := New(cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}

		// Drop verification_tokens so Create(&tok) inside the transaction fails,
		// and the post-failure re-query on users finds no row (not a concurrent
		// signup) → returns wrapped CodeDatabaseError.
		if err := database.Exec("DROP TABLE verification_tokens").Error; err != nil {
			t.Fatalf("failed to drop verification_tokens: %v", err)
		}

		_, _, err = svc.Signup(context.Background(), db.SignupRequest{
			Email:    "txerr@example.com",
			Password: "SecureAlpha#2026!",
		})
		if err == nil {
			t.Fatal("expected error on verification_tokens drop, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeDatabaseError {
			t.Fatalf("expected CodeDatabaseError, got %v", err)
		}
	})
}
