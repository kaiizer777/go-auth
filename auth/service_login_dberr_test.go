package auth

import (
	"context"
	"testing"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// TestService_Login_DBErrors covers the non-NotFound DB error on the user lookup.
func TestService_Login_DBErrors(t *testing.T) {
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

		_, err = svc.Login(context.Background(), db.LoginRequest{
			Email:    "anyone@example.com",
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
}
