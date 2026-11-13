//go:build integration

package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

func TestPasswordReset_BYTEAPrimaryKeyAndASVSPurge(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	// 1. Create verified user
	user, verifyToken, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "reset-test@example.com",
		Password: "InitialPassword123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	if err := authInst.Auth.VerifyEmail(ctx, db.VerifyEmailRequest{Token: verifyToken}); err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	// 2. Request first reset token
	rawResetToken1, err := authInst.Auth.RequestPasswordReset(ctx, db.PasswordResetRequest{
		Email: "reset-test@example.com",
	})
	if err != nil {
		t.Fatalf("RequestPasswordReset 1 failed: %v", err)
	}
	if rawResetToken1 == "" {
		t.Fatal("expected non-empty reset token 1")
	}

	// Request second reset token for same user (sibling token)
	rawResetToken2, err := authInst.Auth.RequestPasswordReset(ctx, db.PasswordResetRequest{
		Email: "reset-test@example.com",
	})
	if err != nil {
		t.Fatalf("RequestPasswordReset 2 failed: %v", err)
	}
	if rawResetToken2 == "" {
		t.Fatal("expected non-empty reset token 2")
	}

	// Verify both tokens exist in password_reset_tokens table with BYTEA PK
	tokenHash1, _ := crypto.HashToken(rawResetToken1)
	tokenHash2, _ := crypto.HashToken(rawResetToken2)

	var activeCount int64
	database.Model(&db.PasswordResetToken{}).Where("user_id = ?", user.ID).Count(&activeCount)
	if activeCount != 2 {
		t.Fatalf("expected 2 active reset tokens in DB, found %d", activeCount)
	}

	// 3. Confirm password reset using rawResetToken1
	newPassword := "NewVerySecurePass123!"
	err = authInst.Auth.ResetPassword(ctx, db.PasswordResetConfirmRequest{
		Token:       rawResetToken1,
		NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// 4. Invariants check:
	// - ASVS L1 token purge: BOTH token 1 and sibling token 2 must be purged
	var remainingCount int64
	database.Model(&db.PasswordResetToken{}).Where("user_id = ?", user.ID).Count(&remainingCount)
	if remainingCount != 0 {
		t.Fatalf("expected 0 reset tokens after ASVS L1 purge, found %d", remainingCount)
	}

	// - Token 1 cannot be replayed
	err = authInst.Auth.ResetPassword(ctx, db.PasswordResetConfirmRequest{
		Token:       rawResetToken1,
		NewPassword: "AnotherPassword123!",
	})
	if err == nil {
		t.Fatal("expected error on replaying token 1, got nil")
	}

	// - Sibling token 2 is also invalid
	err = authInst.Auth.ResetPassword(ctx, db.PasswordResetConfirmRequest{
		Token:       rawResetToken2,
		NewPassword: "AnotherPassword123!",
	})
	if err == nil {
		t.Fatal("expected sibling token 2 to be invalidated by ASVS L1 purge, got nil")
	}

	// - User can now log in with the new password
	loggedInUser, err := authInst.Auth.Login(ctx, db.LoginRequest{
		Email:    "reset-test@example.com",
		Password: newPassword,
	})
	if err != nil {
		t.Fatalf("Login with new password failed: %v", err)
	}
	if loggedInUser.ID != user.ID {
		t.Fatalf("expected logged in user ID %s, got %s", user.ID, loggedInUser.ID)
	}

	// - Login with old password fails
	_, err = authInst.Auth.Login(ctx, db.LoginRequest{
		Email:    "reset-test@example.com",
		Password: "InitialPassword123!",
	})
	if err == nil {
		t.Fatal("expected login with old password to fail, got nil error")
	}
	_ = tokenHash1
	_ = tokenHash2
}

func TestPasswordReset_ExpiredTokenPurge(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	_, _, err = authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "expired-reset@example.com",
		Password: "InitialPassword123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	rawToken, err := authInst.Auth.RequestPasswordReset(ctx, db.PasswordResetRequest{
		Email: "expired-reset@example.com",
	})
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	tokenHash, err := crypto.HashToken(rawToken)
	if err != nil {
		t.Fatalf("HashToken failed: %v", err)
	}

	// Expire token in DB
	err = database.Model(&db.PasswordResetToken{}).
		Where("token_hash = ?", tokenHash[:]).
		Update("expires_at", time.Now().UTC().Add(-1*time.Hour)).Error
	if err != nil {
		t.Fatalf("updating expires_at failed: %v", err)
	}

	// Attempt reset
	err = authInst.Auth.ResetPassword(ctx, db.PasswordResetConfirmRequest{
		Token:       rawToken,
		NewPassword: "NewValidPassword123!",
	})
	if err == nil {
		t.Fatal("expected error on expired reset token, got nil")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeTokenExpired {
		t.Fatalf("expected CodeTokenExpired, got: %v", err)
	}

	// Verify token row was purged
	var count int64
	database.Model(&db.PasswordResetToken{}).Where("token_hash = ?", tokenHash[:]).Count(&count)
	if count != 0 {
		t.Fatalf("expected expired reset token to be purged, found %d", count)
	}
}

func TestPasswordReset_ConcurrentResetRace(t *testing.T) {
	_, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	_, _, err = authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "race-reset@example.com",
		Password: "InitialPassword123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	rawToken, err := authInst.Auth.RequestPasswordReset(ctx, db.PasswordResetRequest{
		Email: "race-reset@example.com",
	})
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	const concurrency = 8
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var rejectedCount atomic.Int32

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := authInst.Auth.ResetPassword(context.Background(), db.PasswordResetConfirmRequest{
				Token:       rawToken,
				NewPassword: "ConcurrentSuccessPassword123!",
			})
			if err == nil {
				successCount.Add(1)
			} else {
				rejectedCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if successCount.Load() != 1 {
		t.Fatalf("expected exactly 1 reset success under race, got %d", successCount.Load())
	}
	if rejectedCount.Load() != concurrency-1 {
		t.Fatalf("expected %d rejected resets, got %d", concurrency-1, rejectedCount.Load())
	}
}
