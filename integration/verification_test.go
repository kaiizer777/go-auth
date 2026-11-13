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

func TestVerification_BYTEAPrimaryKeyAndSuccessfulFlow(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	// 1. Register user
	user, rawToken, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "verify-test@example.com",
		Password: "CorrectHorseBatteryStaple123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	// 2. Inspect BYTEA primary key in PostgreSQL verification_tokens table
	tokenHash, err := crypto.HashToken(rawToken)
	if err != nil {
		t.Fatalf("HashToken failed: %v", err)
	}

	var tok db.VerificationToken
	if err := database.Where("token_hash = ?", tokenHash[:]).First(&tok).Error; err != nil {
		t.Fatalf("querying verification token by BYTEA PK failed: %v", err)
	}
	if tok.UserID != user.ID {
		t.Fatalf("expected token user ID %s, got %s", user.ID, tok.UserID)
	}

	// 3. Verify email with raw token
	err = authInst.Auth.VerifyEmail(ctx, db.VerifyEmailRequest{
		Token: rawToken,
	})
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	// 4. Invariant checks post-verification:
	// - Token row must be consumed/deleted from verification_tokens table
	var count int64
	database.Model(&db.VerificationToken{}).Where("token_hash = ?", tokenHash[:]).Count(&count)
	if count != 0 {
		t.Fatalf("expected token row to be deleted after verification, found %d", count)
	}

	// - User email_verified must now be true in PostgreSQL
	var updatedUser db.User
	if err := database.Where("id = ?", user.ID).First(&updatedUser).Error; err != nil {
		t.Fatalf("querying user failed: %v", err)
	}
	if !updatedUser.EmailVerified {
		t.Fatal("expected email_verified to be true after verification")
	}

	// 5. Replay attempt: verifying the same token again must fail with CodeInvalidToken
	err = authInst.Auth.VerifyEmail(ctx, db.VerifyEmailRequest{
		Token: rawToken,
	})
	if err == nil {
		t.Fatal("expected replay of consumed token to fail, got nil error")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeInvalidToken {
		t.Fatalf("expected CodeInvalidToken on replay, got: %v", err)
	}
}

func TestVerification_ExpiredTokenPurgedAndRejected(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	_, rawToken, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "expired-verify@example.com",
		Password: "CorrectHorseBatteryStaple123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	tokenHash, err := crypto.HashToken(rawToken)
	if err != nil {
		t.Fatalf("HashToken failed: %v", err)
	}

	// Fast-forward token expiry in database to 1 hour in the past
	err = database.Model(&db.VerificationToken{}).
		Where("token_hash = ?", tokenHash[:]).
		Update("expires_at", time.Now().UTC().Add(-1*time.Hour)).Error
	if err != nil {
		t.Fatalf("updating token expires_at failed: %v", err)
	}

	// Verification attempt on expired token
	err = authInst.Auth.VerifyEmail(ctx, db.VerifyEmailRequest{
		Token: rawToken,
	})
	if err == nil {
		t.Fatal("expected error on expired token, got nil")
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeTokenExpired {
		t.Fatalf("expected CodeTokenExpired, got: %v", err)
	}

	// Verify expired token was purged from DB
	var count int64
	database.Model(&db.VerificationToken{}).Where("token_hash = ?", tokenHash[:]).Count(&count)
	if count != 0 {
		t.Fatalf("expected expired token to be purged from DB, found %d", count)
	}
}

func TestVerification_ConcurrentReplayRace(t *testing.T) {
	_, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	_, rawToken, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "race-verify@example.com",
		Password: "CorrectHorseBatteryStaple123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	const concurrency = 8
	var wg sync.WaitGroup
	var successCount atomic.Int32
	var invalidTokenCount atomic.Int32

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := authInst.Auth.VerifyEmail(context.Background(), db.VerifyEmailRequest{
				Token: rawToken,
			})
			if err == nil {
				successCount.Add(1)
				return
			}
			var appErr *errors.Error
			if errors.As(err, &appErr) && appErr.Code() == errors.CodeInvalidToken {
				invalidTokenCount.Add(1)
			}
		}()
	}

	wg.Wait()

	if successCount.Load() != 1 {
		t.Fatalf("expected exactly 1 verification success under race, got %d", successCount.Load())
	}
	if invalidTokenCount.Load() != concurrency-1 {
		t.Fatalf("expected %d invalid token rejections, got %d", concurrency-1, invalidTokenCount.Load())
	}
}
