package matrix_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

func TestMatrix_ClaimedEmailLifecycle(t *testing.T) {
	runMatrix(t, func(t *testing.T, adapter TestAdapter) {
		ctx := context.Background()
		store := adapter.Store
		suffix := uuid.New().String()[:8]
		addr := "claimed_" + suffix + "@example.com"
		owner := createTestUser(t, store, "claim_owner_"+suffix+"@example.com", "Password#2026!", true)
		rival := createTestUser(t, store, "claim_rival_"+suffix+"@example.com", "Password#2026!", true)

		// The key is the Go-normalised address on every adapter.
		if err := store.ClaimedEmails().Claim(ctx, "  "+strings.ToUpper(addr)+" ", owner.ID, false); err != nil {
			t.Fatalf("claim: %v", err)
		}
		claim, err := store.ClaimedEmails().Get(ctx, addr)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if claim.OwnerUserID != owner.ID || claim.Verified {
			t.Fatalf("claim = %+v; want holder %v, unverified", claim, owner.ID)
		}
		if err := store.ClaimedEmails().Claim(ctx, addr, owner.ID, false); err != nil {
			t.Fatalf("same-owner re-claim: %v", err)
		}
		if err := store.ClaimedEmails().Claim(ctx, addr, owner.ID, true); err != nil {
			t.Fatalf("promote: %v", err)
		}
		if claim, err = store.ClaimedEmails().Get(ctx, addr); err != nil || !claim.Verified {
			t.Fatalf("claim after promote = %+v, %v; want verified", claim, err)
		}
		if err := store.ClaimedEmails().Claim(ctx, addr, rival.ID, true); !errors.Is(err, errors.ErrEmailClaimed) {
			t.Fatalf("foreign claim = %v; want ErrEmailClaimed", err)
		}
		if err := store.ClaimedEmails().Claim(ctx, "   ", owner.ID, true); err != nil {
			t.Fatalf("empty claim: %v", err)
		}

		// A non-holder's release is a no-op; the holder's frees the address.
		if err := store.ClaimedEmails().Release(ctx, addr, rival.ID); err != nil {
			t.Fatalf("foreign release: %v", err)
		}
		if _, err := store.ClaimedEmails().Get(ctx, addr); err != nil {
			t.Fatalf("claim disappeared after a foreign release: %v", err)
		}
		if err := store.ClaimedEmails().Release(ctx, addr, owner.ID); err != nil {
			t.Fatalf("release: %v", err)
		}
		if _, err := store.ClaimedEmails().Get(ctx, addr); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("claim after release, err = %v; want not found", err)
		}

		// Deleting the holder releases its claims, and the address becomes
		// claimable by another account.
		if err := store.ClaimedEmails().Claim(ctx, addr, rival.ID, true); err != nil {
			t.Fatalf("re-claim: %v", err)
		}
		if err := store.Users().Delete(ctx, rival.ID); err != nil {
			t.Fatalf("delete holder: %v", err)
		}
		if _, err := store.ClaimedEmails().Get(ctx, addr); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("claim survived its holder's deletion, err = %v", err)
		}
		if err := store.ClaimedEmails().Claim(ctx, addr, owner.ID, false); err != nil {
			t.Fatalf("claim after deletion: %v", err)
		}
	})
}

func TestMatrix_UserLifecycle(t *testing.T) {
	runMatrix(t, func(t *testing.T, adapter TestAdapter) {
		ctx := context.Background()
		app := adapter.App
		store := adapter.Store

		email := fmt.Sprintf("matrix_lifecycle_%s@example.com", uuid.New().String()[:8])
		password := "SuperSecure#2026!"

		// 1. Registration
		user, rawToken, err := app.Auth.Signup(ctx, db.SignupRequest{
			Email:    email,
			Password: password,
		})
		if err != nil {
			t.Fatalf("Signup failed: %v", err)
		}
		if user == nil {
			t.Fatal("expected non-nil user from Signup")
		}
		if rawToken == "" {
			t.Fatal("expected non-empty verification token from Signup")
		}
		if user.EmailVerified {
			t.Fatal("expected email_verified = false on initial signup")
		}
		if user.CredentialVersion != 0 {
			t.Fatalf("expected credential_version = 0, got %d", user.CredentialVersion)
		}

		// Verify hashed token persisted
		tokenHash, err := crypto.HashToken(rawToken)
		if err != nil {
			t.Fatalf("crypto.HashToken failed: %v", err)
		}
		vTok, err := store.VerificationTokens().GetByTokenHash(ctx, tokenHash[:])
		if err != nil {
			t.Fatalf("failed to retrieve verification token: %v", err)
		}
		if vTok.UserID != user.ID {
			t.Fatalf("verification token user mismatch: got %v, want %v", vTok.UserID, user.ID)
		}

		// 2. Email Verification
		_, err = app.Auth.VerifyEmail(ctx, db.VerifyEmailRequest{
			Token: rawToken,
		})
		if err != nil {
			t.Fatalf("VerifyEmail failed: %v", err)
		}

		// Assert user email_verified transitioned to true
		verifiedUser, err := store.Users().GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("failed to get user after verification: %v", err)
		}
		if !verifiedUser.EmailVerified {
			t.Fatal("expected email_verified = true after verification")
		}

		// Assert verification token permanently expunged
		_, err = store.VerificationTokens().GetByTokenHash(ctx, tokenHash[:])
		if err == nil {
			t.Fatal("expected verification token to be expunged after consumption, but found it")
		}

		// 3. Login
		loggedInUser, err := app.Auth.Login(ctx, db.LoginRequest{
			Email:    email,
			Password: password,
		})
		if err != nil {
			t.Fatalf("Login failed: %v", err)
		}
		if loggedInUser.ID != user.ID {
			t.Fatalf("login user mismatch: got %v, want %v", loggedInUser.ID, user.ID)
		}

		// Invalid password returns ErrInvalidCredentials
		_, err = app.Auth.Login(ctx, db.LoginRequest{
			Email:    email,
			Password: "WrongPassword123!",
		})
		if !errors.Is(err, errors.ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials for wrong password, got %v", err)
		}

		// 4. Session Creation & Validation
		sess, rawSessionToken, err := app.Session.CreateSession(ctx, verifiedUser.ID, verifiedUser.CredentialVersion, db.SessionTypeBearer, "127.0.0.1", "MatrixUserAgent/1.0")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		if rawSessionToken == "" || sess == nil {
			t.Fatal("CreateSession returned empty session token or nil session")
		}

		// Validate session
		retrievedSess, err := app.Session.GetSession(ctx, rawSessionToken)
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}
		if retrievedSess.UserID != user.ID {
			t.Fatalf("session user mismatch: got %v, want %v", retrievedSess.UserID, user.ID)
		}
		if retrievedSess.IPAddress != "127.0.0.1" {
			t.Fatalf("session IP mismatch: got %s, want 127.0.0.1", retrievedSess.IPAddress)
		}

		// 5. Logout (Hard-Delete Session)
		err = app.Session.InvalidateSession(ctx, rawSessionToken)
		if err != nil {
			t.Fatalf("InvalidateSession failed: %v", err)
		}

		// Validation after invalidation fails
		_, err = app.Session.GetSession(ctx, rawSessionToken)
		if err == nil {
			t.Fatal("expected GetSession to fail after InvalidateSession, but succeeded")
		}

		// Database inspection: hard deletion asserted (zero rows remaining)
		_, err = store.Sessions().GetByID(ctx, sess.ID)
		if err == nil {
			t.Fatal("expected session row/document to be hard-deleted from database, but found it")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("expected ErrRecordNotFound for session, got: %v", err)
		}
	})
}
