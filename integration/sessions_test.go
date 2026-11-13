//go:build integration

package integration

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
)

func TestSessions_PersistenceAndForeignKeyCascade(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	// 1. Create a user
	user, _, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "session-owner@example.com",
		Password: "InitialPassword123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	// 2. Insert active session record in PostgreSQL sessions table
	_, sessionTokenHash, err := crypto.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	sessionHashHex := hex.EncodeToString(sessionTokenHash[:])

	session := db.Session{
		ID:            uuid.New(),
		UserID:        user.ID,
		TokenHash:     sessionHashHex,
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
		IdleExpiresAt: time.Now().UTC().Add(2 * time.Hour),
		CreatedAt:     time.Now().UTC(),
	}

	if err := database.Create(&session).Error; err != nil {
		t.Fatalf("failed to insert session: %v", err)
	}

	// 3. Query session back
	var queriedSession db.Session
	if err := database.Where("token_hash = ?", sessionHashHex).First(&queriedSession).Error; err != nil {
		t.Fatalf("failed to query session by token_hash: %v", err)
	}
	if queriedSession.UserID != user.ID {
		t.Fatalf("expected user ID %s, got %s", user.ID, queriedSession.UserID)
	}

	// 4. Unique token_hash constraint check: inserting another session with identical token_hash must fail
	duplicateSession := db.Session{
		ID:            uuid.New(),
		UserID:        user.ID,
		TokenHash:     sessionHashHex,
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
		IdleExpiresAt: time.Now().UTC().Add(2 * time.Hour),
		CreatedAt:     time.Now().UTC(),
	}
	if err := database.Create(&duplicateSession).Error; err == nil {
		t.Fatal("expected duplicate session token_hash insertion to fail unique constraint, got nil")
	}

	// 5. Foreign Key CASCADE deletion: deleting user must automatically delete dependent sessions
	if err := database.Where("id = ?", user.ID).Delete(&db.User{}).Error; err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	var sessionCount int64
	if err := database.Model(&db.Session{}).Where("user_id = ?", user.ID).Count(&sessionCount).Error; err != nil {
		t.Fatalf("counting sessions after user deletion failed: %v", err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected 0 sessions after user cascade delete, found %d", sessionCount)
	}
}

func TestSessions_LogoutContract(t *testing.T) {
	_, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	// Verify Logout contract (stubbed for Phase 4 session management, returns nil)
	if err := authInst.Auth.Logout(ctx, "session-id-12345"); err != nil {
		t.Fatalf("Logout returned unexpected error: %v", err)
	}
}
