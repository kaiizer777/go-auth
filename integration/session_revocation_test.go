//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/db"
)

func TestInvalidateAllUserSessions_BumpsVersion_Postgres(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	userID := uuid.New()
	if err := database.Create(&db.User{
		ID:                userID,
		Email:             userID.String() + "@example.com",
		PasswordHash:      "hash",
		CredentialVersion: 0,
		EmailVerified:     true,
	}).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	// Create a few sessions via the service.
	for i := 0; i < 3; i++ {
		_, _, err := authInst.Session.CreateSession(ctx, userID, 0, db.SessionTypeCookie, "127.0.0.1", "agent")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
	}

	if err := authInst.Session.InvalidateAllUserSessions(ctx, userID); err != nil {
		t.Fatalf("InvalidateAllUserSessions failed: %v", err)
	}

	var count int64
	if err := database.Model(&db.Session{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		t.Fatalf("failed to count sessions: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected sessions deleted, found %d", count)
	}

	var user db.User
	if err := database.Where("id = ?", userID).First(&user).Error; err != nil {
		t.Fatalf("failed to load user: %v", err)
	}
	if user.CredentialVersion != 1 {
		t.Fatalf("expected credential_version 1, got %d", user.CredentialVersion)
	}

	// Missing user no-op success.
	missingID := uuid.New()
	if err := authInst.Session.InvalidateAllUserSessions(ctx, missingID); err != nil {
		t.Fatalf("expected no-op success for missing user, got %v", err)
	}
}

func TestInvalidateAllUserSessions_RaceWithRotate_Postgres(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	userID := uuid.New()
	if err := database.Create(&db.User{
		ID:                userID,
		Email:             userID.String() + "@example.com",
		PasswordHash:      "hash",
		CredentialVersion: 0,
		EmailVerified:     true,
	}).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	_, rawID, err := authInst.Session.CreateSession(ctx, userID, 0, db.SessionTypeCookie, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	var mu sync.Mutex
	current := rawID
	var rotations int

	// Rotate in a loop.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			mu.Lock()
			tok := current
			mu.Unlock()
			sess, newTok, err := authInst.Session.RotateSession(ctx, tok, "2.2.2.2", "agent-new")
			if err == nil && sess != nil && newTok != "" {
				mu.Lock()
				current = newTok
				rotations++
				mu.Unlock()
			}
		}
	}()

	// Revoke after a short delay.
	time.Sleep(10 * time.Millisecond)
	if err := authInst.Session.InvalidateAllUserSessions(ctx, userID); err != nil {
		t.Fatalf("InvalidateAllUserSessions failed: %v", err)
	}
	close(done)
	wg.Wait()

	mu.Lock()
	n := rotations
	mu.Unlock()
	if n == 0 {
		t.Fatal("expected at least one successful rotation")
	}

	// Invariant: every surviving session row must carry the current credential version.
	var user db.User
	if err := database.Where("id = ?", userID).First(&user).Error; err != nil {
		t.Fatalf("failed to load user: %v", err)
	}
	var stale int64
	if err := database.Model(&db.Session{}).Where("user_id = ? AND credential_version <> ?", userID, user.CredentialVersion).Count(&stale).Error; err != nil {
		t.Fatalf("failed to count stale sessions: %v", err)
	}
	if stale != 0 {
		t.Fatalf("found %d surviving sessions with stale credential version", stale)
	}
}
