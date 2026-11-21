package matrix_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

func TestMatrix_SessionManagement(t *testing.T) {
	runMatrix(t, func(t *testing.T, adapter TestAdapter) {
		ctx := context.Background()
		app := adapter.App
		store := adapter.Store

		user := createTestUser(t, store, fmt.Sprintf("matrix_sessions_%s@example.com", uuid.New().String()[:8]), "Password#2026!", true)

		// 1. Concurrent Session Creation
		const concurrentSessions = 5
		type sessResult struct {
			token string
			sess  *session.Session
			err   error
		}
		resChan := make(chan sessResult, concurrentSessions)
		var wg sync.WaitGroup
		wg.Add(concurrentSessions)

		for i := 0; i < concurrentSessions; i++ {
			go func(idx int) {
				defer wg.Done()
				ua := fmt.Sprintf("Agent-%d", idx)
				ip := fmt.Sprintf("192.168.1.%d", 10+idx)
				s, tok, err := app.Session.CreateSession(ctx, user.ID, 0, db.SessionTypeBearer, ip, ua)
				resChan <- sessResult{token: tok, sess: s, err: err}
			}(i)
		}
		wg.Wait()
		close(resChan)

		var createdSessions []*session.Session
		var tokens []string
		for res := range resChan {
			if res.err != nil {
				t.Fatalf("concurrent CreateSession failed: %v", res.err)
			}
			createdSessions = append(createdSessions, res.sess)
			tokens = append(tokens, res.token)
		}

		if len(createdSessions) != concurrentSessions {
			t.Fatalf("expected %d sessions, got %d", concurrentSessions, len(createdSessions))
		}

		// Verify each token validates independently
		for _, tok := range tokens {
			s, err := app.Session.GetSession(ctx, tok)
			if err != nil {
				t.Fatalf("failed to validate concurrent session token %s: %v", tok, err)
			}
			if s.UserID != user.ID {
				t.Fatalf("session user mismatch: got %v, want %v", s.UserID, user.ID)
			}
		}

		// 2. ListByUserID
		activeSessions, err := store.Sessions().ListByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUserID failed: %v", err)
		}
		if len(activeSessions) < concurrentSessions {
			t.Fatalf("expected at least %d active sessions, got %d", concurrentSessions, len(activeSessions))
		}

		// 3. UpdateLastActive
		targetSess := createdSessions[0]
		newActiveTime := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Millisecond)
		err = store.Sessions().UpdateLastActive(ctx, targetSess.ID, newActiveTime)
		if err != nil {
			t.Fatalf("UpdateLastActive failed: %v", err)
		}

		updatedSess, err := store.Sessions().GetByID(ctx, targetSess.ID)
		if err != nil {
			t.Fatalf("GetByID failed: %v", err)
		}
		diff := updatedSess.LastActiveAt.Sub(newActiveTime)
		if diff < -time.Second || diff > time.Second {
			t.Fatalf("UpdateLastActive timestamp mismatch: got %v, want ~%v", updatedSess.LastActiveAt, newActiveTime)
		}

		// 4. User Deletion Cascade Verification
		err = store.Users().Delete(ctx, user.ID)
		if err != nil {
			t.Fatalf("Users().Delete failed: %v", err)
		}

		// Assert all user sessions are wiped via cascade
		remainingSessions, err := store.Sessions().ListByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUserID after user delete failed: %v", err)
		}
		if len(remainingSessions) != 0 {
			t.Fatalf("expected 0 sessions after user cascade delete, got %d", len(remainingSessions))
		}

		for _, s := range createdSessions {
			_, err := store.Sessions().GetByID(ctx, s.ID)
			if err == nil {
				t.Fatalf("expected session %s to be cascaded away, but still exists", s.ID)
			} else if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, mongo.ErrNoDocuments) {
				t.Fatalf("expected ErrRecordNotFound for session %s, got: %v", s.ID, err)
			}
		}

		// 5. Credential Version Verification and Serialization
		user2 := createTestUser(t, store, fmt.Sprintf("matrix_cred_%s@example.com", uuid.New().String()[:8]), "Password#2026!", true)

		// Create valid session with current version 0
		sValid, _, err := app.Session.CreateSession(ctx, user2.ID, 0, db.SessionTypeBearer, "127.0.0.1", "Agent-Cred")
		if err != nil || sValid == nil {
			t.Fatalf("CreateSession with current credential version failed: %v", err)
		}

		// Create session with stale credential version (e.g. 99)
		_, _, staleErr := app.Session.CreateSession(ctx, user2.ID, 99, db.SessionTypeBearer, "127.0.0.1", "Agent-Cred")
		if !errors.Is(staleErr, errors.ErrSessionInvalid) {
			t.Fatalf("expected ErrSessionInvalid on stale credential version mint, got: %v", staleErr)
		}

		// Invalidate all user sessions (bumps credential version to 1)
		if err := app.Session.InvalidateAllUserSessions(ctx, user2.ID); err != nil {
			t.Fatalf("InvalidateAllUserSessions failed: %v", err)
		}

		// Minting with previous version 0 now fails because version was bumped
		_, _, bumpedErr := app.Session.CreateSession(ctx, user2.ID, 0, db.SessionTypeBearer, "127.0.0.1", "Agent-Cred")
		if !errors.Is(bumpedErr, errors.ErrSessionInvalid) {
			t.Fatalf("expected ErrSessionInvalid after credential version bump, got: %v", bumpedErr)
		}

		// Minting with new version 1 succeeds
		sNew, _, err := app.Session.CreateSession(ctx, user2.ID, 1, db.SessionTypeBearer, "127.0.0.1", "Agent-Cred")
		if err != nil || sNew == nil {
			t.Fatalf("CreateSession with bumped credential version 1 failed: %v", err)
		}
	})
}
