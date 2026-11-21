package matrix_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

func TestMatrix_TransactionAbortAndRollback(t *testing.T) {
	runMatrix(t, func(t *testing.T, adapter TestAdapter) {
		if !adapter.SupportsTransactions {
			t.Skipf("Adapter %s does not support transactions; skipping atomicity test", adapter.Name)
		}

		ctx := context.Background()
		store := adapter.Store

		// Scenario 1: Multi-Step Mutation with Fault Injection Midway
		userAID := uuid.New()
		userAEmail := fmt.Sprintf("tx_rollback_%s@example.com", uuid.New().String()[:8])
		sessID := uuid.New()

		simulatedErr := fmt.Errorf("injected fault midway through transaction")

		txErr := store.Transaction(ctx, func(txStore db.Store) error {
			// Step 1: Create User
			u := &db.User{
				ID:                userAID,
				Email:             userAEmail,
				PasswordHash:      "hashed_dummy_pw",
				CredentialVersion: 0,
				EmailVerified:     true,
				CreatedAt:         time.Now().UTC(),
				UpdatedAt:         time.Now().UTC(),
			}
			if err := txStore.Users().Create(ctx, u); err != nil {
				return err
			}

			// Step 2: Create Session
			sess := &db.Session{
				ID:                sessID,
				UserID:            userAID,
				IDHash:            fmt.Sprintf("tx_hash_%s", uuid.New().String()),
				SessionType:       db.SessionTypeBearer,
				IPAddress:         "127.0.0.1",
				UserAgent:         "TxTestAgent",
				CredentialVersion: 0,
				LastActiveAt:      time.Now().UTC(),
				AbsoluteExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
				CreatedAt:         time.Now().UTC(),
			}
			if err := txStore.Sessions().Create(ctx, sess); err != nil {
				return err
			}

			// Step 3: Inject fault midway
			return simulatedErr
		})

		if txErr == nil {
			t.Fatal("expected transaction to return error when fault injected, but got nil")
		}

		// Assert 100% Rollback: zero orphaned records in users or sessions
		_, err := store.Users().GetByID(ctx, userAID)
		if err == nil {
			t.Fatalf("atomicity violation: user %s was found after tx abort", userAID)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("expected ErrRecordNotFound for user %s, got: %v", userAID, err)
		}

		_, err = store.Sessions().GetByID(ctx, sessID)
		if err == nil {
			t.Fatalf("atomicity violation: session %s was found after tx abort", sessID)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("expected ErrRecordNotFound for session %s, got: %v", sessID, err)
		}

		// Scenario 2: User Deletion with Midway Abort Leaves Data 100% Intact
		userB := createTestUser(t, store, fmt.Sprintf("tx_preserve_%s@example.com", uuid.New().String()[:8]), "Secure#2026!", true)
		sessB, tok, err := adapter.App.Session.CreateSession(ctx, userB.ID, 0, db.SessionTypeBearer, "127.0.0.1", "AgentB")
		if err != nil {
			t.Fatalf("failed to create session for UserB: %v", err)
		}

		abortErr := fmt.Errorf("aborted deletion cascade")
		deleteTxErr := store.Transaction(ctx, func(txStore db.Store) error {
			// Delete user session inside transaction
			if err := txStore.Sessions().Delete(ctx, sessB.ID); err != nil {
				return err
			}
			// Abort before completing user deletion
			return abortErr
		})

		if deleteTxErr == nil {
			t.Fatal("expected delete transaction to fail")
		}

		// Assert all pre-existing records remain fully intact
		persistedUser, err := store.Users().GetByID(ctx, userB.ID)
		if err != nil || persistedUser == nil {
			t.Fatalf("user was prematurely deleted despite transaction rollback: %v", err)
		}

		validSess, err := adapter.App.Session.GetSession(ctx, tok)
		if err != nil || validSess == nil {
			t.Fatalf("session was prematurely deleted despite transaction rollback: %v", err)
		}
	})
}
