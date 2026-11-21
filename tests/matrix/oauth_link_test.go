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

func TestMatrix_OAuthLink(t *testing.T) {
	runMatrix(t, func(t *testing.T, adapter TestAdapter) {
		ctx := context.Background()
		store := adapter.Store

		user := createTestUser(t, store, fmt.Sprintf("matrix_oauth_%s@example.com", uuid.New().String()[:8]), "Password#2026!", true)

		providerID := "github"
		providerUserID := fmt.Sprintf("gh_%s", uuid.New().String()[:8])

		// 1. Social Identity Linking
		account := &db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         user.ID,
			ProviderID:     providerID,
			ProviderUserID: providerUserID,
			Email:          user.Email,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		err := store.OAuthAccounts().Create(ctx, account)
		if err != nil {
			t.Fatalf("OAuthAccounts().Create failed: %v", err)
		}

		// 2. Lookup by Provider
		fetched, err := store.OAuthAccounts().GetByProvider(ctx, providerID, providerUserID)
		if err != nil {
			t.Fatalf("GetByProvider failed: %v", err)
		}
		if fetched.UserID != user.ID {
			t.Fatalf("linked account user mismatch: got %v, want %v", fetched.UserID, user.ID)
		}
		if fetched.ProviderID != providerID || fetched.ProviderUserID != providerUserID {
			t.Fatalf("provider credentials mismatch: got (%s, %s)", fetched.ProviderID, fetched.ProviderUserID)
		}

		// 3. Duplicate Link Prevention
		duplicateAccount := &db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         user.ID,
			ProviderID:     providerID,
			ProviderUserID: providerUserID,
			Email:          fmt.Sprintf("other_%s@example.com", uuid.New().String()[:8]),
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		dupErr := store.OAuthAccounts().Create(ctx, duplicateAccount)
		if dupErr == nil {
			t.Fatal("expected error on duplicate OAuth link insertion, but succeeded")
		}

		// 4. Cascade on User Deletion
		err = store.Users().Delete(ctx, user.ID)
		if err != nil {
			t.Fatalf("Users().Delete failed: %v", err)
		}

		// Assert linked account cascaded away
		_, err = store.OAuthAccounts().GetByProvider(ctx, providerID, providerUserID)
		if err == nil {
			t.Fatal("expected linked OAuth account to be deleted by cascade, but found it")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) && !errors.Is(err, mongo.ErrNoDocuments) {
			t.Fatalf("expected ErrRecordNotFound for linked OAuth account, got: %v", err)
		}

		accounts, err := store.OAuthAccounts().GetByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetByUserID after user delete failed: %v", err)
		}
		if len(accounts) != 0 {
			t.Fatalf("expected 0 OAuth accounts for user after delete cascade, got %d", len(accounts))
		}
	})
}
