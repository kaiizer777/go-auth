//go:build integration

package integration

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/db"
)

func TestRegistration_PersistenceAndDefaults(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	// 1. Successful Signup
	user, rawToken, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "tester@example.com",
		Password: "SuperSecurePassword123!",
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected created user, got nil")
	}
	if user.ID == uuid.Nil {
		t.Fatal("expected non-nil UUID for user")
	}
	if user.Email != "tester@example.com" {
		t.Fatalf("expected email tester@example.com, got %s", user.Email)
	}
	if rawToken == "" {
		t.Fatal("expected non-empty verification rawToken")
	}

	// Verify persistence in PG
	var dbUser db.User
	if err := database.Where("id = ?", user.ID).First(&dbUser).Error; err != nil {
		t.Fatalf("failed to query created user in DB: %v", err)
	}
	if dbUser.EmailVerified {
		t.Fatal("expected email_verified to be false initially")
	}

	// Verify DB-level DEFAULT uuid_generate_v4() when inserting without Go UUID
	var rawIDStr string
	err = database.Raw(`
		INSERT INTO users (email, password_hash, email_verified) 
		VALUES ('dbdefault@example.com', 'dummyhash', false) 
		RETURNING id
	`).Scan(&rawIDStr).Error
	if err != nil {
		t.Fatalf("inserting user with default UUID failed: %v", err)
	}
	parsedUUID, err := uuid.Parse(rawIDStr)
	if err != nil || parsedUUID == uuid.Nil {
		t.Fatalf("expected database DEFAULT uuid_generate_v4() to produce valid UUID, got: %s", rawIDStr)
	}
}

func TestRegistration_CaseInsensitiveUniqueEmailAndAntiEnumeration(t *testing.T) {
	_, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	ctx := context.Background()

	// 1. Initial signup
	user1, tok1, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "Alice@Example.COM",
		Password: "Password12345!",
	})
	if err != nil {
		t.Fatalf("initial signup failed: %v", err)
	}
	if user1 == nil || tok1 == "" {
		t.Fatal("expected successful initial signup")
	}

	// 2. Duplicate signup with different casing -> triggers LOWER(email) unique index
	// Must return (nil, "", nil) anti-enumeration silent success
	user2, tok2, err := authInst.Auth.Signup(ctx, db.SignupRequest{
		Email:    "alice@example.com",
		Password: "Password12345!",
	})
	if err != nil {
		t.Fatalf("duplicate signup returned error: %v", err)
	}
	if user2 != nil {
		t.Fatalf("expected nil user for anti-enumeration silent success, got %+v", user2)
	}
	if tok2 != "" {
		t.Fatalf("expected empty token for duplicate signup, got %s", tok2)
	}
}

func TestRegistration_ConcurrentDuplicateRace(t *testing.T) {
	database, cfg := setupDB(t)

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}
	defer authInst.Close()

	const concurrency = 8
	var wg sync.WaitGroup
	var successCreatedCount atomic.Int32
	var silentSuccessCount atomic.Int32
	var errorCount atomic.Int32

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Vary casing across concurrent callers
			emailVariant := "raceUser@Example.com"
			if idx%2 == 1 {
				emailVariant = "RACEUSER@example.com"
			}

			user, tok, err := authInst.Auth.Signup(context.Background(), db.SignupRequest{
				Email:    emailVariant,
				Password: "RacePassword123!",
			})
			if err != nil {
				errorCount.Add(1)
				return
			}
			if user != nil && tok != "" {
				successCreatedCount.Add(1)
			} else if user == nil && tok == "" {
				silentSuccessCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	if errorCount.Load() > 0 {
		t.Fatalf("expected 0 errors under concurrent registration, got %d", errorCount.Load())
	}
	if successCreatedCount.Load() != 1 {
		t.Fatalf("expected exactly 1 user created under race, got %d", successCreatedCount.Load())
	}
	if silentSuccessCount.Load() != concurrency-1 {
		t.Fatalf("expected %d silent successes, got %d", concurrency-1, silentSuccessCount.Load())
	}

	// Verify only 1 row exists in DB
	var count int64
	if err := database.Model(&db.User{}).Where("LOWER(email) = LOWER(?)", "raceuser@example.com").Count(&count).Error; err != nil {
		t.Fatalf("counting users failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row in DB, found %d", count)
	}
}
