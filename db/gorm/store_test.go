package gormstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	gormdriver "gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

func setupTestDB(t *testing.T) (*gormdriver.DB, db.Store) {
	t.Helper()
	dbName := fmt.Sprintf("file:mem_%s?mode=memory&cache=shared", uuid.New().String())
	database, err := gormdriver.Open(sqlite.Open(dbName), &gormdriver.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	err = database.AutoMigrate(
		&db.User{},
		&db.Session{},
		&db.VerificationToken{},
		&db.PasswordResetToken{},
		&db.OAuthAccount{},
		&db.TotpSecret{},
		&db.TotpUsedCode{},
		&db.TwoFactorToken{},
	)
	if err != nil {
		t.Fatalf("failed to auto-migrate models: %v", err)
	}

	// secret_kid is deliberately not on db.TotpSecret, so AutoMigrate cannot
	// create it; add what migration 000013 adds.
	if err := database.Exec("ALTER TABLE totp_secrets ADD COLUMN secret_kid VARCHAR(32) NOT NULL DEFAULT ''").Error; err != nil {
		t.Fatalf("failed to add totp_secrets.secret_kid: %v", err)
	}

	store := New(database)
	if store == nil {
		t.Fatalf("New returned nil store")
	}

	return database, store
}

func TestStore_ConstructorsAndAccessors(t *testing.T) {
	if s := New(nil); s != nil {
		t.Fatalf("expected New(nil) to return nil, got %v", s)
	}

	database, store := setupTestDB(t)

	if store.Users() == nil {
		t.Fatal("Users() is nil")
	}
	if store.Sessions() == nil {
		t.Fatal("Sessions() is nil")
	}
	if store.VerificationTokens() == nil {
		t.Fatal("VerificationTokens() is nil")
	}
	if store.PasswordResetTokens() == nil {
		t.Fatal("PasswordResetTokens() is nil")
	}
	if store.OAuthAccounts() == nil {
		t.Fatal("OAuthAccounts() is nil")
	}
	if store.Totp() == nil {
		t.Fatal("Totp() is nil")
	}

	gs, ok := store.(*gormStore)
	if !ok || gs.DB() != database {
		t.Fatal("DB() did not return underlying database")
	}
}

func TestStore_PingAndClose(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()

	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestStore_Transaction(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()

	// Commit path
	uid := uuid.New()
	err := store.Transaction(ctx, func(txStore db.Store) error {
		return txStore.Users().Create(ctx, &db.User{
			ID:    uid,
			Email: "tx_commit@example.com",
		})
	})
	if err != nil {
		t.Fatalf("Transaction commit failed: %v", err)
	}

	u, err := store.Users().GetByID(ctx, uid)
	if err != nil || u == nil {
		t.Fatalf("user not found after tx commit: %v", err)
	}

	// Rollback path
	rollbackUID := uuid.New()
	testErr := errors.New("simulated error")
	err = store.Transaction(ctx, func(txStore db.Store) error {
		_ = txStore.Users().Create(ctx, &db.User{
			ID:    rollbackUID,
			Email: "tx_rollback@example.com",
		})
		return testErr
	})
	if !errors.Is(err, testErr) {
		t.Fatalf("expected testErr, got: %v", err)
	}

	_, err = store.Users().GetByID(ctx, rollbackUID)
	if !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound after rollback, got %v", err)
	}
}

func TestUserStore_AllMethods(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	users := store.Users()

	// 1. Create with empty ID (generates UUID via BeforeCreate)
	u1 := &db.User{
		Email:             "user1@example.com",
		PasswordHash:      "hash1",
		CredentialVersion: 1,
		EmailVerified:     false,
	}
	if err := users.Create(ctx, u1); err != nil {
		t.Fatalf("Create user1 failed: %v", err)
	}
	if u1.ID == uuid.Nil {
		t.Fatal("expected UUID to be generated")
	}

	// 2. GetByID
	got, err := users.GetByID(ctx, u1.ID)
	if err != nil || got.Email != u1.Email {
		t.Fatalf("GetByID mismatch: %v, %v", got, err)
	}

	// 3. GetByID non-existent
	if _, err := users.GetByID(ctx, uuid.New()); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for missing user, got %v", err)
	}

	// 4. GetByIDForUpdate
	gotUp, err := users.GetByIDForUpdate(ctx, u1.ID)
	if err != nil || gotUp.ID != u1.ID {
		t.Fatalf("GetByIDForUpdate failed: %v", err)
	}

	// 5. GetByEmail (case-insensitive)
	gotEmail, err := users.GetByEmail(ctx, "USER1@EXAMPLE.COM")
	if err != nil || gotEmail.ID != u1.ID {
		t.Fatalf("GetByEmail case-insensitive failed: %v", err)
	}
	if _, err := users.GetByEmail(ctx, "missing@example.com"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for missing email, got %v", err)
	}

	// 6. Update
	u1.Email = "user1_updated@example.com"
	if err := users.Update(ctx, u1); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	gotUpdated, err := users.GetByID(ctx, u1.ID)
	if err != nil || gotUpdated.Email != "user1_updated@example.com" {
		t.Fatalf("Update not reflected: %v", gotUpdated)
	}
	// Update non-existent user must return ErrUserNotFound
	missingUser := &db.User{ID: uuid.New(), Email: "nonexistent@example.com"}
	if err := users.Update(ctx, missingUser); !errors.Is(err, apperrors.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound updating non-existent user, got: %v", err)
	}
	// Verify no phantom row was created
	if _, err := users.GetByID(ctx, missingUser.ID); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected non-existent user to not exist after update, got: %v", err)
	}
	// Update duplicate email must return ErrEmailAlreadyExists
	uDuplicate := &db.User{Email: "user_dup@example.com"}
	if err := users.Create(ctx, uDuplicate); err != nil {
		t.Fatalf("failed to create duplicate test user: %v", err)
	}
	uDuplicate.Email = "user1_updated@example.com"
	if err := users.Update(ctx, uDuplicate); !errors.Is(err, apperrors.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists on email collision, got: %v", err)
	}

	// 7. UpdatePassword
	if err := users.UpdatePassword(ctx, u1.ID, "new_secret_hash"); err != nil {
		t.Fatalf("UpdatePassword failed: %v", err)
	}
	gotPass, err := users.GetByID(ctx, u1.ID)
	if err != nil || gotPass.PasswordHash != "new_secret_hash" {
		t.Fatalf("UpdatePassword not reflected: %v", gotPass)
	}

	// 8. IncrementCredentialVersion
	newVer, err := users.IncrementCredentialVersion(ctx, u1.ID)
	if err != nil || newVer != 2 {
		t.Fatalf("IncrementCredentialVersion: got ver=%d, err=%v, want ver=2", newVer, err)
	}
	// Non-existent user
	missingVer, err := users.IncrementCredentialVersion(ctx, uuid.New())
	if err != nil || missingVer != 0 {
		t.Fatalf("IncrementCredentialVersion missing user: got ver=%d, err=%v", missingVer, err)
	}

	// 9. SetEmailVerified
	if err := users.SetEmailVerified(ctx, u1.ID, true); err != nil {
		t.Fatalf("SetEmailVerified true failed: %v", err)
	}
	gotVerif, _ := users.GetByID(ctx, u1.ID)
	if !gotVerif.EmailVerified {
		t.Fatal("expected EmailVerified to be true")
	}

	if err := users.SetEmailVerified(ctx, u1.ID, false); err != nil {
		t.Fatalf("SetEmailVerified false failed: %v", err)
	}
	gotVerif2, _ := users.GetByID(ctx, u1.ID)
	if gotVerif2.EmailVerified {
		t.Fatal("expected EmailVerified to be false")
	}

	// 10. Delete
	if err := users.Delete(ctx, u1.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := users.GetByID(ctx, u1.ID); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected user to be deleted, got %v", err)
	}
}

func TestUserStore_Update_ZeroValuesAndErrors(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	users := store.Users()

	// 1. Create a user with EmailVerified true
	u := &db.User{
		Email:         "verified_user@example.com",
		PasswordHash:  "initial_hash",
		EmailVerified: true,
	}
	if err := users.Create(ctx, u); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// 2. Update EmailVerified to false (zero value)
	u.EmailVerified = false
	if err := users.Update(ctx, u); err != nil {
		t.Fatalf("Update with zero-value EmailVerified failed: %v", err)
	}
	fetched, err := users.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if fetched.EmailVerified != false {
		t.Fatal("expected EmailVerified false to persist across Update")
	}

	// 3. Update non-existent user returns ErrUserNotFound and ErrRecordNotFound
	missing := &db.User{ID: uuid.New(), Email: "ghost@example.com"}
	err = users.Update(ctx, missing)
	if !errors.Is(err, apperrors.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound for missing user update, got: %v", err)
	}
	if !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for missing user update, got: %v", err)
	}

	// 4. Duplicate email returns ErrEmailAlreadyExists
	other := &db.User{Email: "other@example.com"}
	if err := users.Create(ctx, other); err != nil {
		t.Fatalf("Create other user failed: %v", err)
	}
	other.Email = "verified_user@example.com"
	if err := users.Update(ctx, other); !errors.Is(err, apperrors.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists on duplicate email, got: %v", err)
	}
}

func TestUserStore_IncrementCredentialVersion_Concurrent(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	users := store.Users()

	u := &db.User{Email: "concurrent_cred@example.com", CredentialVersion: 1}
	if err := users.Create(ctx, u); err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	versions := make(chan uint32, goroutines)
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ver, err := users.IncrementCredentialVersion(ctx, u.ID)
			if err != nil {
				errCh <- err
				return
			}
			versions <- ver
		}()
	}

	wg.Wait()
	close(versions)
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent IncrementCredentialVersion failed: %v", err)
	}

	seen := make(map[uint32]bool)
	for ver := range versions {
		if seen[ver] {
			t.Fatalf("duplicate credential version observed: %d", ver)
		}
		seen[ver] = true
	}

	if len(seen) != goroutines {
		t.Fatalf("expected %d distinct versions, got %d", goroutines, len(seen))
	}

	for v := uint32(2); v <= uint32(1+goroutines); v++ {
		if !seen[v] {
			t.Errorf("missing expected version %d in sequential progression", v)
		}
	}

	finalUser, err := users.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if uint32(finalUser.CredentialVersion) != uint32(1+goroutines) {
		t.Fatalf("final CredentialVersion = %d, want %d", finalUser.CredentialVersion, 1+goroutines)
	}
}

func TestSessionStore_AllMethods(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	sessions := store.Sessions()

	userID := uuid.New()
	now := time.Now().UTC().Truncate(time.Millisecond)

	s1 := &db.Session{
		UserID:            userID,
		IDHash:            "id_hash_1",
		SessionType:       db.SessionTypeBearer,
		IPAddress:         "127.0.0.1",
		UserAgent:         "test-agent",
		CredentialVersion: 1,
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
		CreatedAt:         now,
	}

	// 1. Create
	if err := sessions.Create(ctx, s1); err != nil {
		t.Fatalf("Create session failed: %v", err)
	}
	if s1.ID == uuid.Nil {
		t.Fatal("expected session ID to be set")
	}

	// 2. GetByID
	got, err := sessions.GetByID(ctx, s1.ID)
	if err != nil || got.IDHash != s1.IDHash {
		t.Fatalf("GetByID mismatch: %v, %v", got, err)
	}
	if _, err := sessions.GetByID(ctx, uuid.New()); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for missing session ID, got %v", err)
	}

	// 3. GetByIDHash
	gotHash, err := sessions.GetByIDHash(ctx, "id_hash_1")
	if err != nil || gotHash.ID != s1.ID {
		t.Fatalf("GetByIDHash mismatch: %v, %v", gotHash, err)
	}
	if _, err := sessions.GetByIDHash(ctx, "missing_hash"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for missing session id_hash, got %v", err)
	}

	// 4. ListByUserID
	s2 := &db.Session{
		UserID:            userID,
		IDHash:            "id_hash_2",
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      now.Add(1 * time.Hour),
		AbsoluteExpiresAt: now.Add(48 * time.Hour),
		CreatedAt:         now,
	}
	if err := sessions.Create(ctx, s2); err != nil {
		t.Fatalf("Create s2 failed: %v", err)
	}

	list, err := sessions.ListByUserID(ctx, userID)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListByUserID got %d items, err=%v", len(list), err)
	}
	if list[0].ID != s2.ID {
		t.Fatalf("expected s2 first due to order by last_active_at DESC, got %v", list[0].ID)
	}

	// 5. UpdateLastActive
	newActive := now.Add(2 * time.Hour)
	if err := sessions.UpdateLastActive(ctx, s1.ID, newActive); err != nil {
		t.Fatalf("UpdateLastActive failed: %v", err)
	}
	gotActive, _ := sessions.GetByID(ctx, s1.ID)
	if !gotActive.LastActiveAt.Equal(newActive) {
		t.Fatalf("UpdateLastActive not reflected: got %v, want %v", gotActive.LastActiveAt, newActive)
	}

	// 6. DeleteByIDHash
	affected, err := sessions.DeleteByIDHash(ctx, "id_hash_2")
	if err != nil || affected != 1 {
		t.Fatalf("DeleteByIDHash: affected=%d, err=%v", affected, err)
	}

	// 7. DeleteIfStale
	s3 := &db.Session{
		UserID:            userID,
		IDHash:            "id_hash_3",
		LastActiveAt:      now.Add(-10 * time.Hour),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
	}
	_ = sessions.Create(ctx, s3)
	delStale, err := sessions.DeleteIfStale(ctx, s3.ID, now)
	if err != nil || delStale != 1 {
		t.Fatalf("DeleteIfStale: got %d, err=%v", delStale, err)
	}

	// 8. DeleteIfStaleByIDHash
	s4 := &db.Session{
		UserID:            userID,
		IDHash:            "id_hash_4",
		LastActiveAt:      now.Add(-10 * time.Hour),
		AbsoluteExpiresAt: now.Add(24 * time.Hour),
	}
	_ = sessions.Create(ctx, s4)
	delStaleHash, err := sessions.DeleteIfStaleByIDHash(ctx, "id_hash_4", now)
	if err != nil || delStaleHash != 1 {
		t.Fatalf("DeleteIfStaleByIDHash: got %d, err=%v", delStaleHash, err)
	}

	// 9. DeleteExpired
	sExpired := &db.Session{
		UserID:            userID,
		IDHash:            "id_hash_expired",
		LastActiveAt:      now.Add(-2 * time.Hour),
		AbsoluteExpiresAt: now.Add(-1 * time.Hour),
	}
	_ = sessions.Create(ctx, sExpired)
	delExp, err := sessions.DeleteExpired(ctx, now, now.Add(-3*time.Hour))
	if err != nil || delExp < 1 {
		t.Fatalf("DeleteExpired: got %d, err=%v", delExp, err)
	}

	// 10. DeleteExpiredByUserID
	sExpiredUser := &db.Session{
		UserID:            userID,
		IDHash:            "id_hash_exp_user",
		LastActiveAt:      now.Add(-2 * time.Hour),
		AbsoluteExpiresAt: now.Add(-1 * time.Hour),
	}
	_ = sessions.Create(ctx, sExpiredUser)
	if err := sessions.DeleteExpiredByUserID(ctx, userID, now, now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("DeleteExpiredByUserID failed: %v", err)
	}

	// 11. Delete
	if err := sessions.Delete(ctx, s1.ID); err != nil {
		t.Fatalf("Delete session failed: %v", err)
	}

	// 12. DeleteByUserID
	s5 := &db.Session{UserID: userID, IDHash: "id_hash_5"}
	_ = sessions.Create(ctx, s5)
	if err := sessions.DeleteByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}
	rem, _ := sessions.ListByUserID(ctx, userID)
	if len(rem) != 0 {
		t.Fatalf("expected 0 sessions after DeleteByUserID, got %d", len(rem))
	}
}

func TestVerificationTokenStore_AllMethods(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	tokens := store.VerificationTokens()

	userID := uuid.New()
	tokenHash := []byte("vtok_secret_hash_12345")
	expiresAt := time.Now().UTC().Add(time.Hour)

	tok := &db.VerificationToken{
		TokenHash: tokenHash,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
	}

	// 1. Create
	if err := tokens.Create(ctx, tok); err != nil {
		t.Fatalf("Create token failed: %v", err)
	}

	// 2. GetByTokenHash
	got, err := tokens.GetByTokenHash(ctx, tokenHash)
	if err != nil || got.UserID != userID {
		t.Fatalf("GetByTokenHash mismatch: %v, %v", got, err)
	}
	if _, err := tokens.GetByTokenHash(ctx, []byte("missing")); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// 3. Delete
	count, err := tokens.Delete(ctx, tokenHash)
	if err != nil || count != 1 {
		t.Fatalf("Delete token failed: count=%d, err=%v", count, err)
	}
	count2, err := tokens.Delete(ctx, tokenHash)
	if err != nil || count2 != 0 {
		t.Fatalf("Delete token second time failed: count=%d, err=%v", count2, err)
	}
	if _, err := tokens.GetByTokenHash(ctx, tokenHash); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected deleted token, got %v", err)
	}

	// 4. DeleteByUserID
	tok2 := &db.VerificationToken{
		TokenHash: []byte("vtok_2"),
		UserID:    userID,
		ExpiresAt: expiresAt,
	}
	_ = tokens.Create(ctx, tok2)
	if err := tokens.DeleteByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}
	if _, err := tokens.GetByTokenHash(ctx, []byte("vtok_2")); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected token to be deleted by user ID, got %v", err)
	}
}

func TestPasswordResetTokenStore_AllMethods(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	resets := store.PasswordResetTokens()

	userID := uuid.New()
	tokenHash := []byte("reset_token_hash_98765")
	now := time.Now().UTC()

	tok := &db.PasswordResetToken{
		TokenHash: tokenHash,
		UserID:    userID,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}

	// 1. Create
	if err := resets.Create(ctx, tok); err != nil {
		t.Fatalf("Create reset token failed: %v", err)
	}

	// 2. GetByTokenHash
	got, err := resets.GetByTokenHash(ctx, tokenHash)
	if err != nil || got.UserID != userID {
		t.Fatalf("GetByTokenHash mismatch: %v, %v", got, err)
	}
	if _, err := resets.GetByTokenHash(ctx, []byte("missing")); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// 3. ConsumeToken - valid
	consumed, err := resets.ConsumeToken(ctx, tokenHash, now)
	if err != nil || !consumed {
		t.Fatalf("ConsumeToken valid: got %v, err=%v", consumed, err)
	}

	// Second consume should return false (already deleted)
	consumedAgain, err := resets.ConsumeToken(ctx, tokenHash, now)
	if err != nil || consumedAgain {
		t.Fatalf("ConsumeToken replay: got %v, err=%v", consumedAgain, err)
	}

	// Consume expired token returns false
	expiredHash := []byte("expired_token_hash")
	_ = resets.Create(ctx, &db.PasswordResetToken{
		TokenHash: expiredHash,
		UserID:    userID,
		ExpiresAt: now.Add(-10 * time.Minute),
	})
	consumedExpired, err := resets.ConsumeToken(ctx, expiredHash, now)
	if err != nil || consumedExpired {
		t.Fatalf("ConsumeToken expired: got %v, err=%v", consumedExpired, err)
	}

	// 4. Delete
	tokDelete := &db.PasswordResetToken{
		TokenHash: []byte("tok_to_delete"),
		UserID:    userID,
		ExpiresAt: now.Add(time.Hour),
	}
	_ = resets.Create(ctx, tokDelete)
	delCount, err := resets.Delete(ctx, []byte("tok_to_delete"))
	if err != nil || delCount != 1 {
		t.Fatalf("Delete failed: count=%d, err=%v", delCount, err)
	}

	// 5. DeleteByUserID
	tokUser := &db.PasswordResetToken{
		TokenHash: []byte("tok_by_user"),
		UserID:    userID,
		ExpiresAt: now.Add(time.Hour),
	}
	_ = resets.Create(ctx, tokUser)
	if err := resets.DeleteByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}
}

func TestOAuthAccountStore_AllMethods(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	oauth := store.OAuthAccounts()

	userID := uuid.New()
	acc := &db.OAuthAccount{
		UserID:         userID,
		ProviderID:     "github",
		ProviderUserID: "gh_user_42",
		Email:          "oauth@example.com",
	}

	// 1. Create
	if err := oauth.Create(ctx, acc); err != nil {
		t.Fatalf("Create oauth account failed: %v", err)
	}
	if acc.ID == uuid.Nil {
		t.Fatal("expected UUID to be assigned")
	}

	// 2. GetByProvider
	got, err := oauth.GetByProvider(ctx, "github", "", "gh_user_42")
	if err != nil || got.ID != acc.ID {
		t.Fatalf("GetByProvider mismatch: %v, %v", got, err)
	}
	if _, err := oauth.GetByProvider(ctx, "github", "", "missing"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
	// A tenant-qualified probe must not resolve a link stored without a tenant.
	if _, err := oauth.GetByProvider(ctx, "github", "tenant-a", "gh_user_42"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for a tenant-qualified probe, got %v", err)
	}

	// 3. GetByUserID
	list, err := oauth.GetByUserID(ctx, userID)
	if err != nil || len(list) != 1 {
		t.Fatalf("GetByUserID got %d items, err=%v", len(list), err)
	}

	// 4. UpdateProviderUserID
	if err := oauth.UpdateProviderUserID(ctx, acc.ID, "gh_456_updated"); err != nil {
		t.Fatalf("UpdateProviderUserID failed: %v", err)
	}
	gotUpdated, err := oauth.GetByProvider(ctx, "github", "", "gh_456_updated")
	if err != nil || gotUpdated == nil || gotUpdated.ProviderUserID != "gh_456_updated" || gotUpdated.ID != acc.ID {
		t.Fatalf("expected updated provider_user_id, got %v, err=%v", gotUpdated, err)
	}
	if _, err := oauth.GetByProvider(ctx, "github", "", "gh_user_42"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected old provider_user_id to not exist, got err=%v", err)
	}
	if err := oauth.UpdateProviderUserID(ctx, uuid.New(), "non_existent"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected gormdriver.ErrRecordNotFound for non-existent link, got %v", err)
	}

	// 5. Delete
	if err := oauth.Delete(ctx, acc.ID); err != nil {
		t.Fatalf("Delete oauth account failed: %v", err)
	}

	// 6. DeleteByUserID
	acc2 := &db.OAuthAccount{
		UserID:         userID,
		ProviderID:     "google",
		ProviderUserID: "goog_99",
		Email:          "goog@example.com",
	}
	_ = oauth.Create(ctx, acc2)
	if err := oauth.DeleteByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}
	listAfter, _ := oauth.GetByUserID(ctx, userID)
	if len(listAfter) != 0 {
		t.Fatalf("expected 0 accounts after DeleteByUserID, got %d", len(listAfter))
	}

	// 7. SaveOAuthTokens / SaveOAuthTokensCAS
	acc3 := &db.OAuthAccount{
		UserID:         userID,
		ProviderID:     "gitlab",
		ProviderUserID: "gl_7",
		Email:          "gl@example.com",
	}
	if err := oauth.Create(ctx, acc3); err != nil {
		t.Fatalf("Create oauth account for token writes failed: %v", err)
	}
	reload := func() *db.OAuthAccount {
		t.Helper()
		got, err := oauth.GetByProvider(ctx, "gitlab", "", "gl_7")
		if err != nil {
			t.Fatalf("reload oauth account failed: %v", err)
		}
		return got
	}
	assertTokens := func(acc *db.OAuthAccount, access, refresh, fingerprint, scope string) {
		t.Helper()
		if acc.AccessTokenCiphertext != access ||
			acc.RefreshTokenCiphertext != refresh ||
			acc.RefreshTokenFingerprint != fingerprint ||
			acc.TokenScope != scope {
			t.Fatalf("token fields = %+v; want access %q refresh %q fingerprint %q scope %q",
				acc, access, refresh, fingerprint, scope)
		}
	}

	// A nil expiry must stay nil, both after a write and after clearing.
	if err := oauth.SaveOAuthTokens(ctx, acc3.ID, db.OAuthTokenRecord{
		AccessTokenCiphertext:   "sealed-access",
		RefreshTokenCiphertext:  "sealed-refresh",
		RefreshTokenFingerprint: strings.Repeat("a", 64),
		TokenScope:              "read:user offline_access",
	}); err != nil {
		t.Fatalf("SaveOAuthTokens without expiry failed: %v", err)
	}
	stored := reload()
	assertTokens(stored, "sealed-access", "sealed-refresh", strings.Repeat("a", 64), "read:user offline_access")
	if stored.TokenExpiresAt != nil {
		t.Fatalf("nil expiry stored as %v; want nil", stored.TokenExpiresAt)
	}

	// An all-empty record clears every token column.
	if err := oauth.SaveOAuthTokens(ctx, acc3.ID, db.OAuthTokenRecord{}); err != nil {
		t.Fatalf("SaveOAuthTokens clear failed: %v", err)
	}
	cleared := reload()
	assertTokens(cleared, "", "", "", "")
	if cleared.TokenExpiresAt != nil {
		t.Fatalf("cleared expiry = %v; want nil", cleared.TokenExpiresAt)
	}

	// An expiry round-trips, and an identical re-save stays a success.
	expiresAt := time.Now().UTC().Truncate(time.Millisecond)
	if err := oauth.SaveOAuthTokens(ctx, acc3.ID, db.OAuthTokenRecord{
		AccessTokenCiphertext:   "sealed-access",
		RefreshTokenCiphertext:  "sealed-refresh",
		RefreshTokenFingerprint: strings.Repeat("b", 64),
		TokenScope:              "offline_access",
		TokenExpiresAt:          &expiresAt,
	}); err != nil {
		t.Fatalf("SaveOAuthTokens with expiry failed: %v", err)
	}
	stored = reload()
	assertTokens(stored, "sealed-access", "sealed-refresh", strings.Repeat("b", 64), "offline_access")
	if stored.TokenExpiresAt == nil || !stored.TokenExpiresAt.Equal(expiresAt) {
		t.Fatalf("expiry roundtrip = %v; want %v", stored.TokenExpiresAt, expiresAt)
	}
	if err := oauth.SaveOAuthTokens(ctx, acc3.ID, db.OAuthTokenRecord{
		AccessTokenCiphertext:   "sealed-access",
		RefreshTokenCiphertext:  "sealed-refresh",
		RefreshTokenFingerprint: strings.Repeat("b", 64),
		TokenScope:              "offline_access",
		TokenExpiresAt:          &expiresAt,
	}); err != nil {
		t.Fatalf("identical re-save failed: %v", err)
	}

	// Re-seed a fingerprint so the CAS cases have a current value to compare.
	winner := strings.Repeat("c", 64)
	if err := oauth.SaveOAuthTokens(ctx, acc3.ID, db.OAuthTokenRecord{
		AccessTokenCiphertext:   "sealed-access",
		RefreshTokenCiphertext:  "sealed-refresh",
		RefreshTokenFingerprint: strings.Repeat("b", 64),
		TokenScope:              "offline_access",
		TokenExpiresAt:          &expiresAt,
	}); err != nil {
		t.Fatalf("re-seed tokens failed: %v", err)
	}

	// An empty expectation never matches, even though the column is non-empty.
	if won, err := oauth.SaveOAuthTokensCAS(ctx, acc3.ID, "", db.OAuthTokenRecord{
		RefreshTokenCiphertext:  "attacker-refresh",
		RefreshTokenFingerprint: winner,
	}); err != nil || won {
		t.Fatalf("empty expectation CAS = (%v, %v); want (false, nil)", won, err)
	}
	assertTokens(reload(), "sealed-access", "sealed-refresh", strings.Repeat("b", 64), "offline_access")

	// A stale expectation is a miss, not an error, and must not mutate the row.
	if won, err := oauth.SaveOAuthTokensCAS(ctx, acc3.ID, strings.Repeat("a", 64), db.OAuthTokenRecord{
		RefreshTokenCiphertext:  "stale-refresh",
		RefreshTokenFingerprint: winner,
	}); err != nil || won {
		t.Fatalf("stale expectation CAS = (%v, %v); want (false, nil)", won, err)
	}
	assertTokens(reload(), "sealed-access", "sealed-refresh", strings.Repeat("b", 64), "offline_access")

	// A matching expectation wins and overwrites all five fields.
	newExpiry := expiresAt.Add(time.Hour)
	if won, err := oauth.SaveOAuthTokensCAS(ctx, acc3.ID, strings.Repeat("b", 64), db.OAuthTokenRecord{
		AccessTokenCiphertext:   "rotated-access",
		RefreshTokenCiphertext:  "rotated-refresh",
		RefreshTokenFingerprint: winner,
		TokenScope:              "offline_access",
		TokenExpiresAt:          &newExpiry,
	}); err != nil || !won {
		t.Fatalf("matching expectation CAS = (%v, %v); want (true, nil)", won, err)
	}
	rotated := reload()
	assertTokens(rotated, "rotated-access", "rotated-refresh", winner, "offline_access")
	if rotated.TokenExpiresAt == nil || !rotated.TokenExpiresAt.Equal(newExpiry) {
		t.Fatalf("rotated expiry = %v; want %v", rotated.TokenExpiresAt, newExpiry)
	}

	// The losing fingerprint is now stale: replaying it must miss.
	if won, err := oauth.SaveOAuthTokensCAS(ctx, acc3.ID, strings.Repeat("b", 64), db.OAuthTokenRecord{
		RefreshTokenFingerprint: "loser",
	}); err != nil || won {
		t.Fatalf("replayed expectation CAS = (%v, %v); want (false, nil)", won, err)
	}
	assertTokens(reload(), "rotated-access", "rotated-refresh", winner, "offline_access")

	// After a clear, an empty expectation still cannot match the empty column.
	if err := oauth.SaveOAuthTokens(ctx, acc3.ID, db.OAuthTokenRecord{}); err != nil {
		t.Fatalf("clear before empty-expectation CAS failed: %v", err)
	}
	if won, err := oauth.SaveOAuthTokensCAS(ctx, acc3.ID, "", db.OAuthTokenRecord{
		AccessTokenCiphertext: "unproven",
	}); err != nil || won {
		t.Fatalf("empty expectation against empty column CAS = (%v, %v); want (false, nil)", won, err)
	}
	assertTokens(reload(), "", "", "", "")

	// CAS against a missing account is a miss, not an error.
	if won, err := oauth.SaveOAuthTokensCAS(ctx, uuid.New(), winner, db.OAuthTokenRecord{
		AccessTokenCiphertext: "ghost",
	}); err != nil || won {
		t.Fatalf("missing-account CAS = (%v, %v); want (false, nil)", won, err)
	}

	// The first-grant write wins only while no refresh token is stored.
	if err := oauth.SaveOAuthTokens(ctx, acc3.ID, db.OAuthTokenRecord{}); err != nil {
		t.Fatalf("clear before IfUnset failed: %v", err)
	}
	if won, err := oauth.SaveOAuthTokensIfUnset(ctx, acc3.ID, db.OAuthTokenRecord{
		AccessTokenCiphertext:   "first-access",
		RefreshTokenCiphertext:  "first-refresh",
		RefreshTokenFingerprint: strings.Repeat("d", 64),
		TokenScope:              "offline_access",
		TokenExpiresAt:          &newExpiry,
	}); err != nil || !won {
		t.Fatalf("IfUnset on a tokenless row = (%v, %v); want (true, nil)", won, err)
	}
	assertTokens(reload(), "first-access", "first-refresh", strings.Repeat("d", 64), "offline_access")

	// A stored grant keeps its place: the guarded write loses and mutates nothing.
	if won, err := oauth.SaveOAuthTokensIfUnset(ctx, acc3.ID, db.OAuthTokenRecord{
		AccessTokenCiphertext:   "late-access",
		RefreshTokenCiphertext:  "late-refresh",
		RefreshTokenFingerprint: strings.Repeat("e", 64),
	}); err != nil || won {
		t.Fatalf("IfUnset over a stored grant = (%v, %v); want (false, nil)", won, err)
	}
	assertTokens(reload(), "first-access", "first-refresh", strings.Repeat("d", 64), "offline_access")

	// IfUnset against a missing account is a miss, not an error.
	if won, err := oauth.SaveOAuthTokensIfUnset(ctx, uuid.New(), db.OAuthTokenRecord{
		AccessTokenCiphertext: "ghost",
	}); err != nil || won {
		t.Fatalf("missing-account IfUnset = (%v, %v); want (false, nil)", won, err)
	}

	// The access-only write leaves the refresh columns exactly as stored.
	accessExpiry := newExpiry.Add(time.Hour)
	if err := oauth.SaveOAuthAccess(ctx, acc3.ID, db.OAuthTokenRecord{
		AccessTokenCiphertext: "access-only",
		TokenScope:            "read:user",
		TokenExpiresAt:        &accessExpiry,
	}); err != nil {
		t.Fatalf("SaveOAuthAccess failed: %v", err)
	}
	accessOnly := reload()
	assertTokens(accessOnly, "access-only", "first-refresh", strings.Repeat("d", 64), "read:user")
	if accessOnly.TokenExpiresAt == nil || !accessOnly.TokenExpiresAt.Equal(accessExpiry) {
		t.Fatalf("access-only expiry = %v; want %v", accessOnly.TokenExpiresAt, accessExpiry)
	}
	// A nil expiry on the access-only path clears the expiry, not the refresh.
	if err := oauth.SaveOAuthAccess(ctx, acc3.ID, db.OAuthTokenRecord{AccessTokenCiphertext: "access-only"}); err != nil {
		t.Fatalf("SaveOAuthAccess without expiry failed: %v", err)
	}
	accessOnly = reload()
	assertTokens(accessOnly, "access-only", "first-refresh", strings.Repeat("d", 64), "")
	if accessOnly.TokenExpiresAt != nil {
		t.Fatalf("access-only nil expiry stored as %v; want nil", accessOnly.TokenExpiresAt)
	}
	// The access-only path reports the backend not-found error.
	if err := oauth.SaveOAuthAccess(ctx, uuid.New(), db.OAuthTokenRecord{AccessTokenCiphertext: "ghost"}); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("missing-account SaveOAuthAccess = %v; want ErrRecordNotFound", err)
	}

	// The unconditional path reports the backend not-found error.
	if err := oauth.SaveOAuthTokens(ctx, uuid.New(), db.OAuthTokenRecord{AccessTokenCiphertext: "ghost"}); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("missing-account SaveOAuthTokens = %v; want ErrRecordNotFound", err)
	}
}

// TestOAuthAccountStore_TenantScopedKey pins #72 at the storage boundary: one
// pairwise subject in two tenants is two identities, and a lookup only resolves
// the tenant it names.
// TestOAuthTokenUpdates_NilExpiryVsZero pins the write payload: a nil expiry is
// written as SQL NULL, while a supplied zero time must not be coerced to NULL.
func TestOAuthTokenUpdates_NilExpiryVsZero(t *testing.T) {
	updates := oauthTokenUpdates(db.OAuthTokenRecord{})
	if got, ok := updates["token_expires_at"]; !ok || got != (*time.Time)(nil) {
		t.Fatalf("nil expiry payload = %v (present=%v); want a nil *time.Time", got, ok)
	}
	if _, ok := updates["updated_at"].(time.Time); !ok {
		t.Fatalf("updated_at payload = %T; want time.Time", updates["updated_at"])
	}

	zero := time.Time{}
	got, ok := oauthTokenUpdates(db.OAuthTokenRecord{TokenExpiresAt: &zero})["token_expires_at"].(*time.Time)
	if !ok || got == nil || !got.IsZero() {
		t.Fatalf("zero expiry payload = %v; want a non-nil zero *time.Time", got)
	}
}

// TestOAuthAccountStore_PartialColumnWrites pins the guarded writes that own a
// single column group: each guard compares the field it writes, and the columns
// another writer owns are never touched on a win or a miss.
func TestOAuthAccountStore_PartialColumnWrites(t *testing.T) {
	ctx := context.Background()
	_, store := setupTestDB(t)
	oauth := store.OAuthAccounts()
	userID := uuid.New()
	expiresAt := time.Now().UTC().Truncate(time.Millisecond)

	accessOnly := db.OAuthTokenRecord{
		AccessTokenCiphertext: "winner-access",
		TokenScope:            "read:user",
		TokenExpiresAt:        &expiresAt,
	}
	full := db.OAuthTokenRecord{
		AccessTokenCiphertext:   "stored-access",
		RefreshTokenCiphertext:  "stored-refresh",
		RefreshTokenFingerprint: strings.Repeat("a", 64),
		TokenScope:              "offline_access",
		TokenExpiresAt:          &expiresAt,
	}

	// newLink seeds one account and returns it with the row reloaded.
	reload := func(t *testing.T, sub string) *db.OAuthAccount {
		t.Helper()
		got, err := oauth.GetByProvider(ctx, "github", "", sub)
		if err != nil {
			t.Fatalf("reload link %s: %v", sub, err)
		}
		return got
	}
	newLink := func(t *testing.T, sub string, rec db.OAuthTokenRecord) *db.OAuthAccount {
		t.Helper()
		acc := &db.OAuthAccount{
			UserID:         userID,
			ProviderID:     "github",
			ProviderUserID: sub,
			Email:          sub + "@example.com",
		}
		if err := oauth.Create(ctx, acc); err != nil {
			t.Fatalf("create link %s: %v", sub, err)
		}
		if rec != (db.OAuthTokenRecord{}) {
			if err := oauth.SaveOAuthTokens(ctx, acc.ID, rec); err != nil {
				t.Fatalf("seed tokens for %s: %v", sub, err)
			}
		}
		return reload(t, sub)
	}

	t.Run("refresh clear is guarded on the fingerprint", func(t *testing.T) {
		acc := newLink(t, "clear", full)

		if won, err := oauth.ClearOAuthRefresh(ctx, acc.ID, ""); err != nil || won {
			t.Fatalf("empty expectation clear = (%v, %v); want (false, nil)", won, err)
		}
		if won, err := oauth.ClearOAuthRefresh(ctx, acc.ID, strings.Repeat("b", 64)); err != nil || won {
			t.Fatalf("stale expectation clear = (%v, %v); want (false, nil)", won, err)
		}
		unchanged := reload(t, "clear")
		if unchanged.AccessTokenCiphertext != "stored-access" || unchanged.RefreshTokenCiphertext != "stored-refresh" {
			t.Fatalf("a missed clear mutated the row: %+v", unchanged)
		}

		if won, err := oauth.ClearOAuthRefresh(ctx, acc.ID, strings.Repeat("a", 64)); err != nil || !won {
			t.Fatalf("matching clear = (%v, %v); want (true, nil)", won, err)
		}
		cleared := reload(t, "clear")
		if cleared.RefreshTokenCiphertext != "" || cleared.RefreshTokenFingerprint != "" {
			t.Fatalf("refresh columns = (%q, %q); want cleared", cleared.RefreshTokenCiphertext, cleared.RefreshTokenFingerprint)
		}
		if cleared.AccessTokenCiphertext != "stored-access" || cleared.TokenScope != "offline_access" ||
			cleared.TokenExpiresAt == nil || !cleared.TokenExpiresAt.Equal(expiresAt) {
			t.Fatalf("access columns = %+v; want them untouched", cleared)
		}

		if won, err := oauth.ClearOAuthRefresh(ctx, uuid.New(), strings.Repeat("a", 64)); err != nil || won {
			t.Fatalf("missing-account clear = (%v, %v); want (false, nil)", won, err)
		}
	})

	t.Run("refresh-if-unset keeps a concurrent access-only winner", func(t *testing.T) {
		acc := newLink(t, "recover-access-only", accessOnly)
		rotated := db.OAuthTokenRecord{
			AccessTokenCiphertext:   "rotated-access",
			RefreshTokenCiphertext:  "rotated-refresh",
			RefreshTokenFingerprint: strings.Repeat("c", 64),
			TokenScope:              "offline_access",
			TokenExpiresAt:          &expiresAt,
		}

		if won, err := oauth.SaveOAuthRefreshIfUnset(ctx, acc.ID, rotated); err != nil || !won {
			t.Fatalf("refresh-if-unset over an access-only row = (%v, %v); want (true, nil)", won, err)
		}
		stored := reload(t, "recover-access-only")
		if stored.RefreshTokenCiphertext != "rotated-refresh" || stored.RefreshTokenFingerprint != strings.Repeat("c", 64) {
			t.Fatalf("refresh columns = (%q, %q); want the rotated pair",
				stored.RefreshTokenCiphertext, stored.RefreshTokenFingerprint)
		}
		if stored.AccessTokenCiphertext != "winner-access" || stored.TokenScope != "read:user" {
			t.Fatalf("access columns = (%+v); want the winner's untouched", stored)
		}
	})

	t.Run("refresh-if-unset fills a tokenless row", func(t *testing.T) {
		acc := newLink(t, "recover-empty", db.OAuthTokenRecord{})
		rotated := db.OAuthTokenRecord{
			AccessTokenCiphertext:   "rotated-access",
			RefreshTokenCiphertext:  "rotated-refresh",
			RefreshTokenFingerprint: strings.Repeat("d", 64),
			TokenScope:              "offline_access",
			TokenExpiresAt:          &expiresAt,
		}

		if won, err := oauth.SaveOAuthRefreshIfUnset(ctx, acc.ID, rotated); err != nil || !won {
			t.Fatalf("refresh-if-unset over a tokenless row = (%v, %v); want (true, nil)", won, err)
		}
		stored := reload(t, "recover-empty")
		if stored.AccessTokenCiphertext != "rotated-access" || stored.RefreshTokenCiphertext != "rotated-refresh" ||
			stored.RefreshTokenFingerprint != strings.Repeat("d", 64) {
			t.Fatalf("token columns = %+v; want the whole rotated pair", stored)
		}
		if stored.TokenScope != "offline_access" || stored.TokenExpiresAt == nil || !stored.TokenExpiresAt.Equal(expiresAt) {
			t.Fatalf("access metadata = %+v; want the record's", stored)
		}
	})

	t.Run("refresh-if-unset loses to a stored refresh grant", func(t *testing.T) {
		acc := newLink(t, "recover-late", full)

		if won, err := oauth.SaveOAuthRefreshIfUnset(ctx, acc.ID, db.OAuthTokenRecord{
			RefreshTokenCiphertext:  "late-refresh",
			RefreshTokenFingerprint: strings.Repeat("e", 64),
			AccessTokenCiphertext:   "late-access",
		}); err != nil || won {
			t.Fatalf("refresh-if-unset over a stored grant = (%v, %v); want (false, nil)", won, err)
		}
		stored := reload(t, "recover-late")
		if stored.AccessTokenCiphertext != "stored-access" || stored.RefreshTokenCiphertext != "stored-refresh" ||
			stored.RefreshTokenFingerprint != strings.Repeat("a", 64) {
			t.Fatalf("token columns = %+v; want the stored grant untouched", stored)
		}
		// A record without a fingerprint cannot prove anything and is refused.
		if won, err := oauth.SaveOAuthRefreshIfUnset(ctx, uuid.New(), db.OAuthTokenRecord{
			RefreshTokenCiphertext: "anonymous",
		}); err != nil || won {
			t.Fatalf("fingerprint-less record = (%v, %v); want (false, nil)", won, err)
		}
	})

	t.Run("access CAS is guarded on the stored envelope", func(t *testing.T) {
		acc := newLink(t, "access-cas", full)

		if won, err := oauth.SaveOAuthAccessCAS(ctx, acc.ID, "stale-access", accessOnly); err != nil || won {
			t.Fatalf("stale expectation = (%v, %v); want (false, nil)", won, err)
		}
		if won, err := oauth.SaveOAuthAccessCAS(ctx, acc.ID, "", accessOnly); err != nil || won {
			t.Fatalf("empty expectation over a stored envelope = (%v, %v); want (false, nil)", won, err)
		}
		unchanged := reload(t, "access-cas")
		if unchanged.AccessTokenCiphertext != "stored-access" {
			t.Fatalf("a missed CAS wrote %q; want stored-access", unchanged.AccessTokenCiphertext)
		}

		if won, err := oauth.SaveOAuthAccessCAS(ctx, acc.ID, "stored-access", accessOnly); err != nil || !won {
			t.Fatalf("matching expectation = (%v, %v); want (true, nil)", won, err)
		}
		stored := reload(t, "access-cas")
		if stored.AccessTokenCiphertext != "winner-access" || stored.TokenScope != "read:user" ||
			stored.TokenExpiresAt == nil || !stored.TokenExpiresAt.Equal(expiresAt) {
			t.Fatalf("access columns = %+v; want the record's", stored)
		}
		if stored.RefreshTokenCiphertext != "stored-refresh" || stored.RefreshTokenFingerprint != strings.Repeat("a", 64) {
			t.Fatalf("refresh columns = (%q, %q); want them untouched",
				stored.RefreshTokenCiphertext, stored.RefreshTokenFingerprint)
		}
	})

	t.Run("access CAS treats an empty envelope as a value", func(t *testing.T) {
		acc := newLink(t, "access-cas-empty", db.OAuthTokenRecord{})

		if won, err := oauth.SaveOAuthAccessCAS(ctx, acc.ID, "", accessOnly); err != nil || !won {
			t.Fatalf("empty expectation over an empty envelope = (%v, %v); want (true, nil)", won, err)
		}
		if got := reload(t, "access-cas-empty"); got.AccessTokenCiphertext != "winner-access" {
			t.Fatalf("access ciphertext = %q; want winner-access", got.AccessTokenCiphertext)
		}
		if won, err := oauth.SaveOAuthAccessCAS(ctx, uuid.New(), "", accessOnly); err != nil || won {
			t.Fatalf("missing-account CAS = (%v, %v); want (false, nil)", won, err)
		}
	})
}

// sqlRecorder captures every statement gorm runs so a test can assert its shape.
type sqlRecorder struct {
	mu    sync.Mutex
	stmts []string
}

func (r *sqlRecorder) LogMode(logger.LogLevel) logger.Interface { return r }
func (r *sqlRecorder) Info(context.Context, string, ...any)     {}
func (r *sqlRecorder) Warn(context.Context, string, ...any)     {}
func (r *sqlRecorder) Error(context.Context, string, ...any)    {}

func (r *sqlRecorder) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, _ := fc()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stmts = append(r.stmts, sql)
}

// reset drops the statements recorded so far.
func (r *sqlRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stmts = nil
}

// updates returns the UPDATE statements recorded so far.
func (r *sqlRecorder) updates() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, stmt := range r.stmts {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), "UPDATE") {
			out = append(out, stmt)
		}
	}
	return out
}

// splitUpdate returns the SET assignment list and the WHERE clause of an UPDATE.
func splitUpdate(t *testing.T, stmt string) (set, where string) {
	t.Helper()
	upper := strings.ToUpper(stmt)
	i := strings.Index(upper, " SET ")
	j := strings.Index(upper, " WHERE ")
	if i < 0 || j < i {
		t.Fatalf("unexpected UPDATE shape: %s", stmt)
	}
	return stmt[i+len(" SET ") : j], stmt[j+len(" WHERE "):]
}

// TestOAuthAccountStore_RefreshIfUnsetGuardsInWhere pins the guard placement:
// MySQL applies single-table SET assignments left to right against the row it is
// updating, so an assignment that reads a column the same statement writes takes
// the already-updated value. A CASE map over access_token_ciphertext therefore
// leaves token_scope and token_expires_at stale or NULL, and tokenFresh treats a
// nil expiry as fresh. The guards must stay in their own WHERE clauses.
func TestOAuthAccountStore_RefreshIfUnsetGuardsInWhere(t *testing.T) {
	ctx := context.Background()
	database, _ := setupTestDB(t)
	recorder := &sqlRecorder{}
	oauth := &oauthAccountStore{db: database.Session(&gormdriver.Session{Logger: recorder})}
	userID := uuid.New()
	expiresAt := time.Now().UTC().Truncate(time.Millisecond)

	newLink := func(t *testing.T, sub string, rec db.OAuthTokenRecord) *db.OAuthAccount {
		t.Helper()
		acc := &db.OAuthAccount{
			UserID:         userID,
			ProviderID:     "github",
			ProviderUserID: sub,
			Email:          sub + "@example.com",
		}
		if err := oauth.Create(ctx, acc); err != nil {
			t.Fatalf("create link %s: %v", sub, err)
		}
		if rec != (db.OAuthTokenRecord{}) {
			if err := oauth.SaveOAuthTokens(ctx, acc.ID, rec); err != nil {
				t.Fatalf("seed tokens for %s: %v", sub, err)
			}
		}
		return acc
	}
	reload := func(t *testing.T, sub string) *db.OAuthAccount {
		t.Helper()
		got, err := oauth.GetByProvider(ctx, "github", "", sub)
		if err != nil {
			t.Fatalf("reload link %s: %v", sub, err)
		}
		return got
	}

	rotated := db.OAuthTokenRecord{
		AccessTokenCiphertext:   "rotated-access",
		RefreshTokenCiphertext:  "rotated-refresh",
		RefreshTokenFingerprint: strings.Repeat("9", 64),
		TokenScope:              "offline_access",
		TokenExpiresAt:          &expiresAt,
	}

	t.Run("assignments never read a column the statement writes", func(t *testing.T) {
		acc := newLink(t, "guard-where", db.OAuthTokenRecord{})
		recorder.reset()

		if won, err := oauth.SaveOAuthRefreshIfUnset(ctx, acc.ID, rotated); err != nil || !won {
			t.Fatalf("refresh-if-unset over a tokenless row = (%v, %v); want (true, nil)", won, err)
		}

		stmts := recorder.updates()
		if len(stmts) != 2 {
			t.Fatalf("UPDATE statements = %d (%v); want 2: the refresh pair, then the access fill", len(stmts), stmts)
		}
		refreshSet, refreshWhere := splitUpdate(t, stmts[0])
		accessSet, accessWhere := splitUpdate(t, stmts[1])
		if !strings.Contains(refreshSet, "refresh_token_fingerprint") ||
			!strings.Contains(refreshWhere, "refresh_token_fingerprint") {
			t.Fatalf("first statement = %s; want the refresh pair guarded on its fingerprint in WHERE", stmts[0])
		}
		if !strings.Contains(accessSet, "access_token_ciphertext") ||
			!strings.Contains(accessWhere, "access_token_ciphertext") {
			t.Fatalf("second statement = %s; want the access fill guarded on access_token_ciphertext in WHERE", stmts[1])
		}
		for _, stmt := range stmts {
			set, _ := splitUpdate(t, stmt)
			if strings.Contains(strings.ToUpper(set), "CASE") {
				t.Fatalf("assignment = %s; want no cross-referencing CASE", stmt)
			}
			assigned := make([]string, 0, 4)
			for _, assignment := range strings.Split(set, ",") {
				col, _, ok := strings.Cut(assignment, "=")
				if !ok {
					t.Fatalf("unparsable assignment %q in %s", assignment, stmt)
				}
				assigned = append(assigned, strings.Trim(strings.TrimSpace(col), "`\""))
			}
			for _, assignment := range strings.Split(set, ",") {
				col, expr, _ := strings.Cut(assignment, "=")
				col = strings.Trim(strings.TrimSpace(col), "`\"")
				lowerExpr := strings.ToLower(expr)
				for _, other := range assigned {
					if other == col {
						continue
					}
					if strings.Contains(lowerExpr, other) {
						t.Fatalf("assignment %q reads %q, which the same statement writes: %s", col, other, stmt)
					}
				}
			}
		}

		stored := reload(t, "guard-where")
		if stored.AccessTokenCiphertext != "rotated-access" || stored.TokenScope != "offline_access" {
			t.Fatalf("access columns = %+v; want the record's", stored)
		}
		if stored.TokenExpiresAt == nil || !stored.TokenExpiresAt.Equal(expiresAt) {
			t.Fatalf("expiry = %v; want the record's non-nil expiry", stored.TokenExpiresAt)
		}
	})

	t.Run("an access-filled row keeps a non-nil expiry", func(t *testing.T) {
		winnerExpiry := expiresAt.Add(-time.Minute)
		acc := newLink(t, "guard-winner", db.OAuthTokenRecord{
			AccessTokenCiphertext: "winner-access",
			TokenScope:            "read:user",
			TokenExpiresAt:        &winnerExpiry,
		})

		if won, err := oauth.SaveOAuthRefreshIfUnset(ctx, acc.ID, rotated); err != nil || !won {
			t.Fatalf("refresh-if-unset over an access-only row = (%v, %v); want (true, nil)", won, err)
		}
		stored := reload(t, "guard-winner")
		if stored.AccessTokenCiphertext != "winner-access" || stored.TokenScope != "read:user" {
			t.Fatalf("access columns = %+v; want the winner's untouched", stored)
		}
		if stored.TokenExpiresAt == nil || !stored.TokenExpiresAt.Equal(winnerExpiry) {
			t.Fatalf("expiry = %v; want the winner's non-nil expiry", stored.TokenExpiresAt)
		}
		if stored.RefreshTokenCiphertext != "rotated-refresh" || stored.RefreshTokenFingerprint != strings.Repeat("9", 64) {
			t.Fatalf("refresh columns = (%q, %q); want the rotated pair",
				stored.RefreshTokenCiphertext, stored.RefreshTokenFingerprint)
		}
	})
}

func TestOAuthAccountStore_TenantScopedKey(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()

	oauth := store.OAuthAccounts()
	userID := uuid.New()

	tenants := []string{"tenant-a", "tenant-b"}
	for _, tenant := range tenants {
		err := oauth.Create(ctx, &db.OAuthAccount{
			UserID:           userID,
			ProviderID:       "microsoft",
			ProviderTenantID: tenant,
			ProviderUserID:   "shared-sub",
			Email:            tenant + "@example.com",
		})
		if err != nil {
			t.Fatalf("create link for %s: %v", tenant, err)
		}
	}

	for _, tenant := range tenants {
		got, err := oauth.GetByProvider(ctx, "microsoft", tenant, "shared-sub")
		if err != nil {
			t.Fatalf("GetByProvider(%s) failed: %v", tenant, err)
		}
		if got.ProviderTenantID != tenant {
			t.Fatalf("resolved tenant = %q; want %q", got.ProviderTenantID, tenant)
		}
	}
	if _, err := oauth.GetByProvider(ctx, "microsoft", "tenant-c", "shared-sub"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound for an unlinked tenant, got %v", err)
	}
}

func TestTotpStore_AllMethods(t *testing.T) {
	_, store := setupTestDB(t)
	ctx := context.Background()
	totp := store.Totp()

	userID := uuid.New()
	secret := &db.TotpSecret{
		UserID:          userID,
		EncryptedSecret: []byte("enc_secret_blob"),
		BackupCodes:     []byte(`["code1","code2"]`),
		Enabled:         false,
	}

	// 1. CreateSecret
	if err := totp.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret failed: %v", err)
	}
	if secret.ID == uuid.Nil {
		t.Fatal("expected secret ID to be generated")
	}

	// 2. GetSecretByUserID
	gotSec, err := totp.GetSecretByUserID(ctx, userID)
	if err != nil || gotSec.ID != secret.ID {
		t.Fatalf("GetSecretByUserID mismatch: %v, %v", gotSec, err)
	}
	if _, err := totp.GetSecretByUserID(ctx, uuid.New()); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// 3. IsTotpEnabled (currently false)
	enabled, err := totp.IsTotpEnabled(ctx, userID)
	if err != nil || enabled {
		t.Fatalf("expected IsTotpEnabled false, got %v, err=%v", enabled, err)
	}

	// 4. EnableSecret
	newCodes := []byte(`["code3","code4"]`)
	if err := totp.EnableSecret(ctx, secret.ID, newCodes); err != nil {
		t.Fatalf("EnableSecret failed: %v", err)
	}

	// Calling EnableSecret again returns ErrTOTPAlreadyEnabled
	if err := totp.EnableSecret(ctx, secret.ID, newCodes); !errors.Is(err, apperrors.ErrTOTPAlreadyEnabled) {
		t.Fatalf("expected ErrTOTPAlreadyEnabled, got %v", err)
	}

	// 5. IsTotpEnabled (now true)
	enabledAfter, err := totp.IsTotpEnabled(ctx, userID)
	if err != nil || !enabledAfter {
		t.Fatalf("expected IsTotpEnabled true, got %v, err=%v", enabledAfter, err)
	}

	// 6. GetSecretByUserIDForUpdate
	secUp, err := totp.GetSecretByUserIDForUpdate(ctx, userID)
	if err != nil || secUp.ID != secret.ID {
		t.Fatalf("GetSecretByUserIDForUpdate failed: %v", err)
	}

	// 7. UpdateBackupCodes
	if err := totp.UpdateBackupCodes(ctx, userID, []string{"bc1", "bc2"}); err != nil {
		t.Fatalf("UpdateBackupCodes failed: %v", err)
	}

	// 8. UpdateBackupCodesJSON
	if err := totp.UpdateBackupCodesJSON(ctx, secret.ID, []byte(`["raw1"]`)); err != nil {
		t.Fatalf("UpdateBackupCodesJSON failed: %v", err)
	}
	// Missing secret returns ErrTOTPNotEnrolled
	if err := totp.UpdateBackupCodesJSON(ctx, uuid.New(), []byte(`["raw1"]`)); !errors.Is(err, apperrors.ErrTOTPNotEnrolled) {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
	}

	// 8b. UpdateBackupCodesCAS
	casSuccess, err := totp.UpdateBackupCodesCAS(ctx, userID, []string{"raw1"}, []string{"raw2"})
	if err != nil || !casSuccess {
		t.Fatalf("UpdateBackupCodesCAS expected success, got %v, err=%v", casSuccess, err)
	}
	casFail, err := totp.UpdateBackupCodesCAS(ctx, userID, []string{"wrong_stale"}, []string{"raw3"})
	if err != nil || casFail {
		t.Fatalf("UpdateBackupCodesCAS expected false on mismatch, got %v, err=%v", casFail, err)
	}

	// 9. DeleteUnconfirmedSecret (should not delete enabled secret)
	if err := totp.DeleteUnconfirmedSecret(ctx, userID); err != nil {
		t.Fatalf("DeleteUnconfirmedSecret failed: %v", err)
	}
	if stillGot, _ := totp.GetSecretByUserID(ctx, userID); stillGot == nil {
		t.Fatal("enabled secret should not have been deleted")
	}

	// Test DeleteUnconfirmedSecret with unconfirmed secret
	unconfirmedUID := uuid.New()
	_ = totp.CreateSecret(ctx, &db.TotpSecret{
		UserID:  unconfirmedUID,
		Enabled: false,
	})
	if err := totp.DeleteUnconfirmedSecret(ctx, unconfirmedUID); err != nil {
		t.Fatalf("DeleteUnconfirmedSecret for unconfirmed secret failed: %v", err)
	}
	if _, err := totp.GetSecretByUserID(ctx, unconfirmedUID); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatal("expected unconfirmed secret to be deleted")
	}

	// 10. DeleteSecret
	if err := totp.DeleteSecret(ctx, userID); err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}

	// 11. UsedCodes: RecordUsedCode, HasUsedCode, PruneUsedCodes
	usedNow := time.Now().UTC()
	codeHash := []byte("used_code_hash_1")
	usedCode := &db.TotpUsedCode{
		UserID:   userID,
		CodeHash: codeHash,
		UsedAt:   usedNow,
	}
	if err := totp.RecordUsedCode(ctx, usedCode); err != nil {
		t.Fatalf("RecordUsedCode failed: %v", err)
	}
	if usedCode.ID == uuid.Nil {
		t.Fatal("expected usedCode ID to be generated")
	}

	hasUsed, err := totp.HasUsedCode(ctx, userID, codeHash, usedNow.Add(-10*time.Minute))
	if err != nil || !hasUsed {
		t.Fatalf("HasUsedCode expected true, got %v, err=%v", hasUsed, err)
	}
	hasUsedOlder, err := totp.HasUsedCode(ctx, userID, codeHash, usedNow.Add(10*time.Minute))
	if err != nil || hasUsedOlder {
		t.Fatalf("HasUsedCode expected false, got %v, err=%v", hasUsedOlder, err)
	}

	if err := totp.PruneUsedCodes(ctx, userID, usedNow.Add(time.Hour)); err != nil {
		t.Fatalf("PruneUsedCodes failed: %v", err)
	}
	hasAfterPrune, _ := totp.HasUsedCode(ctx, userID, codeHash, usedNow.Add(-time.Hour))
	if hasAfterPrune {
		t.Fatal("expected code to be pruned")
	}

	// 12. TwoFactorToken operations
	tokHash := []byte("2fa_tok_hash_123")
	twoFaTok := &db.TwoFactorToken{
		UserID:    userID,
		TokenHash: tokHash,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Attempts:  0,
	}
	if err := totp.CreateTwoFactorToken(ctx, twoFaTok); err != nil {
		t.Fatalf("CreateTwoFactorToken failed: %v", err)
	}
	if twoFaTok.ID == uuid.Nil {
		t.Fatal("expected token ID to be generated")
	}

	got2FA, err := totp.GetTwoFactorToken(ctx, tokHash)
	if err != nil || got2FA.ID != twoFaTok.ID {
		t.Fatalf("GetTwoFactorToken mismatch: %v, %v", got2FA, err)
	}
	if _, err := totp.GetTwoFactorToken(ctx, []byte("missing")); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// IncrementTwoFactorAttempts - normal
	attempts, err := totp.IncrementTwoFactorAttempts(ctx, tokHash, 5, time.Now().UTC())
	if err != nil || attempts != 1 {
		t.Fatalf("IncrementTwoFactorAttempts normal: attempts=%d, err=%v", attempts, err)
	}

	// IncrementTwoFactorAttempts - default maxAttempts (<= 0)
	attempts2, err := totp.IncrementTwoFactorAttempts(ctx, tokHash, 0, time.Now().UTC())
	if err != nil || attempts2 != 2 {
		t.Fatalf("IncrementTwoFactorAttempts default max: attempts=%d, err=%v", attempts2, err)
	}

	// IncrementTwoFactorAttempts - non-existent
	if _, err := totp.IncrementTwoFactorAttempts(ctx, []byte("missing"), 5, time.Now().UTC()); !errors.Is(err, apperrors.ErrTwoFactorTokenInvalid) {
		t.Fatalf("expected ErrTwoFactorTokenInvalid, got %v", err)
	}

	// IncrementTwoFactorAttempts - expired
	expired2FA := &db.TwoFactorToken{
		UserID:    userID,
		TokenHash: []byte("expired_2fa_hash"),
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}
	_ = totp.CreateTwoFactorToken(ctx, expired2FA)
	if _, err := totp.IncrementTwoFactorAttempts(ctx, []byte("expired_2fa_hash"), 5, time.Now().UTC()); !errors.Is(err, apperrors.ErrTwoFactorTokenExpired) {
		t.Fatalf("expected ErrTwoFactorTokenExpired, got %v", err)
	}

	// IncrementTwoFactorAttempts - max attempts exceeded
	capped2FA := &db.TwoFactorToken{
		UserID:    userID,
		TokenHash: []byte("capped_2fa_hash"),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Attempts:  2,
	}
	_ = totp.CreateTwoFactorToken(ctx, capped2FA)
	attCapped, err := totp.IncrementTwoFactorAttempts(ctx, []byte("capped_2fa_hash"), 3, time.Now().UTC())
	if !errors.Is(err, apperrors.ErrTwoFactorMaxAttemptsExceeded) || attCapped != 3 {
		t.Fatalf("expected ErrTwoFactorMaxAttemptsExceeded with 3 attempts, got %d, %v", attCapped, err)
	}

	// ConsumeTwoFactorToken - valid
	consumeValidTok := &db.TwoFactorToken{
		UserID:    userID,
		TokenHash: []byte("consume_tok_hash"),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		Attempts:  0,
	}
	_ = totp.CreateTwoFactorToken(ctx, consumeValidTok)
	consumed, err := totp.ConsumeTwoFactorToken(ctx, []byte("consume_tok_hash"), 5, time.Now().UTC())
	if err != nil || !consumed {
		t.Fatalf("ConsumeTwoFactorToken expected true, got %v, err=%v", consumed, err)
	}
	// Already consumed -> false
	consumedAgain, err := totp.ConsumeTwoFactorToken(ctx, []byte("consume_tok_hash"), 5, time.Now().UTC())
	if err != nil || consumedAgain {
		t.Fatalf("ConsumeTwoFactorToken expected false on second attempt, got %v, err=%v", consumedAgain, err)
	}

	// DeleteTwoFactorToken
	delCount, err := totp.DeleteTwoFactorToken(ctx, twoFaTok.ID)
	if err != nil || delCount != 1 {
		t.Fatalf("DeleteTwoFactorToken: count=%d, err=%v", delCount, err)
	}

	// DeleteTwoFactorTokensByUserID
	tokByUID := &db.TwoFactorToken{
		UserID:    userID,
		TokenHash: []byte("2fa_by_uid"),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	_ = totp.CreateTwoFactorToken(ctx, tokByUID)
	if err := totp.DeleteTwoFactorTokensByUserID(ctx, userID); err != nil {
		t.Fatalf("DeleteTwoFactorTokensByUserID failed: %v", err)
	}
}

func TestNormalizeMySQLError_StoreIntegration(t *testing.T) {
	if got := db.NormalizeMySQLError(nil); got != nil {
		t.Fatalf("NormalizeMySQLError(nil) = %v; want nil", got)
	}

	generic := errors.New("table does not exist")
	if got := db.NormalizeMySQLError(generic); got != generic {
		t.Fatalf("expected generic error to pass through, got %v", got)
	}

	// Test error containing 1062 duplicate entry
	dupEmail := errors.New("Error 1062 (23000): Duplicate entry 'a@b.com' for key 'users.idx_users_email'")
	if got := db.NormalizeMySQLError(dupEmail); !errors.Is(got, apperrors.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got %v", got)
	}

	dupTotp := errors.New("Error 1062: Duplicate entry for key 'uq_totp_used_codes'")
	if got := db.NormalizeMySQLError(dupTotp); !errors.Is(got, apperrors.ErrTOTPCodeReplayed) {
		t.Fatalf("expected ErrTOTPCodeReplayed, got %v", got)
	}

	dupTotpSec := errors.New("Error 1062: Duplicate entry for key 'totp_secrets'")
	if got := db.NormalizeMySQLError(dupTotpSec); !errors.Is(got, apperrors.ErrTOTPAlreadyEnabled) {
		t.Fatalf("expected ErrTOTPAlreadyEnabled, got %v", got)
	}

	dupOAuth := errors.New("Error 1062: Duplicate entry for key 'uq_oauth_accounts'")
	if got := db.NormalizeMySQLError(dupOAuth); !errors.Is(got, apperrors.ErrOAuthAccountAlreadyLinked) {
		t.Fatalf("expected ErrOAuthAccountAlreadyLinked, got %v", got)
	}

	dupUnknown := errors.New("Error 1062: Duplicate entry for key 'unknown_key'")
	if got := db.NormalizeMySQLError(dupUnknown); got != dupUnknown {
		t.Fatalf("expected unknown 1062 error to pass through, got %v", got)
	}

	fkErr := errors.New("ERROR: insert or update on table \"oauth_accounts\" violates foreign key constraint \"fk_oauth_accounts_user_id\" (SQLSTATE 23503)")
	if got := db.NormalizeMySQLError(fkErr); !errors.Is(got, apperrors.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound for postgres fk error, got %v", got)
	}

	if got := db.NormalizeMySQLError(gormdriver.ErrForeignKeyViolated); !errors.Is(got, apperrors.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound for gorm ErrForeignKeyViolated, got %v", got)
	}
}

type dummyDialector struct {
	gormdriver.Dialector
}

func (d dummyDialector) Name() string { return "postgres" }

func TestLockForUpdate_NonSQLite(t *testing.T) {
	database, _ := setupTestDB(t)
	tx := database.Session(&gormdriver.Session{})
	tx.Dialector = dummyDialector{}
	res := lockForUpdate(tx)
	if res == nil {
		t.Fatal("expected non-nil db from lockForUpdate")
	}
}

func TestStore_ContextCanceledErrors(t *testing.T) {
	_, store := setupTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	uid := uuid.New()
	if err := store.Users().Create(ctx, &db.User{Email: "err@example.com"}); err == nil {
		t.Fatal("expected error on Create user with canceled ctx")
	}
	if err := store.Sessions().Create(ctx, &db.Session{IDHash: "err_hash"}); err == nil {
		t.Fatal("expected error on Create session with canceled ctx")
	}
	if err := store.OAuthAccounts().Create(ctx, &db.OAuthAccount{ProviderID: "gh"}); err == nil {
		t.Fatal("expected error on Create oauth with canceled ctx")
	}
	if err := store.Totp().CreateSecret(ctx, &db.TotpSecret{UserID: uid}); err == nil {
		t.Fatal("expected error on CreateSecret with canceled ctx")
	}
	if err := store.Totp().RecordUsedCode(ctx, &db.TotpUsedCode{UserID: uid}); err == nil {
		t.Fatal("expected error on RecordUsedCode with canceled ctx")
	}
}

// TestTotpStore_RewrapPair covers the keyset read and the CAS write the sweep is
// built on: pages ordered by id, pending and enabled rows alike, one statement
// writing ciphertext and hint, and a stale expectation reported as a miss.
func TestTotpStore_RewrapPair(t *testing.T) {
	database, store := setupTestDB(t)
	ctx := context.Background()
	totpStore := store.Totp()

	rows, err := totpStore.ListSecretsForRewrap(ctx, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("empty ListSecretsForRewrap: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("empty table returned %d rows", len(rows))
	}

	blobs := make(map[uuid.UUID][]byte)
	ids := make([]uuid.UUID, 0, 3)
	for i := 0; i < 3; i++ {
		secret := &db.TotpSecret{
			UserID:          uuid.New(),
			EncryptedSecret: []byte(fmt.Sprintf("blob-%d", i)),
			BackupCodes:     []byte("[]"),
			Enabled:         i%2 == 0,
		}
		if err := totpStore.CreateSecret(ctx, secret); err != nil {
			t.Fatalf("CreateSecret: %v", err)
		}
		ids = append(ids, secret.ID)
		blobs[secret.ID] = secret.EncryptedSecret
	}

	var paged []db.TotpSecretRewrap
	cursor := uuid.Nil
	for {
		page, err := totpStore.ListSecretsForRewrap(ctx, cursor, 2)
		if err != nil {
			t.Fatalf("ListSecretsForRewrap: %v", err)
		}
		paged = append(paged, page...)
		if len(page) < 2 {
			break
		}
		cursor = page[len(page)-1].ID
	}
	if len(paged) != len(ids) {
		t.Fatalf("paged %d rows, want %d", len(paged), len(ids))
	}
	for i, row := range paged {
		if i > 0 && paged[i-1].ID.String() >= row.ID.String() {
			t.Fatalf("rows are not ordered by id at %d", i)
		}
		if row.UserID == uuid.Nil {
			t.Errorf("row %s lost its user id", row.ID)
		}
		if !equalsBytes(row.EncryptedSecret, blobs[row.ID]) {
			t.Errorf("row %s ciphertext mismatch", row.ID)
		}
		if row.SecretKid != "" {
			t.Errorf("row %s hint = %q, want empty for a fresh enrolment", row.ID, row.SecretKid)
		}
	}

	if page, err := totpStore.ListSecretsForRewrap(ctx, uuid.Nil, 0); err != nil || len(page) != 0 {
		t.Fatalf("limit 0 returned (%d rows, %v)", len(page), err)
	}

	target := ids[0]
	updated, err := totpStore.UpdateSecretForRewrap(ctx, target, blobs[target], []byte("new-blob"), "k2")
	if err != nil {
		t.Fatalf("UpdateSecretForRewrap: %v", err)
	}
	if !updated {
		t.Fatal("CAS update with the current ciphertext reported a miss")
	}

	var hint string
	if err := database.Raw("SELECT secret_kid FROM totp_secrets WHERE id = ?", target.String()).Scan(&hint).Error; err != nil {
		t.Fatalf("read hint: %v", err)
	}
	if hint != "k2" {
		t.Fatalf("hint = %q, want k2", hint)
	}

	stale, err := totpStore.UpdateSecretForRewrap(ctx, target, blobs[target], []byte("stale-blob"), "k1")
	if err != nil {
		t.Fatalf("stale UpdateSecretForRewrap: %v", err)
	}
	if stale {
		t.Fatal("CAS update with a stale ciphertext reported a hit")
	}

	var ciphertext []byte
	if err := database.Raw("SELECT encrypted_secret FROM totp_secrets WHERE id = ?", target.String()).Row().Scan(&ciphertext); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if !equalsBytes(ciphertext, []byte("new-blob")) {
		t.Fatalf("ciphertext = %q, want new-blob", ciphertext)
	}
}

func equalsBytes(a, b []byte) bool {
	return bytes.Equal(a, b)
}
