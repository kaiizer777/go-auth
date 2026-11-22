package gormstore

import (
	"context"
	"errors"
	"fmt"
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
	got, err := oauth.GetByProvider(ctx, "github", "gh_user_42")
	if err != nil || got.ID != acc.ID {
		t.Fatalf("GetByProvider mismatch: %v, %v", got, err)
	}
	if _, err := oauth.GetByProvider(ctx, "github", "missing"); !errors.Is(err, gormdriver.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}

	// 3. GetByUserID
	list, err := oauth.GetByUserID(ctx, userID)
	if err != nil || len(list) != 1 {
		t.Fatalf("GetByUserID got %d items, err=%v", len(list), err)
	}

	// 4. Delete
	if err := oauth.Delete(ctx, acc.ID); err != nil {
		t.Fatalf("Delete oauth account failed: %v", err)
	}

	// 5. DeleteByUserID
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
