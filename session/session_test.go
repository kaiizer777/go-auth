package session

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:mem_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}

	ddl := `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie',
		csrf_token CHAR(64) NOT NULL DEFAULT '',
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return database
}

func testConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.SessionIdleTimeout = 30 * time.Minute
	cfg.SessionAbsoluteMaxAge = 24 * time.Hour
	return &cfg
}

func TestGenerateRawID_Entropy(t *testing.T) {
	const count = 1000
	seen := make(map[string]struct{}, count)

	for i := 0; i < count; i++ {
		id, err := generateRawID()
		if err != nil {
			t.Fatalf("generateRawID failed: %v", err)
		}

		if len(id) != 32 {
			t.Fatalf("expected len 32, got %d for %q", len(id), id)
		}

		decoded, err := hex.DecodeString(id)
		if err != nil {
			t.Fatalf("expected valid hex string, got %v for %q", err, id)
		}
		if len(decoded) != 16 {
			t.Fatalf("expected 16 decoded bytes, got %d", len(decoded))
		}

		if _, exists := seen[id]; exists {
			t.Fatalf("collision detected at iteration %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestHashID_Deterministic(t *testing.T) {
	id1 := "0123456789abcdef0123456789abcdef"
	id2 := "fedcba9876543210fedcba9876543210"

	h1 := hashID(id1)
	h1Repeat := hashID(id1)
	h2 := hashID(id2)

	if h1 != h1Repeat {
		t.Fatalf("expected deterministic hash, got %q != %q", h1, h1Repeat)
	}

	if h1 == h2 {
		t.Fatalf("expected distinct hashes for distinct IDs, got identical %q", h1)
	}

	if len(h1) != 64 {
		t.Fatalf("expected 64 chars, got %d", len(h1))
	}

	if _, err := hex.DecodeString(h1); err != nil {
		t.Fatalf("expected valid hex hash, got %v", err)
	}
}

func TestCreateSession_StoresHash(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	userID := uuid.New()
	sess, rawID, err := svc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if len(rawID) != 32 {
		t.Fatalf("expected rawID len 32, got %d", len(rawID))
	}

	expectedHash := hashID(rawID)
	if sess.IDHash != expectedHash {
		t.Fatalf("expected domain IDHash %q, got %q", expectedHash, sess.IDHash)
	}

	var row db.Session
	if err := database.Where("id_hash = ?", expectedHash).First(&row).Error; err != nil {
		t.Fatalf("failed to query session by hash: %v", err)
	}

	if row.IDHash != expectedHash {
		t.Fatalf("expected DB id_hash %q, got %q", expectedHash, row.IDHash)
	}
	if row.UserID != userID {
		t.Fatalf("expected DB user_id %s, got %s", userID, row.UserID)
	}
	if row.IPAddress != "127.0.0.1" || row.UserAgent != "test-agent" {
		t.Fatalf("unexpected metadata: ip=%q, ua=%q", row.IPAddress, row.UserAgent)
	}

	now := time.Now().UTC()
	if row.LastActiveAt.Before(now.Add(-2*time.Second)) || row.LastActiveAt.After(now.Add(2*time.Second)) {
		t.Fatalf("unexpected LastActiveAt: %v", row.LastActiveAt)
	}
	expectedExpiry := now.Add(cfg.SessionAbsoluteMaxAge)
	if row.AbsoluteExpiresAt.Before(expectedExpiry.Add(-2*time.Second)) || row.AbsoluteExpiresAt.After(expectedExpiry.Add(2*time.Second)) {
		t.Fatalf("unexpected AbsoluteExpiresAt: %v", row.AbsoluteExpiresAt)
	}
}

func TestGetSession_IdleTimeout(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	rawID, _ := generateRawID()
	now := time.Now().UTC()
	row := &db.Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      now.Add(-cfg.SessionIdleTimeout - 2*time.Second),
		AbsoluteExpiresAt: now.Add(cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now.Add(-cfg.SessionIdleTimeout - 2*time.Second),
	}
	if err := database.Create(row).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	sess, err := svc.GetSession(context.Background(), rawID)
	if sess != nil {
		t.Fatalf("expected nil session, got %+v", sess)
	}
	if !errors.Is(err, apperrors.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}

	var check db.Session
	err = database.Where("id_hash = ?", row.IDHash).First(&check).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected expired session to be deleted, got err=%v", err)
	}
}

func TestGetSession_IdleCheckDoesNotEvictRefreshedSession(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	userID := uuid.New()
	rawID, err := generateRawID()
	if err != nil {
		t.Fatalf("generateRawID failed: %v", err)
	}

	now := time.Now().UTC()
	staleActive := now.Add(-cfg.SessionIdleTimeout - 5*time.Minute)
	seed := &db.Session{
		ID:                uuid.New(),
		UserID:            userID,
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		IPAddress:         "127.0.0.1",
		UserAgent:         "agent",
		LastActiveAt:      staleActive,
		AbsoluteExpiresAt: now.Add(cfg.SessionAbsoluteMaxAge),
		CreatedAt:         staleActive,
	}
	if err := database.Create(seed).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	var bumped bool
	_ = database.Callback().Delete().Before("gorm:delete").Register("test:bump_activity_get", func(tx *gorm.DB) {
		if !bumped {
			bumped = true
			rawDB, _ := tx.DB()
			_, _ = rawDB.Exec("UPDATE sessions SET last_active_at = ? WHERE id = ?", time.Now().UTC(), seed.ID.String())
		}
	})

	sess, err := svc.GetSession(context.Background(), rawID)
	if err != nil {
		t.Fatalf("expected active refreshed session, got error: %v", err)
	}
	if sess == nil || sess.IDHash != seed.IDHash {
		t.Fatalf("expected valid session, got %+v", sess)
	}

	var row db.Session
	if err := database.Where("id = ?", seed.ID).First(&row).Error; err != nil {
		t.Fatalf("expected session row to be retained, got err: %v", err)
	}
}

func TestGetSession_AbsoluteTimeout(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	rawID, _ := generateRawID()
	now := time.Now().UTC()
	row := &db.Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(-2 * time.Second),
		CreatedAt:         now.Add(-25 * time.Hour),
	}
	if err := database.Create(row).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	sess, err := svc.GetSession(context.Background(), rawID)
	if sess != nil {
		t.Fatalf("expected nil session, got %+v", sess)
	}
	if !errors.Is(err, apperrors.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}

	var check db.Session
	err = database.Where("id_hash = ?", row.IDHash).First(&check).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected absolute-expired session to be deleted, got err=%v", err)
	}
}

func TestGetSession_Valid(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	userID := uuid.New()
	rawID, err := generateRawID()
	if err != nil {
		t.Fatalf("generateRawID failed: %v", err)
	}

	now := time.Now().UTC()
	initialLastActive := now.Add(-5 * time.Minute).Truncate(time.Second)
	seed := &db.Session{
		ID:                uuid.New(),
		UserID:            userID,
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		IPAddress:         "127.0.0.1",
		UserAgent:         "agent",
		LastActiveAt:      initialLastActive,
		AbsoluteExpiresAt: now.Add(cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now.Add(-10 * time.Minute),
	}
	if err := database.Create(seed).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	sess, err := svc.GetSession(context.Background(), rawID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if sess.IDHash != seed.IDHash {
		t.Fatalf("expected IDHash %q, got %q", seed.IDHash, sess.IDHash)
	}
	if sess.UserID != userID {
		t.Fatalf("expected UserID %s, got %s", userID, sess.UserID)
	}

	// Poll with a bounded timeout for the asynchronous LastActiveAt update to finish
	var row db.Session
	var updated bool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := database.Where("id_hash = ?", sess.IDHash).First(&row).Error; err == nil {
			if row.LastActiveAt.After(initialLastActive) {
				updated = true
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !updated {
		t.Fatalf("expected LastActiveAt to be updated past %v within deadline, got %v", initialLastActive, row.LastActiveAt)
	}
}

func TestGetSession_MonotonicLastActiveAtUpdate(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	userID := uuid.New()
	rawID, err := generateRawID()
	if err != nil {
		t.Fatalf("generateRawID failed: %v", err)
	}

	now := time.Now().UTC()
	futureActive := now.Add(10 * time.Minute).Truncate(time.Second)
	seed := &db.Session{
		ID:                uuid.New(),
		UserID:            userID,
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		IPAddress:         "127.0.0.1",
		UserAgent:         "agent",
		LastActiveAt:      futureActive,
		AbsoluteExpiresAt: now.Add(cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now.Add(-10 * time.Minute),
	}
	if err := database.Create(seed).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	if _, err := svc.GetSession(context.Background(), rawID); err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Wait briefly for background goroutine to complete
	time.Sleep(50 * time.Millisecond)

	var row db.Session
	if err := database.Where("id_hash = ?", seed.IDHash).First(&row).Error; err != nil {
		t.Fatalf("failed to query row: %v", err)
	}
	if row.LastActiveAt.Before(futureActive) {
		t.Fatalf("expected LastActiveAt not to regress backward, got %v < %v", row.LastActiveAt, futureActive)
	}
}

func TestRawIDValidation_MalformedInputs(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	malformedIDs := []struct {
		name  string
		rawID string
	}{
		{"empty", ""},
		{"too short (31 chars)", "0123456789abcdef0123456789abcde"},
		{"too long (33 chars)", "0123456789abcdef0123456789abcdef0"},
		{"non-hex character", "0123456789abcdef0123456789abcdeg"},
	}

	for _, tc := range malformedIDs {
		t.Run(tc.name, func(t *testing.T) {
			sess, err := svc.GetSession(context.Background(), tc.rawID)
			if sess != nil {
				t.Errorf("GetSession(%q): expected nil session, got %+v", tc.rawID, sess)
			}
			if !errors.Is(err, apperrors.ErrSessionInvalid) {
				t.Errorf("GetSession(%q): expected ErrSessionInvalid, got %v", tc.rawID, err)
			}

			if err := svc.InvalidateSession(context.Background(), tc.rawID); !errors.Is(err, apperrors.ErrSessionInvalid) {
				t.Errorf("InvalidateSession(%q): expected ErrSessionInvalid, got %v", tc.rawID, err)
			}

			rotSess, newRawID, err := svc.RotateSession(context.Background(), tc.rawID, "127.0.0.1", "agent")
			if rotSess != nil || newRawID != "" {
				t.Errorf("RotateSession(%q): expected nil session and empty rawID, got sess=%+v, newRawID=%q", tc.rawID, rotSess, newRawID)
			}
			if !errors.Is(err, apperrors.ErrSessionInvalid) {
				t.Errorf("RotateSession(%q): expected ErrSessionInvalid, got %v", tc.rawID, err)
			}
		})
	}
}

func TestGetSession_NotFound(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	sess, err := svc.GetSession(context.Background(), "0123456789abcdef0123456789abcdef")
	if sess != nil {
		t.Fatalf("expected nil session, got %+v", sess)
	}
	if !errors.Is(err, apperrors.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestInvalidateSession_DeletesRow(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	_, rawID, err := svc.CreateSession(context.Background(), uuid.New(), db.SessionTypeCookie, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if err := svc.InvalidateSession(context.Background(), rawID); err != nil {
		t.Fatalf("InvalidateSession failed: %v", err)
	}

	sess, err := svc.GetSession(context.Background(), rawID)
	if sess != nil {
		t.Fatalf("expected nil session after invalidation, got %+v", sess)
	}
	if !errors.Is(err, apperrors.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestInvalidateSession_Idempotent(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	_, rawID, err := svc.CreateSession(context.Background(), uuid.New(), db.SessionTypeCookie, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if err := svc.InvalidateSession(context.Background(), rawID); err != nil {
		t.Fatalf("first InvalidateSession failed: %v", err)
	}
	if err := svc.InvalidateSession(context.Background(), rawID); err != nil {
		t.Fatalf("second InvalidateSession failed (must be idempotent): %v", err)
	}
}

func TestInvalidateAllUserSessions(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	userA := uuid.New()
	userB := uuid.New()

	var tokensA []string
	for i := 0; i < 3; i++ {
		_, rawID, err := svc.CreateSession(context.Background(), userA, db.SessionTypeCookie, "127.0.0.1", "agent")
		if err != nil {
			t.Fatalf("CreateSession userA failed: %v", err)
		}
		tokensA = append(tokensA, rawID)
	}

	var tokensB []string
	for i := 0; i < 2; i++ {
		_, rawID, err := svc.CreateSession(context.Background(), userB, db.SessionTypeCookie, "127.0.0.1", "agent")
		if err != nil {
			t.Fatalf("CreateSession userB failed: %v", err)
		}
		tokensB = append(tokensB, rawID)
	}

	if err := svc.InvalidateAllUserSessions(context.Background(), userA); err != nil {
		t.Fatalf("InvalidateAllUserSessions failed: %v", err)
	}

	for _, token := range tokensA {
		_, err := svc.GetSession(context.Background(), token)
		if !errors.Is(err, apperrors.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound for invalidated userA session, got %v", err)
		}
	}

	for _, token := range tokensB {
		sess, err := svc.GetSession(context.Background(), token)
		if err != nil || sess == nil {
			t.Fatalf("expected userB session to remain valid, got err=%v", err)
		}
	}
}

func TestRotateSession_Transaction(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	userID := uuid.New()
	_, oldRawID, err := svc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "1.1.1.1", "agent-old")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	newSess, newRawID, err := svc.RotateSession(context.Background(), oldRawID, "2.2.2.2", "agent-new")
	if err != nil {
		t.Fatalf("RotateSession failed: %v", err)
	}

	if newRawID == oldRawID {
		t.Fatal("expected newRawID to differ from oldRawID")
	}
	if len(newRawID) != 32 {
		t.Fatalf("expected newRawID len 32, got %d", len(newRawID))
	}
	if newSess.UserID != userID {
		t.Fatalf("expected preserved UserID %s, got %s", userID, newSess.UserID)
	}
	if newSess.IPAddress != "2.2.2.2" || newSess.UserAgent != "agent-new" {
		t.Fatalf("unexpected rotated metadata: ip=%q, ua=%q", newSess.IPAddress, newSess.UserAgent)
	}

	// Old raw ID must now return ErrSessionNotFound
	oldSess, err := svc.GetSession(context.Background(), oldRawID)
	if oldSess != nil {
		t.Fatalf("expected nil session for oldRawID, got %+v", oldSess)
	}
	if !errors.Is(err, apperrors.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for oldRawID, got %v", err)
	}

	// New raw ID must be valid
	validSess, err := svc.GetSession(context.Background(), newRawID)
	if err != nil || validSess == nil {
		t.Fatalf("expected newRawID to be valid, got err=%v", err)
	}
	if validSess.IDHash != hashID(newRawID) {
		t.Fatalf("expected IDHash %q, got %q", hashID(newRawID), validSess.IDHash)
	}
}

func TestRotateSession_Expired_IdleTimeout(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	rawID, _ := generateRawID()
	now := time.Now().UTC()
	row := &db.Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      now.Add(-cfg.SessionIdleTimeout - 2*time.Second),
		AbsoluteExpiresAt: now.Add(cfg.SessionAbsoluteMaxAge),
		CreatedAt:         now.Add(-cfg.SessionIdleTimeout - 2*time.Second),
	}
	if err := database.Create(row).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	sess, newRawID, err := svc.RotateSession(context.Background(), rawID, "1.1.1.1", "agent")
	if sess != nil || newRawID != "" {
		t.Fatalf("expected nil session and empty rawID, got sess=%+v, rawID=%q", sess, newRawID)
	}
	if !errors.Is(err, apperrors.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}

	var check db.Session
	err = database.Where("id_hash = ?", row.IDHash).First(&check).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected expired session to be deleted, got err=%v", err)
	}
}

func TestRotateSession_IdleCheckDoesNotEvictRefreshedSession(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	userID := uuid.New()
	rawID, err := generateRawID()
	if err != nil {
		t.Fatalf("generateRawID failed: %v", err)
	}

	now := time.Now().UTC()
	staleActive := now.Add(-cfg.SessionIdleTimeout - 5*time.Minute)
	seed := &db.Session{
		ID:                uuid.New(),
		UserID:            userID,
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		IPAddress:         "127.0.0.1",
		UserAgent:         "agent-old",
		LastActiveAt:      staleActive,
		AbsoluteExpiresAt: now.Add(cfg.SessionAbsoluteMaxAge),
		CreatedAt:         staleActive,
	}
	if err := database.Create(seed).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	var bumped bool
	_ = database.Callback().Delete().Before("gorm:delete").Register("test:bump_activity_rotate", func(tx *gorm.DB) {
		if !bumped {
			bumped = true
			rawDB, _ := tx.DB()
			_, _ = rawDB.Exec("UPDATE sessions SET last_active_at = ? WHERE id_hash = ?", time.Now().UTC(), seed.IDHash)
		}
	})

	newSess, newRawID, err := svc.RotateSession(context.Background(), rawID, "2.2.2.2", "agent-new")
	if err != nil {
		t.Fatalf("expected RotateSession to succeed on refreshed session, got error: %v", err)
	}
	if newSess == nil || newRawID == "" {
		t.Fatalf("expected rotated session, got sess=%+v, rawID=%q", newSess, newRawID)
	}
}

func TestRotateSession_Expired_AbsoluteTimeout(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	rawID, _ := generateRawID()
	now := time.Now().UTC()
	row := &db.Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      now,
		AbsoluteExpiresAt: now.Add(-2 * time.Second),
		CreatedAt:         now.Add(-25 * time.Hour),
	}
	if err := database.Create(row).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	sess, newRawID, err := svc.RotateSession(context.Background(), rawID, "1.1.1.1", "agent")
	if sess != nil || newRawID != "" {
		t.Fatalf("expected nil session and empty rawID, got sess=%+v, rawID=%q", sess, newRawID)
	}
	if !errors.Is(err, apperrors.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}

	var check db.Session
	err = database.Where("id_hash = ?", row.IDHash).First(&check).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected expired session to be deleted, got err=%v", err)
	}
}

func TestRotateSession_NotFound(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	sess, newRawID, err := svc.RotateSession(context.Background(), "0123456789abcdef0123456789abcdef", "1.1.1.1", "agent")
	if sess != nil || newRawID != "" {
		t.Fatalf("expected nil session, got %+v", sess)
	}
	if !errors.Is(err, apperrors.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestRotateSession_ConcurrentOrDoubleRotate(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	_, oldRawID, err := svc.CreateSession(context.Background(), uuid.New(), db.SessionTypeCookie, "1.1.1.1", "agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// First rotation succeeds
	sess1, newRawID1, err1 := svc.RotateSession(context.Background(), oldRawID, "2.2.2.2", "agent-2")
	if err1 != nil || sess1 == nil || newRawID1 == "" {
		t.Fatalf("first rotation failed: %v", err1)
	}

	// Double rotation with the already-deleted old token fails with ErrSessionNotFound
	sess2, newRawID2, err2 := svc.RotateSession(context.Background(), oldRawID, "3.3.3.3", "agent-3")
	if sess2 != nil || newRawID2 != "" {
		t.Fatalf("second rotation should fail, got sess=%+v, newRawID=%q", sess2, newRawID2)
	}
	if !errors.Is(err2, apperrors.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for double-rotation, got %v", err2)
	}
}

func TestRotateSession_PreservesAbsoluteExpiresAt(t *testing.T) {
	database := setupTestDB(t)
	cfg := testConfig()
	svc := NewService(database, cfg)

	rawID, _ := generateRawID()
	now := time.Now().UTC()
	// Set absolute expiry to 3 hours from now (less than default 24h)
	initialAbsoluteExpiry := now.Add(3 * time.Hour).Truncate(time.Second)
	row := &db.Session{
		ID:                uuid.New(),
		UserID:            uuid.New(),
		IDHash:            hashID(rawID),
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      now,
		AbsoluteExpiresAt: initialAbsoluteExpiry,
		CreatedAt:         now.Add(-2 * time.Hour),
	}
	if err := database.Create(row).Error; err != nil {
		t.Fatalf("failed to seed session: %v", err)
	}

	newSess, newRawID, err := svc.RotateSession(context.Background(), rawID, "2.2.2.2", "agent-rot")
	if err != nil {
		t.Fatalf("RotateSession failed: %v", err)
	}
	if newRawID == "" {
		t.Fatal("expected non-empty newRawID")
	}

	if !newSess.AbsoluteExpiresAt.Equal(initialAbsoluteExpiry) {
		t.Fatalf("expected preserved AbsoluteExpiresAt %v, got %v", initialAbsoluteExpiry, newSess.AbsoluteExpiresAt)
	}

	var dbRow db.Session
	if err := database.Where("id_hash = ?", hashID(newRawID)).First(&dbRow).Error; err != nil {
		t.Fatalf("failed to query new session: %v", err)
	}
	if !dbRow.AbsoluteExpiresAt.Equal(initialAbsoluteExpiry) {
		t.Fatalf("expected DB AbsoluteExpiresAt %v, got %v", initialAbsoluteExpiry, dbRow.AbsoluteExpiresAt)
	}
}
