package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/session"
)

func setupSessionTestDB(t *testing.T) *gorm.DB {
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
		ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL,
		absolute_expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to create sessions schema: %v", err)
	}

	return database
}

func testSessionConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.SessionIdleTimeout = 30 * time.Minute
	cfg.SessionAbsoluteMaxAge = 24 * time.Hour
	return &cfg
}

func TestSessionHandler_GetCurrentSession(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	userID := uuid.New()
	sess, rawID, err := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	ctx := context.WithValue(req.Context(), contextKeySession, sess)
	ctx = context.WithValue(ctx, contextKeyRawID, rawID)
	ctx = context.WithValue(ctx, contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.GetCurrentSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var res struct {
		Session struct {
			SessionID   string `json:"session_id"`
			SessionType string `json:"session_type"`
		} `json:"session"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if res.Session.SessionID != sess.IDHash {
		t.Errorf("expected session_id to be IDHash %q, got %q", sess.IDHash, res.Session.SessionID)
	}
	if len(res.Session.SessionID) != 64 {
		t.Errorf("expected 64-char SHA-256 hex session_id, got %d chars", len(res.Session.SessionID))
	}
	if res.Session.SessionType != "cookie" {
		t.Errorf("expected session_type 'cookie', got %q", res.Session.SessionType)
	}
}

func TestSessionHandler_GetCurrentSession_MissingContext(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	rec := httptest.NewRecorder()
	h.GetCurrentSession(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
	}
}

func TestSessionHandler_Logout(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	userID := uuid.New()
	sess, rawID, err := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "127.0.0.1", "test-ua")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	ctx := context.WithValue(req.Context(), contextKeySession, sess)
	ctx = context.WithValue(ctx, contextKeyRawID, rawID)
	ctx = context.WithValue(ctx, contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// Verify server-side invalidation
	_, err = sessSvc.GetSession(context.Background(), rawID)
	if err == nil {
		t.Fatal("expected session to be invalidated from database")
	}

	// Verify cookie clearing
	cookies := rec.Result().Cookies()
	var clearedCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.SessionCookieName {
			clearedCookie = c
			break
		}
	}
	if clearedCookie == nil {
		t.Fatalf("expected cookie %q in response", cfg.SessionCookieName)
	}
	if clearedCookie.MaxAge != -1 {
		t.Errorf("expected cookie MaxAge -1, got %d", clearedCookie.MaxAge)
	}
}

func TestSessionHandler_ListSessions(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	userID := uuid.New()
	sess1, rawID1, err := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "127.0.0.1", "device-1")
	if err != nil {
		t.Fatalf("failed to create sess1: %v", err)
	}
	sess2, _, err := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeBearer, "127.0.0.2", "device-2")
	if err != nil {
		t.Fatalf("failed to create sess2: %v", err)
	}

	// Create an expired session that should be excluded
	expiredSess := db.Session{
		ID:                uuid.New(),
		UserID:            userID,
		IDHash:            "expired_hash_12345678901234567890123456789012345678901234567890123456",
		SessionType:       db.SessionTypeCookie,
		LastActiveAt:      time.Now().UTC().Add(-2 * time.Hour),
		AbsoluteExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		CreatedAt:         time.Now().UTC().Add(-3 * time.Hour),
	}
	_ = database.Create(&expiredSess).Error

	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	ctx := context.WithValue(req.Context(), contextKeySession, sess1)
	ctx = context.WithValue(ctx, contextKeyRawID, rawID1)
	ctx = context.WithValue(ctx, contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ListSessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var res struct {
		Sessions []struct {
			SessionID   string `json:"session_id"`
			SessionType string `json:"session_type"`
			IsCurrent   bool   `json:"is_current"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if len(res.Sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(res.Sessions))
	}

	var foundCurrent, foundOther bool
	for _, s := range res.Sessions {
		switch s.SessionID {
		case sess1.IDHash:
			if !s.IsCurrent {
				t.Errorf("expected sess1 to have is_current=true")
			}
			foundCurrent = true
		case sess2.IDHash:
			if s.IsCurrent {
				t.Errorf("expected sess2 to have is_current=false")
			}
			foundOther = true
		}
	}

	if !foundCurrent || !foundOther {
		t.Errorf("expected to find both sess1 and sess2 in output")
	}

	var expiredCount int64
	database.Model(&db.Session{}).Where("id = ?", expiredSess.ID).Count(&expiredCount)
	if expiredCount != 0 {
		t.Errorf("expected expired session to be purged from database, found %d", expiredCount)
	}
}

func TestSessionHandler_ListSessions_MissingContext(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	rec := httptest.NewRecorder()
	h.ListSessions(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on ListSessions without user context, got %d", rec.Code)
	}
}

func TestSessionHandler_InvalidateAllSessions(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	userID := uuid.New()
	_, rawID1, _ := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "127.0.0.1", "device-1")
	_, rawID2, _ := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeBearer, "127.0.0.2", "device-2")

	req := httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.InvalidateAllSessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// Verify both sessions invalidated
	if _, err := sessSvc.GetSession(context.Background(), rawID1); err == nil {
		t.Errorf("expected rawID1 to be invalidated")
	}
	if _, err := sessSvc.GetSession(context.Background(), rawID2); err == nil {
		t.Errorf("expected rawID2 to be invalidated")
	}
}

func TestSessionHandler_InvalidateAllSessions_MissingContext(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	req := httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
	rec := httptest.NewRecorder()
	h.InvalidateAllSessions(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on InvalidateAllSessions without user context, got %d", rec.Code)
	}
}

func TestSessionHandler_NewSessionHandler_NilConfigDefaults(t *testing.T) {
	database := setupSessionTestDB(t)
	sessSvc := session.NewService(database, nil)
	h := NewSessionHandler(sessSvc, database, nil)

	if h.cfg == nil {
		t.Fatalf("expected default config to be set when cfg is nil")
	}
	if h.cfg.SessionIdleTimeout == 0 {
		t.Errorf("expected positive SessionIdleTimeout from default config")
	}
}

func TestSessionHandler_RotateSession(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	userID := uuid.New()
	sess, rawID, err := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "127.0.0.1", "device-1")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/session/rotate", nil)
	ctx := context.WithValue(req.Context(), contextKeySession, sess)
	ctx = context.WithValue(ctx, contextKeyRawID, rawID)
	ctx = context.WithValue(ctx, contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.RotateSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// Old session must be invalid
	if _, err := sessSvc.GetSession(context.Background(), rawID); err == nil {
		t.Fatalf("expected old session to be invalidated after rotation")
	}

	// Cookie must be set with new session ID
	cookies := rec.Result().Cookies()
	var newCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.SessionCookieName {
			newCookie = c
			break
		}
	}
	if newCookie == nil {
		t.Fatalf("expected new session cookie in response")
	}
	if newCookie.Value == rawID {
		t.Errorf("expected cookie value to differ from old rawID")
	}

	// Verify new session is valid
	if _, err := sessSvc.GetSession(context.Background(), newCookie.Value); err != nil {
		t.Fatalf("expected new session from cookie to be valid: %v", err)
	}
}

func TestSessionHandler_RotateSession_CookieNoTokenLeakOnHeaderOrQuery(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	userID := uuid.New()
	sess, rawID, err := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeCookie, "127.0.0.1", "device-cookie")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Attacker tries to coerce raw token exposure via ?type=bearer and X-Auth-Type: bearer
	req := httptest.NewRequest(http.MethodPost, "/auth/session/rotate?type=bearer", nil)
	req.Header.Set("X-Auth-Type", "bearer")
	ctx := context.WithValue(req.Context(), contextKeySession, sess)
	ctx = context.WithValue(ctx, contextKeyRawID, rawID)
	ctx = context.WithValue(ctx, contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.RotateSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var respBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("failed to decode json body: %v", err)
	}

	// Must NOT contain "token"
	if _, hasToken := respBody["token"]; hasToken {
		t.Fatalf("security violation: raw session token was leaked in JSON response body for cookie session: %v", respBody)
	}

	if respBody["message"] != "Session rotated successfully" {
		t.Errorf("expected 'Session rotated successfully', got %v", respBody["message"])
	}

	// Must set HttpOnly cookie
	cookies := rec.Result().Cookies()
	var newCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.SessionCookieName {
			newCookie = c
			break
		}
	}
	if newCookie == nil {
		t.Fatalf("expected new session cookie to be set")
	}
}

func TestSessionHandler_RotateSession_BearerReturnsToken(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := testSessionConfig()
	sessSvc := session.NewService(database, cfg)
	h := NewSessionHandler(sessSvc, database, cfg)

	userID := uuid.New()
	sess, rawID, err := sessSvc.CreateSession(context.Background(), userID, db.SessionTypeBearer, "127.0.0.1", "device-bearer")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/session/rotate", nil)
	ctx := context.WithValue(req.Context(), contextKeySession, sess)
	ctx = context.WithValue(ctx, contextKeyRawID, rawID)
	ctx = context.WithValue(ctx, contextKeyUserID, userID)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.RotateSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var respBody struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("failed to decode json body: %v", err)
	}

	if respBody.Token == "" {
		t.Fatalf("expected bearer rotation to return new raw token in JSON body")
	}
	if respBody.Token == rawID {
		t.Fatalf("expected new token to differ from old raw token")
	}
}

func TestRotateSession_NilSessionService_ReturnsInternalError(t *testing.T) {
	h := NewSessionHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/auth/session/rotate", nil)
	ctx := context.WithValue(req.Context(), contextKeyRawID, "0123456789abcdef0123456789abcdef")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.RotateSession(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error on nil sessionSvc, got %d", rec.Code)
	}
}

func TestSessionHandler_ListSessions_NilSessionService_ReturnsInternalError(t *testing.T) {
	h := NewSessionHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	ctx := context.WithValue(req.Context(), contextKeyUserID, uuid.New())
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ListSessions(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error on nil sessionSvc, got %d", rec.Code)
	}
}
