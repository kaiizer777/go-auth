package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

func setupIntegrationApp(t *testing.T, modifyCfg ...func(*config.Config)) (*goauth.Auth, *gorm.DB, config.Config) {
	t.Helper()

	dbName := fmt.Sprintf("file:integ_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS verification_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		provider_id VARCHAR(32) NOT NULL,
		provider_tenant_id VARCHAR(64) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		access_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_fingerprint CHAR(64) NOT NULL DEFAULT '',
		token_expires_at DATETIME,
		token_scope TEXT NOT NULL DEFAULT '',
		created_at DATETIME,
		updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_tenant_uid UNIQUE (provider_id, provider_tenant_id, provider_user_id)
	);
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
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"
	cfg.DisableAsyncEmailDispatch = true
	cfg.SessionIdleTimeout = 30 * time.Minute
	cfg.SessionAbsoluteMaxAge = 24 * time.Hour
	cfg.SessionCookieSecure = false // dev mode for tests
	for _, fn := range modifyCfg {
		fn(&cfg)
	}

	app, err := goauth.NewWithDB(database, cfg)
	if err != nil {
		t.Fatalf("goauth.NewWithDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = app.Close()
	})

	return app, database, cfg
}

func signupUser(t *testing.T, app *goauth.Auth, email, pass string) uuid.UUID {
	t.Helper()
	u, _, err := app.Auth.Signup(context.Background(), db.SignupRequest{
		Email:    email,
		Password: pass,
	})
	if err != nil {
		t.Fatalf("signupUser failed: %v", err)
	}
	return u.ID
}

func readCookieFromResponse(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Test 1: TestLoginCookieFlow (ASVS V3.2, V3.4)
// POST /auth/login sets sid cookie -> GET /auth/session with cookie returns 200 with 64-char hash -> DELETE invalidates session
func TestLoginCookieFlow(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t)
	email := "cookie_flow@example.com"
	pass := "SecurePassword123!"
	signupUser(t, app, email, pass)

	// 1. Login with cookie
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	loginPair, loginToken := fetchCSRFPair(t, app.Handler)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req.AddCookie(loginPair)
	req.Header.Set(cfg.CSRFHeaderName, loginToken)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login, got %d: %s", rec.Code, rec.Body.String())
	}

	var sidCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.SessionCookieName {
			sidCookie = c
			break
		}
	}
	if sidCookie == nil {
		t.Fatalf("expected session cookie %q in login response", cfg.SessionCookieName)
	}
	if len(sidCookie.Value) != 32 {
		t.Fatalf("expected 32-character raw session ID in cookie, got %q", sidCookie.Value)
	}

	// 2. GET /auth/session with cookie
	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq.AddCookie(sidCookie)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET /auth/session, got %d: %s", getRec.Code, getRec.Body.String())
	}

	var sessResp struct {
		Session struct {
			SessionID   string `json:"session_id"`
			SessionType string `json:"session_type"`
		} `json:"session"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &sessResp); err != nil {
		t.Fatalf("failed to decode GET /auth/session response: %v", err)
	}

	if len(sessResp.Session.SessionID) != 64 {
		t.Fatalf("expected 64-char SHA-256 hex session_id, got %q", sessResp.Session.SessionID)
	}
	if sessResp.Session.SessionID == sidCookie.Value {
		t.Fatalf("expected session_id to NOT match raw session ID cookie")
	}

	// Retrieve CSRF token set by GET
	var csrfCookie *http.Cookie
	for _, c := range getRec.Result().Cookies() {
		if c.Name == cfg.CSRFCookieName {
			csrfCookie = c
			break
		}
	}

	// 3. DELETE /auth/session
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.AddCookie(sidCookie)
	if csrfCookie != nil {
		delReq.AddCookie(csrfCookie)
		delReq.Header.Set(cfg.CSRFHeaderName, csrfCookie.Value)
	}
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DELETE /auth/session, got %d: %s", delRec.Code, delRec.Body.String())
	}

	// 4. Subsequent GET /auth/session returns 401
	getReq2 := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq2.AddCookie(sidCookie)
	getRec2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec2, getReq2)

	if getRec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after logout, got %d", getRec2.Code)
	}
}

// Test 2: TestLoginBearerFlow (ASVS V3.2)
// POST /auth/login with X-Auth-Type: bearer returns raw token in body; Bearer auth GET returns 200; DELETE invalidates token
func TestLoginBearerFlow(t *testing.T) {
	app, _, _ := setupIntegrationApp(t)
	email := "bearer_flow@example.com"
	pass := "SecurePassword123!"
	signupUser(t, app, email, pass)

	// 1. Login with Bearer
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("X-Auth-Type", "bearer")
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var bearerResp struct {
		UserID uuid.UUID `json:"user_id"`
		Token  string    `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bearerResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if bearerResp.UserID == uuid.Nil {
		t.Errorf("expected non-nil user_id in bearer login response")
	}
	if len(bearerResp.Token) != 32 {
		t.Fatalf("expected 32-char token, got %q", bearerResp.Token)
	}

	// 2. GET /auth/session with Bearer token
	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq.Header.Set("Authorization", "Bearer "+bearerResp.Token)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET /auth/session, got %d: %s", getRec.Code, getRec.Body.String())
	}

	// 3. DELETE /auth/session with Bearer (skips CSRF)
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.Header.Set("Authorization", "Bearer "+bearerResp.Token)
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DELETE, got %d: %s", delRec.Code, delRec.Body.String())
	}

	// 4. Replay token returns 401
	getReq2 := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq2.Header.Set("Authorization", "Bearer "+bearerResp.Token)
	getRec2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec2, getReq2)

	if getRec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on reused token, got %d", getRec2.Code)
	}
}

// Test 3: TestSessionFixationPrevention (ASVS V3.2.1)
// Pre-login session ID is discarded; fresh session ID generated on every login
func TestSessionFixationPrevention(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t)
	email := "fixation@example.com"
	pass := "SecurePassword123!"
	signupUser(t, app, email, pass)

	// First login
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	csrfCookie, csrfToken := fetchCSRFPair(t, app.Handler)
	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req1.AddCookie(csrfCookie)
	req1.Header.Set(cfg.CSRFHeaderName, csrfToken)
	rec1 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec1, req1)
	cookie1 := readCookieFromResponse(rec1.Result(), cfg.SessionCookieName)
	if cookie1 == nil {
		t.Fatalf("failed to read cookie 1")
	}

	// Second login with existing cookie passed in header
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req2.AddCookie(cookie1)
	req2.AddCookie(csrfCookie)
	req2.Header.Set(cfg.CSRFHeaderName, csrfToken)
	rec2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec2, req2)
	cookie2 := readCookieFromResponse(rec2.Result(), cfg.SessionCookieName)
	if cookie2 == nil {
		t.Fatalf("failed to read cookie 2")
	}

	if cookie1.Value == cookie2.Value {
		t.Fatalf("session fixation vulnerability: server reused session ID across logins (%q)", cookie1.Value)
	}
}

// Test 4: TestAllSessionsInvalidatedOnPasswordChange (ASVS V3.3.1)
// Password reset purges all active session rows for the target user
func TestAllSessionsInvalidatedOnPasswordChange(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t)
	email := "pw_change_purge@example.com"
	pass := "OriginalPass123!"
	newPass := "NewPass9876543!"
	signupUser(t, app, email, pass)

	// Device 1 login
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	csrfCookie, csrfToken := fetchCSRFPair(t, app.Handler)
	loginReq1 := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	loginReq1.AddCookie(csrfCookie)
	loginReq1.Header.Set(cfg.CSRFHeaderName, csrfToken)
	rec1 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec1, loginReq1)
	cookie1 := readCookieFromResponse(rec1.Result(), cfg.SessionCookieName)

	// Device 2 login
	loginReq2 := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	loginReq2.AddCookie(csrfCookie)
	loginReq2.Header.Set(cfg.CSRFHeaderName, csrfToken)
	rec2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec2, loginReq2)
	cookie2 := readCookieFromResponse(rec2.Result(), cfg.SessionCookieName)

	// Verify both sessions work
	reqCheck1 := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	reqCheck1.AddCookie(cookie1)
	recCheck1 := httptest.NewRecorder()
	app.Handler.ServeHTTP(recCheck1, reqCheck1)
	if recCheck1.Code != http.StatusOK {
		t.Fatalf("session 1 check failed: %d", recCheck1.Code)
	}

	// Initiate password reset
	tok, err := app.Auth.RequestPasswordReset(context.Background(), db.PasswordResetRequest{Email: email})
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}

	// Complete password reset
	_, err = app.Auth.ResetPassword(context.Background(), db.PasswordResetConfirmRequest{
		Token:       tok,
		NewPassword: newPass,
	})
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// Verify session 1 is invalidated
	recAfter1 := httptest.NewRecorder()
	app.Handler.ServeHTTP(recAfter1, reqCheck1)
	if recAfter1.Code != http.StatusUnauthorized {
		t.Fatalf("expected session 1 to return 401 after password reset, got %d", recAfter1.Code)
	}

	// Verify session 2 is invalidated
	reqCheck2 := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	reqCheck2.AddCookie(cookie2)
	recAfter2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(recAfter2, reqCheck2)
	if recAfter2.Code != http.StatusUnauthorized {
		t.Fatalf("expected session 2 to return 401 after password reset, got %d", recAfter2.Code)
	}
}

// Test: login whose credential check precedes a password reset must not mint a
// usable session when it resumes after the reset (issue #27). Sequentially
// simulates the login-vs-reset window: mint-time validation rejects the stale
// version and persists nothing.
func TestSessionRejectedWhenLoginCapturedOldCredentialVersion(t *testing.T) {
	app, database, _ := setupIntegrationApp(t)
	email := "login_vs_reset@example.com"
	pass := "OriginalPass123!"
	newPass := "NewPass9876543!"
	signupUser(t, app, email, pass)

	// Credential check happens before the reset: capture old version.
	user, err := app.Auth.Login(context.Background(), db.LoginRequest{Email: email, Password: pass})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	oldVersion := user.CredentialVersion

	// Reset completes in between, bumping credential version and purging sessions.
	tok, err := app.Auth.RequestPasswordReset(context.Background(), db.PasswordResetRequest{Email: email})
	if err != nil {
		t.Fatalf("RequestPasswordReset failed: %v", err)
	}
	if _, err := app.Auth.ResetPassword(context.Background(), db.PasswordResetConfirmRequest{
		Token:       tok,
		NewPassword: newPass,
	}); err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// In-flight login resumes and attempts to mint a session stamped with the
	// old version: mint-time validation rejects it and persists nothing.
	_, _, err = app.Session.CreateSession(context.Background(), user.ID, oldVersion, db.SessionTypeCookie, "127.0.0.1", "agent")
	if !stderrors.Is(err, apperrors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid on stale mint, got %v", err)
	}

	var count int64
	if err := database.Model(&db.Session{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("failed to count sessions: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no session persisted on stale mint, found %d", count)
	}

	// Positive control: mint with the fresh post-reset version succeeds.
	freshUser, err := app.Auth.Login(context.Background(), db.LoginRequest{Email: email, Password: newPass})
	if err != nil {
		t.Fatalf("fresh Login failed: %v", err)
	}
	if _, _, err := app.Session.CreateSession(context.Background(), user.ID, freshUser.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "agent"); err != nil {
		t.Fatalf("fresh mint with current version failed: %v", err)
	}
}

// Test 5: TestListSessions_MultipleDevices (ASVS V3.2.2)
// Listing returns all active sessions; is_current is true only for requesting session; session IDs are SHA-256 hashes
func TestListSessions_MultipleDevices(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t)
	email := "multi_device@example.com"
	pass := "Pass123456789!"
	signupUser(t, app, email, pass)

	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})

	pair, pairToken := fetchCSRFPair(t, app.Handler)
	newLoginReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
		r.AddCookie(pair)
		r.Header.Set(cfg.CSRFHeaderName, pairToken)
		return r
	}

	// Login device 1
	rec1 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec1, newLoginReq())
	c1 := readCookieFromResponse(rec1.Result(), cfg.SessionCookieName)

	// Login device 2
	rec2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec2, newLoginReq())
	_ = rec2

	// List sessions from device 1
	listReq := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	listReq.AddCookie(c1)
	listRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /auth/sessions, got %d: %s", listRec.Code, listRec.Body.String())
	}

	var res struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
			IsCurrent bool   `json:"is_current"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode /auth/sessions response: %v", err)
	}

	if len(res.Sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(res.Sessions))
	}

	currentCount := 0
	for _, s := range res.Sessions {
		if len(s.SessionID) != 64 {
			t.Errorf("expected 64-char hex hash session_id, got %q", s.SessionID)
		}
		if s.IsCurrent {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Fatalf("expected exactly 1 session to have is_current=true, got %d", currentCount)
	}
}

// Test 6: TestIdleTimeoutEnforced_Integration (ASVS V3.3.2)
// Inactivity past SessionIdleTimeout triggers 401 SESSION_EXPIRED and deletes session row
func TestIdleTimeoutEnforced_Integration(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t, func(c *config.Config) {
		c.SessionIdleTimeout = 80 * time.Millisecond
		c.SessionAbsoluteMaxAge = 10 * time.Second
	})

	email := "idle_timeout@example.com"
	pass := "Pass123456789!"
	signupUser(t, app, email, pass)

	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	pair, pairToken := fetchCSRFPair(t, app.Handler)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	loginReq.AddCookie(pair)
	loginReq.Header.Set(cfg.CSRFHeaderName, pairToken)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, loginReq)
	c := readCookieFromResponse(rec.Result(), cfg.SessionCookieName)

	// Wait past idle timeout
	time.Sleep(120 * time.Millisecond)

	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq.AddCookie(c)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after idle timeout, got %d", getRec.Code)
	}
}

// Test 7: TestAbsoluteTimeoutEnforced_Integration (ASVS V3.3.3)
// Elapsed time past SessionAbsoluteMaxAge triggers 401 SESSION_EXPIRED even if kept active
func TestAbsoluteTimeoutEnforced_Integration(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t, func(c *config.Config) {
		c.SessionIdleTimeout = 150 * time.Millisecond
		c.SessionAbsoluteMaxAge = 250 * time.Millisecond
	})

	email := "abs_timeout@example.com"
	pass := "Pass123456789!"
	signupUser(t, app, email, pass)

	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	pair, pairToken := fetchCSRFPair(t, app.Handler)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	loginReq.AddCookie(pair)
	loginReq.Header.Set(cfg.CSRFHeaderName, pairToken)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, loginReq)
	c := readCookieFromResponse(rec.Result(), cfg.SessionCookieName)

	// Keep session active before idle timeout expires (first keep-alive at 60ms)
	time.Sleep(60 * time.Millisecond)
	keepAliveReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	keepAliveReq.AddCookie(c)
	keepAliveRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(keepAliveRec, keepAliveReq)
	if keepAliveRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on first keep-alive request, got %d", keepAliveRec.Code)
	}

	// Second keep-alive at 120ms to ensure idle timeout (150ms) never elapses before absolute timeout (250ms)
	time.Sleep(60 * time.Millisecond)
	keepAliveReq2 := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	keepAliveReq2.AddCookie(c)
	keepAliveRec2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(keepAliveRec2, keepAliveReq2)
	if keepAliveRec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on second keep-alive request, got %d", keepAliveRec2.Code)
	}

	// Wait until absolute timeout elapses (total elapsed: ~260ms > 250ms, but only 140ms since last keep-alive < 150ms idle)
	time.Sleep(140 * time.Millisecond)

	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq.AddCookie(c)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized after absolute timeout, got %d", getRec.Code)
	}
}

// TestLogin_SetsCSRFCookieAndEnablesImmediateRotation verifies that login attaches a CSRF cookie,
// and state-changing endpoints can be accessed immediately with that token without an initial GET request.
func TestLogin_SetsCSRFCookieAndEnablesImmediateRotation(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t)
	email := "login_csrf_test@example.com"
	pass := "SecurePassword123!"
	signupUser(t, app, email, pass)

	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	pair, pairToken := fetchCSRFPair(t, app.Handler)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req.AddCookie(pair)
	req.Header.Set(cfg.CSRFHeaderName, pairToken)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on login, got %d: %s", rec.Code, rec.Body.String())
	}

	var sidCookie, csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case cfg.SessionCookieName:
			sidCookie = c
		case cfg.CSRFCookieName:
			csrfCookie = c
		}
	}
	if sidCookie == nil {
		t.Fatalf("expected session cookie %q in login response", cfg.SessionCookieName)
	}
	if csrfCookie == nil {
		t.Fatalf("expected csrf cookie %q in login response", cfg.CSRFCookieName)
	}
	if len(csrfCookie.Value) != 64 {
		t.Fatalf("expected 64-char hex CSRF token, got %q", csrfCookie.Value)
	}

	// Immediately rotate session without prior GET request
	rotReq := httptest.NewRequest(http.MethodPost, "/auth/session/rotate", nil)
	rotReq.AddCookie(sidCookie)
	rotReq.AddCookie(csrfCookie)
	rotReq.Header.Set(cfg.CSRFHeaderName, csrfCookie.Value)
	rotRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rotRec, rotReq)

	if rotRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on rotate session with login CSRF cookie, got %d: %s", rotRec.Code, rotRec.Body.String())
	}
}

// TestCSRF_BootstrapOnUnauthenticatedSafeRequest verifies that GET /auth/session attaches a CSRF cookie
// even when unauthenticated (401 response).
func TestCSRF_BootstrapOnUnauthenticatedSafeRequest(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t)

	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on unauthenticated GET /auth/session, got %d", getRec.Code)
	}

	var csrfCookie *http.Cookie
	for _, c := range getRec.Result().Cookies() {
		if c.Name == cfg.CSRFCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatalf("expected CSRF cookie to be bootstrapped on unauthenticated GET /auth/session")
	}
	if len(csrfCookie.Value) != 64 {
		t.Fatalf("expected 64-char hex CSRF cookie, got %q", csrfCookie.Value)
	}
}
