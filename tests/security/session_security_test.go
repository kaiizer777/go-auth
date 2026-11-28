package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
)

func setupSecurityApp(t *testing.T, modifyCfg ...func(*config.Config)) (*goauth.Auth, *gorm.DB, config.Config) {
	t.Helper()

	dbName := fmt.Sprintf("file:sec_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
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
	CREATE TABLE IF NOT EXISTS claimed_emails (
		email VARCHAR(255) PRIMARY KEY,
		owner_user_id TEXT NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
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
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token_hash BLOB PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME
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
	cfg.SessionCookieSecure = true // secure by default for security testing
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

func signupSecurityUser(t *testing.T, app *goauth.Auth, email, pass string) uuid.UUID {
	t.Helper()
	u, _, err := app.Auth.Signup(context.Background(), db.SignupRequest{
		Email:    email,
		Password: pass,
	})
	if err != nil {
		t.Fatalf("signupSecurityUser failed: %v", err)
	}
	return u.ID
}

func readCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// csrfPairForLogin fetches a CSRF cookie+token pair for state-changing auth requests.
func csrfPairForLogin(t *testing.T, app *goauth.Auth) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/csrf", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/csrf: expected 200, got %d", rec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.CSRFToken) != 64 {
		t.Fatalf("bad csrf token response: %q err=%v", rec.Body.String(), err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Value == body.CSRFToken {
			return c, body.CSRFToken
		}
	}
	t.Fatal("no CSRF cookie matching JSON token")
	return nil, ""
}

// attachCSRF equips req with a valid CSRF cookie+header pair.
func attachCSRF(req *http.Request, cfg config.Config, cookie *http.Cookie, token string) {
	req.AddCookie(cookie)
	req.Header.Set(cfg.CSRFHeaderName, token)
}

// loginCookieSession performs a cookie-transport login with a valid CSRF pair.
func loginCookieSession(t *testing.T, app *goauth.Auth, cfg config.Config, email, pass string) *http.Cookie {
	t.Helper()
	csrfCookie, token := csrfPairForLogin(t, app)
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	attachCSRF(req, cfg, csrfCookie, token)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie login failed: %d: %s", rec.Code, rec.Body.String())
	}
	sid := readCookie(rec.Result(), cfg.SessionCookieName)
	if sid == nil {
		t.Fatal("no session cookie in login response")
	}
	return sid
}

// Test 8: TestReplayDeletedSession (ASVS V3.3.1)
// Replaying logged-out raw session ID returns 401 SESSION_INVALID (confirms server-side invalidation)
func TestReplayDeletedSession(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "replay_del@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	// Login with Bearer
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("X-Auth-Type", "bearer")
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)

	var bearerResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &bearerResp)

	// Logout
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.Header.Set("Authorization", "Bearer "+bearerResp.Token)
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", delRec.Code)
	}

	// Replay raw session ID
	replayReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	replayReq.Header.Set("Authorization", "Bearer "+bearerResp.Token)
	replayRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(replayRec, replayReq)

	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for replayed deleted session, got %d", replayRec.Code)
	}
	_ = cfg
}

// Test 9: TestCSRFBypassAttempt_CookieEndpoint (ASVS V3.4.1)
// State-changing request with cookie session missing X-CSRF-Token header returns 403 CSRF_TOKEN_MISSING
func TestCSRFBypassAttempt_CookieEndpoint(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "csrf_bypass@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	// Login with cookie (CSRF pair required on the login itself)
	sidCookie := loginCookieSession(t, app, cfg, email, pass)

	// Attempt state-changing DELETE /auth/session with session cookie but without CSRF token
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.AddCookie(sidCookie)
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when CSRF token is missing, got %d", delRec.Code)
	}
}

// Test 10: TestCSRFMismatch_CookieEndpoint (ASVS V3.4.1)
// Request with mismatched CSRF cookie and header returns 403 CSRF_TOKEN_INVALID
func TestCSRFMismatch_CookieEndpoint(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "csrf_mismatch@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	sidCookie := loginCookieSession(t, app, cfg, email, pass)

	tokenA := "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
	tokenB := "9999888877776666555544443333222211110000ffffeeeeddddccccbbbbaaaa"

	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.AddCookie(sidCookie)
	delReq.AddCookie(&http.Cookie{Name: cfg.CSRFCookieName, Value: tokenA})
	delReq.Header.Set(cfg.CSRFHeaderName, tokenB)
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for mismatched CSRF tokens, got %d", delRec.Code)
	}
}

// Test 11: TestCSRFBypassAttempt_BearerEndpoint (ASVS V3.4.1)
// Bearer-authenticated state-changing request skips CSRF validation and succeeds (Bearer inherently CSRF-immune)
func TestCSRFBypassAttempt_BearerEndpoint(t *testing.T) {
	app, _, _ := setupSecurityApp(t)
	email := "csrf_bearer@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	// Login with Bearer
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("X-Auth-Type", "bearer")
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)

	var bearerResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &bearerResp)

	// State-changing DELETE /auth/session with Bearer and NO CSRF header -> must succeed (200 OK)
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.Header.Set("Authorization", "Bearer "+bearerResp.Token)
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for Bearer request without CSRF header, got %d", delRec.Code)
	}
}

// Test 11b: TestCSRFBypassAttempt_BearerHeaderSpoofingWithCookie
// An attacker provides a valid victim session cookie and a spoofed/dummy Bearer header to bypass CSRF.
// RequireAuth must strictly validate the Bearer header and reject with 401, never falling back to cookie.
func TestCSRFBypassAttempt_BearerHeaderSpoofingWithCookie(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "csrf_spoof@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	// Login with cookie
	sidCookie := loginCookieSession(t, app, cfg, email, pass)

	// State-changing DELETE /auth/session with valid cookie but dummy/invalid Bearer header
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.AddCookie(sidCookie)
	delReq.Header.Set("Authorization", "Bearer dummy-spoofed-token")
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when Bearer header is spoofed, got %d", delRec.Code)
	}
}

// Test 12: TestRateLimitTrigger_Login (ASVS V3.2.4)
// Attempt MaxAttempts + 1 from same IP|email returns 429 RATE_LIMIT_EXCEEDED with Retry-After header
func TestRateLimitTrigger_Login(t *testing.T) {
	app, _, cfg := setupSecurityApp(t, func(c *config.Config) {
		c.RateLimitLoginMax = 3
		c.RateLimitLoginWindow = 15 * time.Minute
	})

	email := "ratelimit_trigger@example.com"
	reqBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: "badpassword"})
	csrfCookie, csrfToken := csrfPairForLogin(t, app)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(reqBody))
		req.RemoteAddr = "10.0.0.1:1234"
		attachCSRF(req, cfg, csrfCookie, csrfToken)
		rec := httptest.NewRecorder()
		app.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 Unauthorized, got %d", i+1, rec.Code)
		}
	}

	// 4th attempt exceeds limit
	req4 := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(reqBody))
	req4.RemoteAddr = "10.0.0.1:1234"
	attachCSRF(req4, cfg, csrfCookie, csrfToken)
	rec4 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec4.Code)
	}
	if rec4.Header().Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}
}

// Test 13: TestRateLimitReset_OnSuccess (ASVS V3.2.4)
// Successful login clears the rate limit bucket for IP|email
func TestRateLimitReset_OnSuccess(t *testing.T) {
	app, _, cfg := setupSecurityApp(t, func(c *config.Config) {
		c.RateLimitLoginMax = 2
		c.RateLimitLoginWindow = 15 * time.Minute
	})

	email := "ratelimit_reset@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)
	csrfCookie, csrfToken := csrfPairForLogin(t, app)

	// 1 failed attempt
	badBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: "wrong"})
	reqBad := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(badBody))
	reqBad.RemoteAddr = "10.0.0.2:1234"
	attachCSRF(reqBad, cfg, csrfCookie, csrfToken)
	recBad := httptest.NewRecorder()
	app.Handler.ServeHTTP(recBad, reqBad)

	// Successful login resets bucket
	goodBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	reqGood := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(goodBody))
	reqGood.RemoteAddr = "10.0.0.2:1234"
	attachCSRF(reqGood, cfg, csrfCookie, csrfToken)
	recGood := httptest.NewRecorder()
	app.Handler.ServeHTTP(recGood, reqGood)

	if recGood.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on valid login, got %d", recGood.Code)
	}

	// Another attempt should be allowed immediately
	reqAnother := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(goodBody))
	reqAnother.RemoteAddr = "10.0.0.2:1234"
	attachCSRF(reqAnother, cfg, csrfCookie, csrfToken)
	recAnother := httptest.NewRecorder()
	app.Handler.ServeHTTP(recAnother, reqAnother)

	if recAnother.Code != http.StatusOK {
		t.Fatalf("expected 200 OK after bucket reset, got %d", recAnother.Code)
	}
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Test 14: TestSessionIDNotInLogs (ASVS V3.1.2)
// Custom slog.Handler / buffer asserts raw 32-char session ID and hashes never appear in log records
func TestSessionIDNotInLogs(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "log_leak_test@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	// Intercept default slog logger with a buffer
	lb := &logBuffer{}
	origLogger := slog.Default()
	testLogger := slog.New(slog.NewTextHandler(lb, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(testLogger)
	t.Cleanup(func() {
		slog.SetDefault(origLogger)
	})

	// Login
	sidCookie := loginCookieSession(t, app, cfg, email, pass)
	rawID := sidCookie.Value

	// GET session
	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq.AddCookie(sidCookie)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	var sessResp struct {
		Session struct {
			SessionID string `json:"session_id"`
		} `json:"session"`
	}
	_ = json.Unmarshal(getRec.Body.Bytes(), &sessResp)
	idHash := sessResp.Session.SessionID

	// Logout
	csrfCookie := readCookie(getRec.Result(), cfg.CSRFCookieName)
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.AddCookie(sidCookie)
	if csrfCookie != nil {
		delReq.AddCookie(csrfCookie)
		delReq.Header.Set(cfg.CSRFHeaderName, csrfCookie.Value)
	}
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)

	logs := lb.String()

	// Assert raw session ID is NEVER in logs
	if strings.Contains(logs, rawID) {
		t.Fatalf("security violation: raw session ID %q appeared in slog logs: %s", rawID, logs)
	}

	// Assert session hash is NEVER in logs
	if strings.Contains(logs, idHash) {
		t.Fatalf("security violation: session ID hash %q appeared in slog logs: %s", idHash, logs)
	}

	// Assert password is NEVER in logs
	if strings.Contains(logs, pass) {
		t.Fatalf("security violation: password %q appeared in slog logs", pass)
	}
}

// Test 15: TestSessionIDNotInURL (ASVS V3.1.2)
// Asserts raw session ID never appears in URL query parameters, paths, or Location headers
func TestSessionIDNotInURL(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "url_leak_test@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	csrfCookie, csrfToken := csrfPairForLogin(t, app)
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	attachCSRF(loginReq, cfg, csrfCookie, csrfToken)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, loginReq)
	sidCookie := readCookie(rec.Result(), cfg.SessionCookieName)
	if sidCookie == nil {
		t.Fatal("no session cookie in login response")
	}
	rawID := sidCookie.Value

	// Verify Location header on login response does not contain raw ID
	if loc := rec.Header().Get("Location"); strings.Contains(loc, rawID) {
		t.Fatalf("raw session ID found in login Location header: %s", loc)
	}

	// GET session
	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq.AddCookie(sidCookie)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	if loc := getRec.Header().Get("Location"); strings.Contains(loc, rawID) {
		t.Fatalf("raw session ID found in session Location header: %s", loc)
	}
}

// Test 16: TestGetSessionResponse_NoRawID (ASVS V3.1.2)
// Asserts GET /auth/session body does not contain raw 32-char ID; asserts session_id is 64-char SHA-256 hash
func TestGetSessionResponse_NoRawID(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "no_raw_id@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	sidCookie := loginCookieSession(t, app, cfg, email, pass)
	rawID := sidCookie.Value

	getReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq.AddCookie(sidCookie)
	getRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec, getReq)

	body := getRec.Body.String()
	if strings.Contains(body, rawID) {
		t.Fatalf("security violation: raw session ID %q found in GET /auth/session body: %s", rawID, body)
	}

	var res struct {
		Session struct {
			SessionID string `json:"session_id"`
		} `json:"session"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(res.Session.SessionID) != 64 {
		t.Fatalf("expected 64-char SHA-256 hex session_id, got %q", res.Session.SessionID)
	}
}

// Test 17: TestSessionCookieHttpOnly (ASVS V3.4.2)
// Set-Cookie header contains HttpOnly, SameSite=Lax, and Secure attributes
func TestSessionCookieHttpOnly(t *testing.T) {
	app, _, cfg := setupSecurityApp(t, func(c *config.Config) {
		c.SessionCookieSecure = true
		c.SessionCookieSameSite = http.SameSiteLaxMode
	})

	email := "cookie_flags@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	sidCookie := loginCookieSession(t, app, cfg, email, pass)
	if sidCookie == nil {
		t.Fatalf("expected session cookie %q to be set", cfg.SessionCookieName)
	}
	if !sidCookie.HttpOnly {
		t.Errorf("expected session cookie to have HttpOnly=true")
	}
	if !sidCookie.Secure {
		t.Errorf("expected session cookie to have Secure=true")
	}
	if sidCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", sidCookie.SameSite)
	}
}

// Test 18: TestBearerTokenEntropy (ASVS V3.1.1)
// 1,000 generated tokens are exactly 32 hex chars with zero duplicate collisions
func TestBearerTokenEntropy(t *testing.T) {
	app, database, _ := setupSecurityApp(t)
	const count = 1000
	seen := make(map[string]struct{}, count)

	entropyUserID := uuid.New()
	if err := database.Create(&db.User{ID: entropyUserID, Email: "entropy@example.com", PasswordHash: "hash", CredentialVersion: 0}).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	for i := 0; i < count; i++ {
		_, rawID, err := app.Session.CreateSession(context.Background(), entropyUserID, 0, db.SessionTypeBearer, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		if len(rawID) != 32 {
			t.Fatalf("expected token len 32, got %d: %q", len(rawID), rawID)
		}
		if _, exists := seen[rawID]; exists {
			t.Fatalf("collision detected on generated session token: %q", rawID)
		}
		seen[rawID] = struct{}{}
	}
}

// Test 19: TestRotateSession_OldIDRejected (ASVS V3.2.1)
// After rotation, old session ID returns 401 SESSION_INVALID while new session ID succeeds
func TestRotateSession_OldIDRejected(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "rotate_test@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	// Login with Bearer
	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("X-Auth-Type", "bearer")
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)

	var bearerResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &bearerResp)
	oldToken := bearerResp.Token

	// Rotate session
	rotReq := httptest.NewRequest(http.MethodPost, "/auth/session/rotate", nil)
	rotReq.Header.Set("Authorization", "Bearer "+oldToken)
	rotRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rotRec, rotReq)

	if rotRec.Code != http.StatusOK {
		t.Fatalf("rotation failed: %d: %s", rotRec.Code, rotRec.Body.String())
	}

	var rotResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rotRec.Body.Bytes(), &rotResp)
	newToken := rotResp.Token

	if newToken == oldToken {
		t.Fatalf("expected rotated token to differ from old token")
	}

	// Old token must return 401
	getOld := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getOld.Header.Set("Authorization", "Bearer "+oldToken)
	recOld := httptest.NewRecorder()
	app.Handler.ServeHTTP(recOld, getOld)
	if recOld.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for old session token, got %d", recOld.Code)
	}

	// New token must return 200
	getNew := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getNew.Header.Set("Authorization", "Bearer "+newToken)
	recNew := httptest.NewRecorder()
	app.Handler.ServeHTTP(recNew, getNew)
	if recNew.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for new session token, got %d", recNew.Code)
	}
	_ = cfg
}

// Test 20: TestConcurrentLogout (ASVS V3.3.1)
// Concurrent DELETE /auth/session calls with -race pass without race conditions and return idempotent 200 OK
func TestConcurrentLogout(t *testing.T) {
	app, _, _ := setupSecurityApp(t)
	email := "concurrent_logout@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	loginBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("X-Auth-Type", "bearer")
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)

	var bearerResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &bearerResp)
	token := bearerResp.Token

	const concurrency = 10
	var wg sync.WaitGroup
	wg.Add(concurrency)

	statusCodes := make([]int, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
			delReq.Header.Set("Authorization", "Bearer "+token)
			delRec := httptest.NewRecorder()
			app.Handler.ServeHTTP(delRec, delReq)
			statusCodes[idx] = delRec.Code
		}(i)
	}

	wg.Wait()

	// Every concurrent request must either succeed with 200 or return 401 (already invalidated)
	// Neither panics, and no race conditions occur
	has200 := false
	for _, code := range statusCodes {
		if code == http.StatusOK {
			has200 = true
		} else if code != http.StatusUnauthorized {
			t.Errorf("unexpected status code during concurrent logout: %d", code)
		}
	}
	if !has200 {
		t.Errorf("expected at least one 200 OK in concurrent logouts")
	}
}

// Test 21: TestTransportBinding_RejectionNormalized (ASVS V3.2)
// Cookie sessions rejected via Bearer, bearer sessions rejected via Cookie.
// Error envelope normalized to CodeSessionInvalid.
func TestTransportBinding_RejectionNormalized(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email := "transport_bind@example.com"
	pass := "Pass123456789!"
	signupSecurityUser(t, app, email, pass)

	// 1. Create cookie session
	cookie := loginCookieSession(t, app, cfg, email, pass)
	cookieVal := cookie.Value

	// Try using cookie token via Bearer header
	getReq1 := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq1.Header.Set("Authorization", "Bearer "+cookieVal)
	getRec1 := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec1, getReq1)
	if getRec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for cookie session delivered via Bearer, got %d", getRec1.Code)
	}
	var errResp1 struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(getRec1.Body.Bytes(), &errResp1); err != nil {
		t.Fatalf("failed to decode error response 1: %v", err)
	}
	if errResp1.Code != "SESSION_INVALID" {
		t.Fatalf("expected error code SESSION_INVALID, got %q", errResp1.Code)
	}

	// 2. Create bearer session
	bearerBody, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	reqBearer := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bearerBody))
	reqBearer.Header.Set("X-Auth-Type", "bearer")
	recBearer := httptest.NewRecorder()
	app.Handler.ServeHTTP(recBearer, reqBearer)
	if recBearer.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for bearer login, got %d: %s", recBearer.Code, recBearer.Body.String())
	}
	var bearerResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(recBearer.Body.Bytes(), &bearerResp); err != nil {
		t.Fatalf("failed to decode bearer login response: %v", err)
	}
	if bearerResp.Token == "" {
		t.Fatalf("expected non-empty bearer token in login response")
	}
	bearerVal := bearerResp.Token

	// Try using bearer token via Cookie
	getReq2 := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	getReq2.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: bearerVal})
	getRec2 := httptest.NewRecorder()
	app.Handler.ServeHTTP(getRec2, getReq2)
	if getRec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bearer session delivered via Cookie, got %d", getRec2.Code)
	}
	var errResp2 struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(getRec2.Body.Bytes(), &errResp2); err != nil {
		t.Fatalf("failed to decode error response 2: %v", err)
	}
	if errResp2.Code != "SESSION_INVALID" {
		t.Fatalf("expected error code SESSION_INVALID, got %q", errResp2.Code)
	}
}
