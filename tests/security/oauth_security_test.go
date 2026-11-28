package security_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

// secTokenKEK is a fixed valid keyring: kid "test-kid" plus the 32 bytes 0x00-0x1f.
const secTokenKEK = "test-kid:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// setupOAuthSecurityApp builds the full HTTP stack over an isolated sqlite DB.
func setupOAuthSecurityApp(t *testing.T, mocks map[string]*oauthmock.Mock, modifyCfg ...func(*config.Config)) (http.Handler, *gorm.DB, config.Config) {
	t.Helper()
	name := fmt.Sprintf("file:oauth_sec_%s?mode=memory&cache=shared", uuid.New().String())
	database, err := gorm.Open(sqlite.Open(name), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0, email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME, updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS claimed_emails (
		email VARCHAR(255) PRIMARY KEY,
		owner_user_id TEXT NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider_id VARCHAR(32) NOT NULL,
		provider_tenant_id VARCHAR(64) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		access_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_fingerprint CHAR(64) NOT NULL DEFAULT '',
		token_expires_at DATETIME,
		token_scope TEXT NOT NULL DEFAULT '',
		created_at DATETIME, updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_tenant_uid UNIQUE (provider_id, provider_tenant_id, provider_user_id)
	);
	CREATE TABLE IF NOT EXISTS verification_tokens (
		token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie', ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '', credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL, absolute_expires_at DATETIME NOT NULL, created_at DATETIME
	);`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("schema: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"
	cfg.DisableAsyncEmailDispatch = true
	cfg.SessionCookieSecure = true
	cfg.OAuth.StateSecret = "test-oauth-state-secret-32bytes!!"
	cfg.OAuth.TokenKEK = secTokenKEK
	for _, fn := range modifyCfg {
		fn(&cfg)
	}
	authSvc, err := auth.New(cfg, database, cfg.EmailHooks)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	for _, m := range mocks {
		t.Cleanup(m.Close)
	}
	providers := map[string]oauth.Provider{}
	for id, m := range mocks {
		providers[id] = m
	}
	sessionSvc := session.NewService(database, &cfg)
	oauthSvc := oauth.NewService(database, sessionSvc, providers, &cfg)
	h := handler.New(database, cfg, authSvc,
		handler.WithSessionService(sessionSvc),
		handler.WithOAuthService(oauthSvc, providers),
	)
	return h, database, cfg
}

func secInitiate(t *testing.T, h http.Handler, path string) (string, []*http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("initiate %s: status = %d; want 302 (%s)", path, rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if state := loc.Query().Get("state"); state != "" {
		return state, rec.Result().Cookies()
	}
	t.Fatalf("Location missing state: %q", rec.Header().Get("Location"))
	return "", nil
}

func secFindCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func secVerifier(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		t.Fatalf("state cookie not signed payload format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode state payload: %v", err)
	}
	var payload oauth.OAuthStatePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal state payload: %v", err)
	}
	return payload.CodeVerifier
}

func secErrCode(t *testing.T, rec *httptest.ResponseRecorder) apperrors.Code {
	t.Helper()
	var resp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return resp.Code
}

func secCounts(t *testing.T, database *gorm.DB) (users, links, sessions int64) {
	t.Helper()
	if err := database.Model(&db.User{}).Count(&users).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := database.Model(&db.OAuthAccount{}).Count(&links).Error; err != nil {
		t.Fatalf("count links: %v", err)
	}
	if err := database.Model(&db.Session{}).Count(&sessions).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return users, links, sessions
}

func TestOAuthSecurity_PrehijackUnverifiedRejectedVictimUntouched(t *testing.T) {
	m := oauthmock.New("google", "attacker-sub", "victim@example.com", false)
	h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"google": m})

	victim := db.User{ID: uuid.New(), Email: "victim@example.com", PasswordHash: "local-hash", EmailVerified: true}
	if err := database.Create(&victim).Error; err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	state, cookies := secInitiate(t, h, "/auth/oauth/google")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=evil&state="+state, nil)
	req.AddCookie(secFindCookie(cookies, cfg.OAuth.StateCookieName))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (%s)", rec.Code, rec.Body.String())
	}
	if code := secErrCode(t, rec); code != apperrors.CodeOAuthEmailUnverified {
		t.Fatalf("code = %s; want OAUTH_EMAIL_UNVERIFIED", code)
	}
	var after db.User
	if err := database.Where("id = ?", victim.ID).First(&after).Error; err != nil {
		t.Fatalf("victim missing: %v", err)
	}
	if after.Email != victim.Email || after.PasswordHash != victim.PasswordHash || !after.EmailVerified {
		t.Fatalf("victim mutated: %+v", after)
	}
	if users, links, sessions := secCounts(t, database); users != 1 || links != 0 || sessions != 0 {
		t.Fatalf("users=%d links=%d sessions=%d; want 1/0/0", users, links, sessions)
	}
}

func TestOAuthSecurity_LocalUnverifiedLinkConflict(t *testing.T) {
	m := oauthmock.New("google", "sub-7", "pending@example.com", true)
	h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"google": m})

	local := db.User{ID: uuid.New(), Email: "pending@example.com", PasswordHash: "hash", EmailVerified: false}
	if err := database.Create(&local).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	state, cookies := secInitiate(t, h, "/auth/oauth/google")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
	req.AddCookie(secFindCookie(cookies, cfg.OAuth.StateCookieName))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d; want 409 (%s)", rec.Code, rec.Body.String())
	}
	if code := secErrCode(t, rec); code != apperrors.CodeOAuthAccountLinkConflict {
		t.Fatalf("code = %s; want OAUTH_ACCOUNT_LINK_CONFLICT", code)
	}
	if users, links, _ := secCounts(t, database); users != 1 || links != 0 {
		t.Fatalf("users=%d links=%d; want 1/0", users, links)
	}
	var after db.User
	if err := database.Where("id = ?", local.ID).First(&after).Error; err != nil {
		t.Fatalf("local missing: %v", err)
	}
	if after.EmailVerified || after.PasswordHash != "hash" {
		t.Fatalf("local mutated: %+v", after)
	}
}

// argon2MemoryFloor is the smallest allocation one Argon2id derivation at the
// given memory cost can produce: Argon2 allocates one KiB block per unit, so the
// exact footprint is memoryKiB*1024 and the floor keeps only 10% headroom for the
// allocations the surrounding login path adds. TotalAlloc is monotonic, so a
// loaded runner can only push the measurement up, never below the floor, while a
// dummy hash run at half the configured memory lands near 0.5x and stays visible.
func argon2MemoryFloor(memoryKiB uint32) uint64 {
	return uint64(memoryKiB) * 1024 * 9 / 10
}

// allocDelta reports bytes allocated by fn, so a memory-hard derivation that
// did not run is visible without measuring elapsed time.
func allocDelta(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestOAuthSecurity_OAuthOnlyLoginDummyHashCost(t *testing.T) {
	m := oauthmock.New("google", "sub-timing", "timing@example.com", true)
	h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"google": m})

	state, cookies := secInitiate(t, h, "/auth/oauth/google")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
	req.AddCookie(secFindCookie(cookies, cfg.OAuth.StateCookieName))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("oauth setup flow: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var oauthUser db.User
	if err := database.Where("LOWER(email) = LOWER(?)", "timing@example.com").First(&oauthUser).Error; err != nil {
		t.Fatalf("oauth user: %v", err)
	}
	if oauthUser.PasswordHash != "" {
		t.Fatalf("oauth user hash = %q; want empty", oauthUser.PasswordHash)
	}

	signupViaService(t, database, cfg, "normal@example.com", "NormalPass123!")

	login := func(email, password string) (int, string, uint64) {
		csrfRec := httptest.NewRecorder()
		h.ServeHTTP(csrfRec, httptest.NewRequest(http.MethodGet, "/auth/csrf", nil))
		var tok struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.Unmarshal(csrfRec.Body.Bytes(), &tok); err != nil {
			t.Fatalf("csrf token: %v", err)
		}
		var jar *http.Cookie
		for _, c := range csrfRec.Result().Cookies() {
			if c.Value == tok.CSRFToken {
				jar = c
			}
		}
		body, _ := json.Marshal(db.LoginRequest{Email: email, Password: password})
		r := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(jar)
		r.Header.Set(cfg.CSRFHeaderName, tok.CSRFToken)
		var code int
		var respBody string
		alloc := allocDelta(func() {
			out := httptest.NewRecorder()
			h.ServeHTTP(out, r)
			code, respBody = out.Code, out.Body.String()
		})
		return code, respBody, alloc
	}

	oauthCode, oauthBody, oauthAlloc := login("timing@example.com", "WrongPass000!")
	normalCode, normalBody, normalAlloc := login("normal@example.com", "WrongPass000!")
	ghostCode, ghostBody, ghostAlloc := login("ghost@example.com", "WrongPass000!")

	for name, code := range map[string]int{"oauth-only": oauthCode, "normal": normalCode, "ghost": ghostCode} {
		if code != http.StatusUnauthorized {
			t.Fatalf("%s login: status = %d; want 401", name, code)
		}
	}
	if oauthBody != ghostBody || normalBody != ghostBody {
		t.Fatal("login bodies must be identical across oauth-only, normal, and missing users")
	}
	floor := argon2MemoryFloor(cfg.Argon2.Memory)
	for name, alloc := range map[string]uint64{"oauth-only": oauthAlloc, "normal": normalAlloc, "ghost": ghostAlloc} {
		if alloc < floor {
			t.Fatalf("%s login allocated %d bytes; want >= %d (Argon2id m=%d KiB did not run)", name, alloc, floor, cfg.Argon2.Memory)
		}
	}
}

func signupViaService(t *testing.T, database *gorm.DB, cfg config.Config, email, pass string) db.User {
	t.Helper()
	authSvc, err := auth.New(cfg, database, cfg.EmailHooks)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	user, _, err := authSvc.Signup(context.Background(), db.SignupRequest{Email: email, Password: pass})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if err := database.Model(&db.User{}).Where("id = ?", user.ID).Update("email_verified", true).Error; err != nil {
		t.Fatalf("verify: %v", err)
	}
	return *user
}

func TestOAuthSecurity_CanonicalPostFormPostNoCSRF(t *testing.T) {
	for _, path := range []string{"/auth/oauth/apple/callback", "/api/auth/oauth/apple/callback"} {
		t.Run(path, func(t *testing.T) {
			m := oauthmock.New("apple", "apple-canon-1", "canon@example.com", true)
			h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"apple": m})

			state, cookies := secInitiate(t, h, "/auth/oauth/apple")
			req := httptest.NewRequest(http.MethodPost, path,
				strings.NewReader(url.Values{"code": {"apple-code-1"}, "state": {state}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(secFindCookie(cookies, cfg.OAuth.StateCookieName))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusFound {
				t.Fatalf("POST callback: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
			}
			if sid := secFindCookie(rec.Result().Cookies(), cfg.SessionCookieName); sid == nil || sid.Value == "" {
				t.Fatal("no session cookie on POST success")
			}
			if users, links, sessions := secCounts(t, database); users != 1 || links != 1 || sessions != 1 {
				t.Fatalf("users=%d links=%d sessions=%d; want 1/1/1", users, links, sessions)
			}
		})
	}
}

func TestOAuthSecurity_StateRejected(t *testing.T) {
	t.Run("handler missing cookie, mismatch, empty, expired, provider mismatch", func(t *testing.T) {
		m := oauthmock.New("google", "sub-s", "state@example.com", true)
		h, _, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"google": m})

		state, cookies := secInitiate(t, h, "/auth/oauth/google")
		sc := secFindCookie(cookies, cfg.OAuth.StateCookieName)

		drive := func(name, provider, param string, cookie *http.Cookie) {
			t.Helper()
			q := "?code=c"
			if param != "" {
				q += "&state=" + param
			}
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+provider+"/callback"+q, nil)
			if cookie != nil {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || secErrCode(t, rec) != apperrors.CodeOAuthStateInvalid {
				t.Fatalf("%s: status = %d body %s; want 403 OAUTH_STATE_INVALID", name, rec.Code, rec.Body.String())
			}
		}
		drive("missing cookie", "google", state, nil)
		drive("mismatched state", "google", state+"-bad", sc)
		drive("empty state param", "google", "", sc)
		drive("provider mismatch", "github", state, sc)

		// Mint an already-expired cookie directly: sub-second TTLs fail
		// config validation, so the normal app stack (10m TTL) drives the
		// callback while expiry rides inside the signed payload.
		expCfg := cfg
		expCfg.OAuth.StateTTL = time.Millisecond
		w := httptest.NewRecorder()
		expiredState, err := oauth.SetStateCookie(w, &expCfg, "google", "verifier", "")
		if err != nil {
			t.Fatalf("mint expired state: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+expiredState, nil)
		req.AddCookie(secFindCookie(w.Result().Cookies(), expCfg.OAuth.StateCookieName))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || secErrCode(t, rec) != apperrors.CodeOAuthStateInvalid {
			t.Fatalf("expired state: status = %d body %s; want 403 OAUTH_STATE_INVALID", rec.Code, rec.Body.String())
		}
	})

	t.Run("service expired and empty state", func(t *testing.T) {
		database, cfg := secServiceDB(t)
		stub := oauthmock.New("google", "sub-x", "x@example.com", true)
		defer stub.Close()
		svc := oauth.NewService(database, session.NewService(database, &cfg),
			map[string]oauth.Provider{"google": stub}, &cfg)

		expiredCfg := cfg
		expiredCfg.OAuth.StateTTL = time.Millisecond
		w := httptest.NewRecorder()
		expiredState, err := oauth.SetStateCookie(w, &expiredCfg, "google", "verifier", "")
		if err != nil {
			t.Fatalf("mint expired state: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		cookie := secFindCookie(w.Result().Cookies(), expiredCfg.OAuth.StateCookieName)
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		_, _, _, err = svc.HandleCallback(req.Context(), rec, req, "google", "code-1", expiredState, db.SessionTypeCookie)
		secRequireCode(t, err, apperrors.CodeOAuthStateInvalid, http.StatusForbidden)

		w2 := httptest.NewRecorder()
		if _, err := oauth.SetStateCookie(w2, &cfg, "google", "verifier", ""); err != nil {
			t.Fatalf("mint fresh state: %v", err)
		}
		req2 := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback", nil)
		req2.AddCookie(secFindCookie(w2.Result().Cookies(), cfg.OAuth.StateCookieName))
		_, _, _, err = svc.HandleCallback(req2.Context(), httptest.NewRecorder(), req2, "google", "code-1", "", db.SessionTypeCookie)
		secRequireCode(t, err, apperrors.CodeOAuthStateInvalid, http.StatusForbidden)
	})
}

func secServiceDB(t *testing.T) (*gorm.DB, config.Config) {
	t.Helper()
	name := fmt.Sprintf("file:oauth_svc_%s?mode=memory&cache=shared", uuid.New().String())
	database, err := gorm.Open(sqlite.Open(name), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0, email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME, updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS claimed_emails (
		email VARCHAR(255) PRIMARY KEY,
		owner_user_id TEXT NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider_id VARCHAR(32) NOT NULL,
		provider_tenant_id VARCHAR(64) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		access_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_fingerprint CHAR(64) NOT NULL DEFAULT '',
		token_expires_at DATETIME,
		token_scope TEXT NOT NULL DEFAULT '',
		created_at DATETIME, updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_tenant_uid UNIQUE (provider_id, provider_tenant_id, provider_user_id)
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie', ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '', credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL, absolute_expires_at DATETIME NOT NULL, created_at DATETIME
	);`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("schema: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.SessionCookieSecure = false
	cfg.OAuth.StateSecret = "test-oauth-state-secret-32bytes!!"
	cfg.OAuth.TokenKEK = secTokenKEK
	return database, cfg
}

func secRequireCode(t *testing.T, err error, want apperrors.Code, status int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s; got nil", want)
	}
	var appErr *apperrors.Error
	if !apperrors.As(err, &appErr) {
		t.Fatalf("error type = %T; want *errors.Error", err)
	}
	if appErr.Code() != want {
		t.Fatalf("code = %q; want %q", appErr.Code(), want)
	}
	if appErr.HTTPStatus() != status {
		t.Fatalf("status = %d; want %d", appErr.HTTPStatus(), status)
	}
}

func TestOAuthSecurity_TamperedVerifier502(t *testing.T) {
	m := oauthmock.New("google", "sub-t", "tamper@example.com", true)
	m.CorruptVerifier = true
	h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"google": m})

	state, cookies := secInitiate(t, h, "/auth/oauth/google")
	sc := secFindCookie(cookies, cfg.OAuth.StateCookieName)
	// No SetRequireVerifier: the mock binds S256(verifier) to the challenge
	// observed at authorize time, so the tampered verifier must fail by
	// default exactly like a real provider.
	original := secVerifier(t, sc)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d; want 502 (%s)", rec.Code, rec.Body.String())
	}
	if code := secErrCode(t, rec); code != apperrors.CodeOAuthProviderError {
		t.Fatalf("code = %s; want OAUTH_PROVIDER_ERROR", code)
	}
	if got, _ := m.ObservedVerifier(); got == original {
		t.Fatal("provider should have observed the tampered verifier, not the original")
	}
	if users, links, sessions := secCounts(t, database); users != 0 || links != 0 || sessions != 0 {
		t.Fatalf("users=%d links=%d sessions=%d; want 0/0/0", users, links, sessions)
	}
}

func TestOAuthSecurity_ReplayFails(t *testing.T) {
	m := oauthmock.New("google", "sub-r", "replay@example.com", true)
	m.SingleUseCodes = true
	h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"google": m})

	state, cookies := secInitiate(t, h, "/auth/oauth/google")
	sc := secFindCookie(cookies, cfg.OAuth.StateCookieName)
	makeReq := func() (*httptest.ResponseRecorder, *http.Request) {
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=replay-code&state="+state, nil)
		req.AddCookie(sc)
		return httptest.NewRecorder(), req
	}
	rec, req := makeReq()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("first callback: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
	}

	// Same state and cookie presented twice: the server-side consumed-state
	// record rejects the replay before any provider call.
	rec2, req2 := makeReq()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("replayed state reuse: status = %d; want 403 (%s)", rec2.Code, rec2.Body.String())
	}
	if code := secErrCode(t, rec2); code != apperrors.CodeOAuthStateInvalid {
		t.Fatalf("replay code = %s; want OAUTH_STATE_INVALID", code)
	}

	// Same provider code under a fresh state reaches the provider, which
	// rejects the second use of the code itself.
	state2, cookies2 := secInitiate(t, h, "/auth/oauth/google")
	sc2 := secFindCookie(cookies2, cfg.OAuth.StateCookieName)
	req2b := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=replay-code&state="+state2, nil)
	req2b.AddCookie(sc2)
	rec2b := httptest.NewRecorder()
	h.ServeHTTP(rec2b, req2b)
	if rec2b.Code != http.StatusBadGateway {
		t.Fatalf("replayed code reuse: status = %d; want 502 (%s)", rec2b.Code, rec2b.Body.String())
	}
	if code := secErrCode(t, rec2b); code != apperrors.CodeOAuthProviderError {
		t.Fatalf("replay code = %s; want OAUTH_PROVIDER_ERROR", code)
	}

	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=replay-code&state="+state, nil))
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("cookie-less replay: status = %d; want 403", rec3.Code)
	}
	if users, links, sessions := secCounts(t, database); users != 1 || links != 1 || sessions != 1 {
		t.Fatalf("users=%d links=%d sessions=%d; want 1/1/1", users, links, sessions)
	}
}

func TestOAuthSecurity_ZeroSecretLeakInLogs(t *testing.T) {
	sink := &secLogSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(sink, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	m := oauthmock.New("apple", "apple-leak-1", "leak@example.com", true)
	h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"apple": m})

	state, cookies := secInitiate(t, h, "/auth/oauth/apple")
	sc := secFindCookie(cookies, cfg.OAuth.StateCookieName)
	verifier := secVerifier(t, sc)

	req := httptest.NewRequest(http.MethodPost, "/auth/oauth/apple/callback",
		strings.NewReader(url.Values{"code": {"leak-code"}, "state": {state}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: status = %d (%s)", rec.Code, rec.Body.String())
	}
	sid := secFindCookie(rec.Result().Cookies(), cfg.SessionCookieName)
	if sid == nil {
		t.Fatal("no session cookie")
	}

	logs := sink.String()
	_, encodedKey, ok := strings.Cut(secTokenKEK, ":")
	if !ok {
		t.Fatal("test keyring spec is missing its separator")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	// Negative controls: slog escapes control bytes and base64-encodes []byte,
	// so a raw substring search can never see either form. Both arms must find a
	// secret that the handler really did render, or the leak assertions are dead.
	var escapedProbe, base64Probe bytes.Buffer
	probe := slog.New(slog.NewJSONHandler(&escapedProbe, nil))
	probe.Info("escaped probe", "key", string(keyBytes))
	probe = slog.New(slog.NewJSONHandler(&base64Probe, nil))
	probe.Info("base64 probe", "key", keyBytes)
	if !secLogLeaks(escapedProbe.String(), string(keyBytes)) {
		t.Fatal("leak detector misses a JSON-escaped key")
	}
	if !secLogLeaks(base64Probe.String(), string(keyBytes)) {
		t.Fatal("leak detector misses a base64-encoded key")
	}
	var stored db.OAuthAccount
	if err := database.Where("provider_id = ?", "apple").First(&stored).Error; err != nil {
		t.Fatalf("load linked apple account: %v", err)
	}
	if stored.AccessTokenCiphertext == "" || stored.RefreshTokenCiphertext == "" {
		t.Fatal("linked account must store both sealed token columns")
	}
	if secLogLeaks(logs, encodedKey) {
		t.Errorf("log leaked the token key in base64")
	}
	for name, secret := range map[string]string{
		"access token":       m.AccessToken,
		"refresh token":      m.RefreshToken,
		"id token":           m.IDToken,
		"client secret":      m.ClientSecret,
		"code verifier":      verifier,
		"raw session":        sid.Value,
		"token key":          string(keyBytes),
		"access ciphertext":  stored.AccessTokenCiphertext,
		"refresh ciphertext": stored.RefreshTokenCiphertext,
	} {
		if secret != "" && secLogLeaks(logs, secret) {
			t.Errorf("log leaked %s", name)
		}
	}
	for _, hdr := range []string{"Authorization", "Cookie", "Set-Cookie"} {
		if strings.Contains(logs, hdr) {
			t.Errorf("log leaked sensitive header %q", hdr)
		}
	}
	found := false
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `"msg":"oauth_callback_success"`) {
			found = true
			if !strings.Contains(line, `"session_id_hash":`) {
				t.Error("oauth_callback_success missing session_id_hash")
			}
		}
	}
	if !found {
		t.Fatal("missing oauth_callback_success audit event")
	}
	var n int64
	if err := database.Model(&db.Session{}).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("sessions = %d, err = %v; want 1", n, err)
	}
}

// secLogLeaks reports whether secret appears in captured slog output: verbatim,
// inside a decoded JSON value (the handler escapes control bytes, so a raw
// substring search cannot see them), or inside any base64 chunk the log carries.
func secLogLeaks(logs, secret string) bool {
	if strings.Contains(logs, secret) {
		return true
	}
	for _, line := range strings.Split(logs, "\n") {
		var record any
		if err := json.Unmarshal([]byte(line), &record); err == nil && secJSONValueContains(record, secret) {
			return true
		}
	}
	for _, chunk := range secBase64Chunk.FindAllString(logs, -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			if raw, err := enc.DecodeString(chunk); err == nil && bytes.Contains(raw, []byte(secret)) {
				return true
			}
		}
	}
	return false
}

// secJSONValueContains walks a decoded JSON value, including nested groups and
// slices, for the secret in any string it holds.
func secJSONValueContains(value any, secret string) bool {
	switch v := value.(type) {
	case string:
		return strings.Contains(v, secret)
	case map[string]any:
		for key, inner := range v {
			if strings.Contains(key, secret) || secJSONValueContains(inner, secret) {
				return true
			}
		}
	case []any:
		for _, inner := range v {
			if secJSONValueContains(inner, secret) {
				return true
			}
		}
	}
	return false
}

// secBase64Chunk matches the base64 runs a JSON log line can carry, including
// the URL-safe alphabet and padding.
var secBase64Chunk = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)

// secLogSink is a mutex-guarded writer so captured slog output stays race-clean.
type secLogSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *secLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *secLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// secReasons extracts every oauth_callback_failure reason in emission order.
func secReasons(t *testing.T, logs string) []string {
	t.Helper()
	var reasons []string
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, `"msg":"oauth_callback_failure"`) {
			continue
		}
		var rec struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		reasons = append(reasons, rec.Reason)
	}
	return reasons
}

func TestOAuthSecurity_CallbackFailureReasons(t *testing.T) {
	cases := []struct {
		name       string
		mock       *oauthmock.Mock
		corrupt    bool
		seed       func(t *testing.T, database *gorm.DB)
		query      func(state string) string
		wantStatus int
		wantReason string
	}{
		{
			name: "email_unverified_merge_gate",
			mock: oauthmock.New("google", "sub-reason-unverified", "reason-unverified@example.com", false),
			seed: func(t *testing.T, database *gorm.DB) {
				t.Helper()
				local := db.User{ID: uuid.New(), Email: "reason-unverified@example.com", PasswordHash: "hash", EmailVerified: true}
				if err := database.Create(&local).Error; err != nil {
					t.Fatalf("seed local: %v", err)
				}
			},
			query:      func(state string) string { return "?code=c&state=" + state },
			wantStatus: http.StatusBadRequest, wantReason: "email_unverified",
		},
		{
			name:       "userinfo_invalid",
			mock:       oauthmock.New("google", "sub-reason-padded", " padded@example.com", true),
			query:      func(state string) string { return "?code=c&state=" + state },
			wantStatus: http.StatusBadGateway, wantReason: "userinfo_invalid",
		},
		{
			name: "link_conflict",
			mock: oauthmock.New("google", "sub-reason-conflict", "reason-conflict@example.com", true),
			seed: func(t *testing.T, database *gorm.DB) {
				t.Helper()
				local := db.User{ID: uuid.New(), Email: "reason-conflict@example.com", PasswordHash: "hash", EmailVerified: false}
				if err := database.Create(&local).Error; err != nil {
					t.Fatalf("seed local: %v", err)
				}
			},
			query:      func(state string) string { return "?code=c&state=" + state },
			wantStatus: http.StatusConflict, wantReason: "OAUTH_ACCOUNT_LINK_CONFLICT",
		},
		{
			name:       "provider_error",
			mock:       oauthmock.New("google", "sub-reason-provider", "reason-provider@example.com", true),
			query:      func(string) string { return "?error=access_denied" },
			wantStatus: http.StatusBadGateway, wantReason: "provider_error",
		},
		{
			name:       "exchange_failed",
			mock:       oauthmock.New("google", "sub-reason-exchange", "reason-exchange@example.com", true),
			corrupt:    true,
			query:      func(state string) string { return "?code=c&state=" + state },
			wantStatus: http.StatusBadGateway, wantReason: "exchange_failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &secLogSink{}
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(sink, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			tc.mock.CorruptVerifier = tc.corrupt
			h, database, cfg := setupOAuthSecurityApp(t, map[string]*oauthmock.Mock{"google": tc.mock})
			if tc.seed != nil {
				tc.seed(t, database)
			}
			state, cookies := secInitiate(t, h, "/auth/oauth/google")
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback"+tc.query(state), nil)
			req.AddCookie(secFindCookie(cookies, cfg.OAuth.StateCookieName))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d; want %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			reasons := secReasons(t, sink.String())
			if len(reasons) == 0 || reasons[len(reasons)-1] != tc.wantReason {
				t.Fatalf("reasons = %v; want last %q", reasons, tc.wantReason)
			}
		})
	}
}
