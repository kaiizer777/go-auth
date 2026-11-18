package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

// setupOAuthFlow builds the full HTTP stack (auth + session + oauth routes)
// over an isolated sqlite DB with mock providers wired by slug.
func setupOAuthFlow(t *testing.T, mocks map[string]*oauthmock.Mock, modifyCfg ...func(*config.Config)) (http.Handler, *gorm.DB, config.Config) {
	t.Helper()
	name := fmt.Sprintf("file:oauth_e2e_%s?mode=memory&cache=shared", uuid.New().String())
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
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider_id VARCHAR(32) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
		created_at DATETIME, updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_uid UNIQUE (provider_id, provider_user_id)
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
	cfg.SessionCookieSecure = false
	cfg.OAuth.StateSecret = "test-oauth-state-secret-32bytes!!"
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

// driveInitiate runs the provider dance entry and returns the state param plus issued cookies.
func driveInitiate(t *testing.T, h http.Handler, path string) (string, []*http.Cookie) {
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
	state := loc.Query().Get("state")
	if state == "" || loc.Query().Get("code_challenge") == "" {
		t.Fatalf("Location missing state/challenge: %q", rec.Header().Get("Location"))
	}
	return state, rec.Result().Cookies()
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// stateVerifier decodes the signed (not encrypted) state payload to recover the PKCE verifier.
func stateVerifier(t *testing.T, cookie *http.Cookie) string {
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

func oauthCounts(t *testing.T, database *gorm.DB) (users, links, sessions int64) {
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

// callbackGET runs a browser-flow GET callback and requires the 302/session/cleared-state triple.
func callbackGET(t *testing.T, h http.Handler, cfg config.Config, provider, code, state string, stateCookie *http.Cookie) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+provider+"/callback?code="+code+"&state="+state, nil)
	req.AddCookie(stateCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q; want /", loc)
	}
	sid := findCookie(rec.Result().Cookies(), cfg.SessionCookieName)
	if sid == nil || len(sid.Value) != 32 {
		t.Fatalf("missing 32-char session cookie in callback response")
	}
	if cleared := findCookie(rec.Result().Cookies(), cfg.OAuth.StateCookieName); cleared == nil || cleared.MaxAge != -1 {
		t.Fatal("state cookie not cleared on success")
	}
	return sid
}

// sessionUserID verifies the session cookie against GET /auth/session and returns the bound user.
func sessionUserID(t *testing.T, h http.Handler, database *gorm.DB, sid *http.Cookie) uuid.UUID {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(sid)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/session: status = %d; want 200 (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Session struct {
			SessionID string `json:"session_id"`
		} `json:"session"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if len(body.Session.SessionID) != 64 || body.Session.SessionID == sid.Value {
		t.Fatalf("session_id = %q; want 64-char hash distinct from raw cookie", body.Session.SessionID)
	}
	var sess db.Session
	if err := database.Where("id_hash = ?", body.Session.SessionID).First(&sess).Error; err != nil {
		t.Fatalf("session row: %v", err)
	}
	return sess.UserID
}

func TestOAuthE2E_AllProviders(t *testing.T) {
	for _, tc := range []struct {
		name, provider, sub, email string
		formPost                   bool
	}{
		{"google GET callback", "google", "goog-sub-1", "e2e-google@example.com", false},
		{"github GET callback", "github", "gh-id-4242", "e2e-github@example.com", false},
		{"apple POST form_post callback", "apple", "apple-sub-9", "e2e-apple@example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := oauthmock.New(tc.provider, tc.sub, tc.email, true)
			h, database, cfg := setupOAuthFlow(t, map[string]*oauthmock.Mock{tc.provider: m})

			state, cookies := driveInitiate(t, h, "/auth/oauth/"+tc.provider)
			sc := findCookie(cookies, cfg.OAuth.StateCookieName)
			if sc == nil || !sc.HttpOnly || sc.MaxAge <= 0 {
				t.Fatalf("bad state cookie: %+v", sc)
			}
			verifier := stateVerifier(t, sc)
			if len(verifier) != 43 {
				t.Fatalf("verifier len = %d; want 43", len(verifier))
			}

			var sid *http.Cookie
			if tc.formPost {
				req := httptest.NewRequest(http.MethodPost, "/auth/oauth/"+tc.provider+"/callback",
					strings.NewReader(url.Values{"code": {"code-" + tc.provider}, "state": {state}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(sc)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusFound {
					t.Fatalf("form_post callback: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
				}
				sid = findCookie(rec.Result().Cookies(), cfg.SessionCookieName)
				if sid == nil {
					t.Fatal("no session cookie on form_post success")
				}
			} else {
				sid = callbackGET(t, h, cfg, tc.provider, "code-"+tc.provider, state, sc)
			}

			userID := sessionUserID(t, h, database, sid)
			var user db.User
			if err := database.Where("id = ?", userID).First(&user).Error; err != nil {
				t.Fatalf("load user: %v", err)
			}
			if !user.EmailVerified || user.PasswordHash != "" {
				t.Fatalf("oauth user verified=%v hash=%q; want true/empty", user.EmailVerified, user.PasswordHash)
			}
			var link db.OAuthAccount
			if err := database.Where("provider_id = ? AND provider_user_id = ?", tc.provider, tc.sub).First(&link).Error; err != nil {
				t.Fatalf("link row: %v", err)
			}
			if link.UserID != userID || !strings.EqualFold(link.Email, tc.email) {
				t.Fatalf("link = %+v; want user %v email %s", link, userID, tc.email)
			}
			if got, calls := m.ObservedVerifier(); calls != 1 || got != verifier {
				t.Fatalf("provider saw verifier %q in %d calls; want %q once", got, calls, verifier)
			}
			if users, links, sessions := oauthCounts(t, database); users != 1 || links != 1 || sessions != 1 {
				t.Fatalf("users=%d links=%d sessions=%d; want 1/1/1", users, links, sessions)
			}
		})
	}
}

func TestOAuthE2E_AutoLinkVerifiedEmail(t *testing.T) {
	m := oauthmock.New("google", "sub-link-1", "linked@example.com", true)
	h, database, cfg := setupOAuthFlow(t, map[string]*oauthmock.Mock{"google": m})

	existing := db.User{ID: uuid.New(), Email: "linked@example.com", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&existing).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	state, cookies := driveInitiate(t, h, "/auth/oauth/google")
	sid := callbackGET(t, h, cfg, "google", "code-1", state, findCookie(cookies, cfg.OAuth.StateCookieName))

	if got := sessionUserID(t, h, database, sid); got != existing.ID {
		t.Fatalf("session user = %v; want seeded %v", got, existing.ID)
	}
	if users, links, _ := oauthCounts(t, database); users != 1 || links != 1 {
		t.Fatalf("users=%d links=%d; want 1/1", users, links)
	}
}

func TestOAuthE2E_MultiProviderOneUser(t *testing.T) {
	g := oauthmock.New("google", "sub-multi-g", "multi@example.com", true)
	hh := oauthmock.New("github", "sub-multi-h", "multi@example.com", true)
	h, database, cfg := setupOAuthFlow(t, map[string]*oauthmock.Mock{"google": g, "github": hh})

	stateG, cookiesG := driveInitiate(t, h, "/auth/oauth/google")
	sidG := callbackGET(t, h, cfg, "google", "code-g", stateG, findCookie(cookiesG, cfg.OAuth.StateCookieName))
	first := sessionUserID(t, h, database, sidG)

	stateH, cookiesH := driveInitiate(t, h, "/auth/oauth/github")
	sidH := callbackGET(t, h, cfg, "github", "code-h", stateH, findCookie(cookiesH, cfg.OAuth.StateCookieName))
	if got := sessionUserID(t, h, database, sidH); got != first {
		t.Fatalf("github session user = %v; want google user %v", got, first)
	}
	var links []db.OAuthAccount
	if err := database.Where("user_id = ?", first).Find(&links).Error; err != nil {
		t.Fatalf("links: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("links for user = %d; want 2 (google+github)", len(links))
	}
	if users, total, sessions := oauthCounts(t, database); users != 1 || total != 2 || sessions != 2 {
		t.Fatalf("users=%d links=%d sessions=%d; want 1/2/2", users, total, sessions)
	}
}
