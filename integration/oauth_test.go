//go:build integration

package integration

// Real-PostgreSQL OAuth E2E: same provider flows as the isolated sqlite
// suites (tests/integration, tests/security) but against migrated PG so
// PG-specific behavior (23505 strings, real migrations, multi-connection
// races) is covered. PG-gated via setupDB: skips cleanly when PG is
// unreachable (TEST_DATABASE_URL or the default test URL), hard-fails on CI.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

// pgSetupOAuth builds the full HTTP stack over real PG (migrated schema)
// with mock providers wired by slug.
func pgSetupOAuth(t *testing.T, mocks map[string]*oauthmock.Mock) (http.Handler, *gorm.DB, config.Config) {
	t.Helper()
	database, cfg := setupDB(t)
	cfg.OAuth.StateSecret = "test-oauth-state-secret-32bytes!!"
	cfg.SessionCookieSecure = false
	cfg.DisableAsyncEmailDispatch = true
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

func pgInitiate(t *testing.T, h http.Handler, path string) (string, []*http.Cookie) {
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

func pgFindCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func pgStateVerifier(t *testing.T, cookie *http.Cookie) string {
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

func pgCounts(t *testing.T, database *gorm.DB) (users, links, sessions int64) {
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

// pgForwardBrowserCookies forwards initiate cookies the way a browser would:
// Lax cookies are withheld on cross-site POST (Apple form_post) and Secure
// cookies need HTTPS. httptest applies no cookie policy, so hand-injecting
// with AddCookie cannot observe a SameSite break.
func pgForwardBrowserCookies(req *http.Request, cookies []*http.Cookie) {
	https := req.URL.Scheme == "https" || req.TLS != nil
	for _, c := range cookies {
		if c.Secure && !https {
			continue
		}
		if req.Method == http.MethodPost && c.SameSite == http.SameSiteLaxMode {
			continue
		}
		req.AddCookie(c)
	}
}

// pgCallbackGET runs a browser-flow GET callback, requiring 302 + session.
func pgCallbackGET(t *testing.T, h http.Handler, cfg config.Config, provider, code, state string, stateCookie *http.Cookie) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+provider+"/callback?code="+code+"&state="+state, nil)
	req.AddCookie(stateCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
	}
	sid := pgFindCookie(rec.Result().Cookies(), cfg.SessionCookieName)
	if sid == nil || len(sid.Value) != 32 {
		t.Fatalf("missing 32-char session cookie in callback response")
	}
	return sid
}

// pgSessionUserID verifies the session cookie via GET /auth/session.
func pgSessionUserID(t *testing.T, h http.Handler, database *gorm.DB, sid *http.Cookie) uuid.UUID {
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

func TestOAuthPG_E2E_AllProviders(t *testing.T) {
	for _, tc := range []struct {
		name, provider, sub, email string
		formPost                   bool
	}{
		{"google GET callback", "google", "pg-goog-1", "pg-e2e-google@example.com", false},
		{"github GET callback", "github", "pg-gh-4242", "pg-e2e-github@example.com", false},
		{"apple POST form_post callback", "apple", "pg-apple-9", "pg-e2e-apple@example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := oauthmock.New(tc.provider, tc.sub, tc.email, true)
			h, database, cfg := pgSetupOAuth(t, map[string]*oauthmock.Mock{tc.provider: m})

			state, cookies := pgInitiate(t, h, "/auth/oauth/"+tc.provider)
			sc := pgFindCookie(cookies, cfg.OAuth.StateCookieName)
			if sc == nil || !sc.HttpOnly || sc.MaxAge <= 0 {
				t.Fatalf("bad state cookie: %+v", sc)
			}
			if tc.formPost {
				if sc.SameSite != http.SameSiteNoneMode || !sc.Secure {
					t.Fatalf("form_post state cookie SameSite=%v Secure=%v; want None/true", sc.SameSite, sc.Secure)
				}
			} else if sc.SameSite != http.SameSiteLaxMode {
				t.Fatalf("GET-flow state cookie SameSite=%v; want Lax", sc.SameSite)
			}
			verifier := pgStateVerifier(t, sc)

			var sid *http.Cookie
			if tc.formPost {
				req := httptest.NewRequest(http.MethodPost, "https://example.com/auth/oauth/"+tc.provider+"/callback",
					strings.NewReader(url.Values{"code": {"code-" + tc.provider}, "state": {state}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				pgForwardBrowserCookies(req, cookies)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusFound {
					t.Fatalf("form_post callback: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
				}
				sid = pgFindCookie(rec.Result().Cookies(), cfg.SessionCookieName)
				if sid == nil {
					t.Fatal("no session cookie on form_post success")
				}
			} else {
				sid = pgCallbackGET(t, h, cfg, tc.provider, "code-"+tc.provider, state, sc)
			}

			userID := pgSessionUserID(t, h, database, sid)
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
			if users, links, sessions := pgCounts(t, database); users != 1 || links != 1 || sessions != 1 {
				t.Fatalf("users=%d links=%d sessions=%d; want 1/1/1", users, links, sessions)
			}
		})
	}
}

func TestOAuthPG_AutoLinkVerifiedEmail(t *testing.T) {
	m := oauthmock.New("google", "pg-sub-link-1", "pg-linked@example.com", true)
	h, database, cfg := pgSetupOAuth(t, map[string]*oauthmock.Mock{"google": m})

	existing := db.User{ID: uuid.New(), Email: "pg-linked@example.com", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&existing).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	state, cookies := pgInitiate(t, h, "/auth/oauth/google")
	sid := pgCallbackGET(t, h, cfg, "google", "code-1", state, pgFindCookie(cookies, cfg.OAuth.StateCookieName))

	if got := pgSessionUserID(t, h, database, sid); got != existing.ID {
		t.Fatalf("session user = %v; want seeded %v", got, existing.ID)
	}
	if users, links, _ := pgCounts(t, database); users != 1 || links != 1 {
		t.Fatalf("users=%d links=%d; want 1/1", users, links)
	}
}

func TestOAuthPG_MultiProviderOneUser(t *testing.T) {
	g := oauthmock.New("google", "pg-sub-multi-g", "pg-multi@example.com", true)
	hh := oauthmock.New("github", "pg-sub-multi-h", "pg-multi@example.com", true)
	h, database, cfg := pgSetupOAuth(t, map[string]*oauthmock.Mock{"google": g, "github": hh})

	stateG, cookiesG := pgInitiate(t, h, "/auth/oauth/google")
	sidG := pgCallbackGET(t, h, cfg, "google", "code-g", stateG, pgFindCookie(cookiesG, cfg.OAuth.StateCookieName))
	first := pgSessionUserID(t, h, database, sidG)

	stateH, cookiesH := pgInitiate(t, h, "/auth/oauth/github")
	sidH := pgCallbackGET(t, h, cfg, "github", "code-h", stateH, pgFindCookie(cookiesH, cfg.OAuth.StateCookieName))
	if got := pgSessionUserID(t, h, database, sidH); got != first {
		t.Fatalf("github session user = %v; want google user %v", got, first)
	}
	var links []db.OAuthAccount
	if err := database.Where("user_id = ?", first).Find(&links).Error; err != nil {
		t.Fatalf("links: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("links for user = %d; want 2 (google+github)", len(links))
	}
	if users, total, sessions := pgCounts(t, database); users != 1 || total != 2 || sessions != 2 {
		t.Fatalf("users=%d links=%d sessions=%d; want 1/2/2", users, total, sessions)
	}
}

// TestOAuthPG_ConcurrentCallbacksConverge fires N parallel callbacks sharing
// one code over PG's multi-connection pool so linkOrCreate genuinely races on
// 23505; all must 302 (zero 500s) and converge on one user plus one link.
func TestOAuthPG_ConcurrentCallbacksConverge(t *testing.T) {
	const n = 8
	m := oauthmock.New("google", "pg-race-sub", "pg-race@example.com", true)
	h, database, cfg := pgSetupOAuth(t, map[string]*oauthmock.Mock{"google": m})

	type attempt struct {
		state  string
		cookie *http.Cookie
	}
	atts := make([]attempt, n)
	for i := range atts {
		state, cookies := pgInitiate(t, h, "/auth/oauth/google")
		sc := pgFindCookie(cookies, cfg.OAuth.StateCookieName)
		if sc == nil {
			t.Fatal("missing state cookie")
		}
		atts[i] = attempt{state, sc}
	}
	code := fmt.Sprintf("race-code-%s", uuid.NewString())

	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range atts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code="+code+"&state="+atts[i].state, nil)
			req.AddCookie(atts[i].cookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusFound {
			t.Fatalf("callback %d: status = %d; want 302 (no 500s)", i, c)
		}
	}
	if users, links, sessions := pgCounts(t, database); users != 1 || links != 1 || int(sessions) != n {
		t.Fatalf("users=%d links=%d sessions=%d; want 1/1/%d", users, links, sessions, n)
	}
}
