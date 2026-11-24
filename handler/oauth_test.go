package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/session"
)

// stubOAuthProvider scripts provider responses for handler-level OAuth tests.
type stubOAuthProvider struct {
	id      string
	info    *oauth.UserInfo
	infoErr error
	exchErr error
}

func (f *stubOAuthProvider) ID() string { return f.id }

func (f *stubOAuthProvider) AuthURL(state, codeChallenge string) string {
	return "https://provider.example/auth?state=" + state + "&code_challenge=" + codeChallenge
}

func (f *stubOAuthProvider) AuthCodeURL(state, codeChallenge string, _ ...oauth.AuthCodeOption) string {
	return f.AuthURL(state, codeChallenge)
}

func (f *stubOAuthProvider) ExchangeCode(_ context.Context, code, _ string) (*oauth.TokenResponse, error) {
	if f.exchErr != nil {
		return nil, f.exchErr
	}
	if code == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed", nil)
	}
	return &oauth.TokenResponse{AccessToken: "stub-access"}, nil
}

func (f *stubOAuthProvider) FetchUserInfo(_ context.Context, _ *oauth.TokenResponse) (*oauth.UserInfo, error) {
	if f.infoErr != nil {
		return nil, f.infoErr
	}
	return f.info, nil
}

func oauthTestConfig() config.Config {
	cfg := testConfig()
	cfg.SessionCookieSecure = false
	cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
	return cfg
}

func oauthTestEnv(t *testing.T, info *oauth.UserInfo, opts ...Option) (*gorm.DB, http.Handler) {
	t.Helper()
	database := setupTestDB(t)
	if err := database.Exec(`CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		provider_id VARCHAR(32) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		created_at DATETIME,
		updated_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create oauth_accounts: %v", err)
	}
	cfg := oauthTestConfig()
	stub := &stubOAuthProvider{id: "google", info: info}
	appleInfo := *info
	appleInfo.ProviderID = "apple"
	appleStub := &stubOAuthProvider{id: "apple", info: &appleInfo}
	providers := map[string]oauth.Provider{"google": stub, "apple": appleStub}
	sessionSvc := session.NewService(database, &cfg)
	oauthSvc := oauth.NewService(database, sessionSvc, providers, &cfg)
	args := []Option{
		WithSessionService(sessionSvc),
		WithOAuthService(oauthSvc, providers),
	}
	args = append(args, opts...)
	h := New(database, cfg, nil, args...)
	return database, h
}

// attachBrowserCookies forwards initiate cookies the way a browser would: Lax
// cookies are withheld on cross-site POST (Apple form_post) and Secure
// cookies need HTTPS. httptest applies no cookie policy, so tests that
// hand-inject with AddCookie cannot observe a SameSite break.
func attachBrowserCookies(req *http.Request, cookies []*http.Cookie) {
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

// driveInitiate performs a real initiate through the router.
func driveInitiate(t *testing.T, h http.Handler, path string) (string, []*http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("initiate %s: status = %d; want 302 (%s)", path, rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("Location missing state: %q", loc)
	}
	return state, rec.Result().Cookies(), loc
}

func stateCookie(t *testing.T, cookies []*http.Cookie) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == "oauth_state" {
			return c
		}
	}
	t.Fatal("no oauth_state cookie issued")
	return nil
}

func TestOAuthInitiateRoute(t *testing.T) {
	t.Run("sets state cookie and 302s to provider", func(t *testing.T) {
		_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "s", Email: "a@b.c", EmailVerified: true})
		state, cookies, loc := driveInitiate(t, h, "/auth/oauth/google")
		if !strings.Contains(loc, "https://provider.example/auth") {
			t.Fatalf("Location = %q; want provider URL", loc)
		}
		if !strings.Contains(loc, "code_challenge=") {
			t.Fatalf("Location missing PKCE challenge: %q", loc)
		}
		c := stateCookie(t, cookies)
		if !c.HttpOnly || c.MaxAge <= 0 {
			t.Fatalf("state cookie HttpOnly=%v MaxAge=%d; want true/>0", c.HttpOnly, c.MaxAge)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Fatalf("GET-flow state cookie SameSite=%v; want Lax", c.SameSite)
		}
		_ = state
	})

	t.Run("apple initiate issues None Secure state cookie", func(t *testing.T) {
		_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "apple", ProviderUserID: "s", Email: "a@b.c", EmailVerified: true})
		_, cookies, _ := driveInitiate(t, h, "/auth/oauth/apple")
		c := stateCookie(t, cookies)
		if c.SameSite != http.SameSiteNoneMode {
			t.Fatalf("form_post state cookie SameSite=%v; want None", c.SameSite)
		}
		if !c.Secure {
			t.Fatal("form_post state cookie Secure=false; want true (None requires Secure)")
		}
	})

	t.Run("alias initiates identically", func(t *testing.T) {
		_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "s", Email: "a@b.c", EmailVerified: true})
		_, _, loc := driveInitiate(t, h, "/api/auth/oauth/google")
		if !strings.Contains(loc, "https://provider.example/auth") {
			t.Fatalf("alias Location = %q", loc)
		}
	})

	t.Run("non-canonical casing dispatches", func(t *testing.T) {
		_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "s", Email: "a@b.c", EmailVerified: true})
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/GOOGLE")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/GOOGLE/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("callback with non-canonical casing: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("attached provider map dispatches", func(t *testing.T) {
		cfg := oauthTestConfig()
		database := setupTestDB(t)
		custom := &stubOAuthProvider{id: "custom-map", info: &oauth.UserInfo{
			ProviderID: "custom-map", ProviderUserID: "map-sub", Email: "map@example.com", EmailVerified: true}}
		providers := map[string]oauth.Provider{"custom-map": custom}
		oauthSvc := oauth.NewService(database, session.NewService(database, &cfg), providers, &cfg)
		h := New(database, cfg, nil, WithOAuthService(oauthSvc, providers))
		driveInitiate(t, h, "/auth/oauth/custom-map")
	})

	t.Run("attached registry dispatches dynamic providers", func(t *testing.T) {
		cfg := oauthTestConfig()
		database := setupTestDB(t)
		reg := oauth.NewRegistry()
		if err := reg.Register(&stubOAuthProvider{id: "custom-idp", info: &oauth.UserInfo{
			ProviderID: "custom-idp", ProviderUserID: "reg-sub", Email: "reg@example.com", EmailVerified: true}}); err != nil {
			t.Fatalf("register provider: %v", err)
		}
		oauthSvc := oauth.NewServiceWithRegistry(gormstore.New(database), session.NewService(database, &cfg), reg, &cfg)
		h := New(database, cfg, nil, WithOAuthRegistry(oauthSvc, reg))
		driveInitiate(t, h, "/auth/oauth/custom-idp")
	})

	t.Run("attached providers without a service report the wiring bug", func(t *testing.T) {
		cfg := oauthTestConfig()
		providers := map[string]oauth.Provider{"google": &stubOAuthProvider{id: "google"}}
		h := New(nil, cfg, nil, WithOAuthService(nil, providers))
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d; want 500 (%s)", rec.Code, rec.Body.String())
		}
		if code := decodeErrCode(t, rec); code != errors.CodeInternalError {
			t.Fatalf("code = %s; want INTERNAL_ERROR", code)
		}
	})

	t.Run("unknown provider 404s", func(t *testing.T) {
		_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "s", Email: "a@b.c", EmailVerified: true})
		for _, path := range []string{"/auth/oauth/discord", "/api/auth/oauth/microsoft"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s: status = %d; want 404", path, rec.Code)
			}
			if code := decodeErrCode(t, rec); code != errors.CodeOAuthProviderNotFound {
				t.Fatalf("%s: code = %s; want OAUTH_PROVIDER_NOT_FOUND", path, code)
			}
		}
	})
}

func TestOAuthCallbackRoute(t *testing.T) {
	callbackInfo := func() *oauth.UserInfo {
		return &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-1", Email: "jane@example.com", EmailVerified: true}
	}

	t.Run("tampered state 403s without touching DB", func(t *testing.T) {
		database, h := oauthTestEnv(t, callbackInfo())
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state+"-bad", nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d; want 403", rec.Code)
		}
		if code := decodeErrCode(t, rec); code != errors.CodeOAuthStateInvalid {
			t.Fatalf("code = %s; want OAUTH_STATE_INVALID", code)
		}
		var n int64
		if err := database.Model(&db.User{}).Count(&n).Error; err != nil || n != 0 {
			t.Fatalf("users = %d, err = %v; want 0", n, err)
		}
	})

	t.Run("unverified email registers unverified user", func(t *testing.T) {
		database, h := oauthTestEnv(t,
			&oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-9", Email: "new@example.com"})
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d; want 302 (%s)", rec.Code, rec.Body.String())
		}
		var user db.User
		if err := database.Where("email = ?", "new@example.com").First(&user).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		if user.EmailVerified {
			t.Fatal("user EmailVerified = true; want false")
		}
		var links, sessions int64
		if err := database.Model(&db.OAuthAccount{}).Count(&links).Error; err != nil || links != 0 {
			t.Fatalf("links = %d, err = %v; want 0 for an unverified address", links, err)
		}
		if err := database.Model(&db.Session{}).Count(&sessions).Error; err != nil || sessions != 1 {
			t.Fatalf("sessions = %d, err = %v; want 1", sessions, err)
		}
	})

	t.Run("unverified email cannot merge into existing account", func(t *testing.T) {
		database, h := oauthTestEnv(t,
			&oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-10", Email: "victim@example.com"})
		victim := db.User{ID: uuid.New(), Email: "victim@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&victim).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d; want 400 (%s)", rec.Code, rec.Body.String())
		}
		if code := decodeErrCode(t, rec); code != errors.CodeOAuthEmailUnverified {
			t.Fatalf("code = %s; want OAUTH_EMAIL_UNVERIFIED", code)
		}
		for _, m := range []struct {
			model any
			want  int64
		}{{&db.User{}, 1}, {&db.OAuthAccount{}, 0}, {&db.Session{}, 0}} {
			var n int64
			if err := database.Model(m.model).Count(&n).Error; err != nil || n != m.want {
				t.Fatalf("model %T count = %d, err = %v; want %d", m.model, n, err, m.want)
			}
		}
		var after db.User
		if err := database.Where("id = ?", victim.ID).First(&after).Error; err != nil {
			t.Fatalf("victim missing: %v", err)
		}
		if after.PasswordHash != "hash" || !after.EmailVerified {
			t.Fatalf("victim mutated: %+v", after)
		}
	})

	t.Run("verified email creates user then 302s", func(t *testing.T) {
		database, h := oauthTestEnv(t, callbackInfo())
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d; want 302 (%s)", rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Fatalf("Location = %q; want /", loc)
		}
		var users int64
		if err := database.Model(&db.User{}).Count(&users).Error; err != nil || users != 1 {
			t.Fatalf("users = %d, err = %v; want 1", users, err)
		}
		var user db.User
		if err := database.First(&user).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		if !user.EmailVerified || user.PasswordHash != "" {
			t.Fatalf("verified=%v hash=%q; want true/empty", user.EmailVerified, user.PasswordHash)
		}
	})

	t.Run("verified email links existing user without dup", func(t *testing.T) {
		database, h := oauthTestEnv(t, callbackInfo())
		existing := db.User{ID: uuid.New(), Email: "jane@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&existing).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d; want 302 (%s)", rec.Code, rec.Body.String())
		}
		var users int64
		if err := database.Model(&db.User{}).Count(&users).Error; err != nil || users != 1 {
			t.Fatalf("users = %d, err = %v; want 1", users, err)
		}
		var links int64
		if err := database.Model(&db.OAuthAccount{}).Count(&links).Error; err != nil || links != 1 {
			t.Fatalf("links = %d, err = %v; want 1", links, err)
		}
	})

	t.Run("repeat login reuses link with fresh session", func(t *testing.T) {
		database, h := oauthTestEnv(t, callbackInfo())
		for i := 0; i < 2; i++ {
			state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
			req.AddCookie(stateCookie(t, cookies))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusFound {
				t.Fatalf("login %d: status = %d (%s)", i, rec.Code, rec.Body.String())
			}
		}
		var users, links, sessions int64
		_ = database.Model(&db.User{}).Count(&users)
		_ = database.Model(&db.OAuthAccount{}).Count(&links)
		_ = database.Model(&db.Session{}).Count(&sessions)
		if users != 1 || links != 1 || sessions != 2 {
			t.Fatalf("users=%d links=%d sessions=%d; want 1/1/2", users, links, sessions)
		}
	})

	t.Run("form_post callback succeeds without CSRF tokens", func(t *testing.T) {
		_, h := oauthTestEnv(t, callbackInfo())
		// POST alias route with urlencoded body; no CSRF cookie/header attached.
		state, cookies, _ := driveInitiate(t, h, "/api/auth/oauth/apple")
		sc := stateCookie(t, cookies)
		if sc.SameSite != http.SameSiteNoneMode || !sc.Secure {
			t.Fatalf("form_post state cookie SameSite=%v Secure=%v; want None/true", sc.SameSite, sc.Secure)
		}
		req := httptest.NewRequest(http.MethodPost, "https://example.com/api/auth/oauth/apple/callback",
			strings.NewReader(url.Values{"code": {"c"}, "state": {state}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		attachBrowserCookies(req, cookies)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("POST callback: status = %d; want 302 (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("provider error param maps to 502", func(t *testing.T) {
		_, h := oauthTestEnv(t, callbackInfo())
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?error=access_denied", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d; want 502", rec.Code)
		}
		if code := decodeErrCode(t, rec); code != errors.CodeOAuthProviderError {
			t.Fatalf("code = %s; want OAUTH_PROVIDER_ERROR", code)
		}
	})

	t.Run("JSON accept returns 200 payload", func(t *testing.T) {
		_, h := oauthTestEnv(t, callbackInfo())
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; want 200 (%s)", rec.Code, rec.Body.String())
		}
		var body struct {
			UserID uuid.UUID `json:"user_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.UserID == uuid.Nil {
			t.Fatal("empty user_id in JSON response")
		}
	})

	t.Run("JSON branch sanitizes attacker redirect", func(t *testing.T) {
		_, h := oauthTestEnv(t, callbackInfo())
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google?redirect_url=https://evil.example/phish")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; want 200 (%s)", rec.Code, rec.Body.String())
		}
		var body struct {
			RedirectURL string `json:"redirect_url"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.RedirectURL != "/" {
			t.Fatalf("redirect_url = %q; want /", body.RedirectURL)
		}
	})

	t.Run("provider error clears single-use state cookie", func(t *testing.T) {
		_, h := oauthTestEnv(t, callbackInfo())
		_, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?error=access_denied", nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d; want 502", rec.Code)
		}
		cleared := false
		for _, c := range rec.Result().Cookies() {
			if c.Name == "oauth_state" && c.MaxAge == -1 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("oauth_state cookie not cleared on provider error")
		}
	})

	t.Run("nil oauth service maps to internal error", func(t *testing.T) {
		cfg := oauthTestConfig()
		h := &Handler{cfg: cfg}
		cases := []struct {
			name string
			run  func(rec *httptest.ResponseRecorder, req *http.Request)
		}{
			{"initiate", func(rec *httptest.ResponseRecorder, req *http.Request) { h.OAuthInitiate(rec, req) }},
			{"callback", func(rec *httptest.ResponseRecorder, req *http.Request) { h.OAuthCallback(rec, req) }},
		}
		for _, tc := range cases {
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
			req.SetPathValue("provider", "google")
			rec := httptest.NewRecorder()
			tc.run(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s: status = %d; want 500", tc.name, rec.Code)
			}
			if code := decodeErrCode(t, rec); code != errors.CodeInternalError {
				t.Fatalf("%s: code = %s; want INTERNAL_ERROR", tc.name, code)
			}
		}
	})

	t.Run("unverified local blocks link with 409", func(t *testing.T) {
		database, h := oauthTestEnv(t, callbackInfo())
		local := db.User{ID: uuid.New(), Email: "jane@example.com", PasswordHash: "hash", EmailVerified: false}
		if err := database.Create(&local).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d; want 409 (%s)", rec.Code, rec.Body.String())
		}
		if code := decodeErrCode(t, rec); code != errors.CodeOAuthAccountLinkConflict {
			t.Fatalf("code = %s; want OAUTH_ACCOUNT_LINK_CONFLICT", code)
		}
	})
}

func TestOAuthCallbackBearerBranch(t *testing.T) {
	bearerInfo := &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-bearer", Email: "bearer@example.com", EmailVerified: true}
	cases := []struct {
		name  string
		apply func(*http.Request)
	}{
		{"type query", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("type", "bearer")
			r.URL.RawQuery = q.Encode()
		}},
		{"auth type header", func(r *http.Request) { r.Header.Set("X-Auth-Type", "bearer") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database, h := oauthTestEnv(t, bearerInfo)
			state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
			req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
			tc.apply(req)
			req.AddCookie(stateCookie(t, cookies))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d; want 200 (%s)", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q; want no-store", got)
			}
			if got := rec.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q; want no-cache", got)
			}
			var body struct {
				UserID    uuid.UUID `json:"user_id"`
				Token     string    `json:"token"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Token == "" {
				t.Fatal("bearer branch returned no token")
			}
			cfg := oauthTestConfig()
			for _, c := range rec.Result().Cookies() {
				if c.Name == cfg.SessionCookieName {
					t.Fatal("bearer branch must not set a session cookie")
				}
			}
			svc := session.NewService(database, &cfg)
			sess, err := svc.GetSession(context.Background(), body.Token)
			if err != nil {
				t.Fatalf("bearer token rejected: %v", err)
			}
			if sess.Type != db.SessionTypeBearer {
				t.Fatalf("session type = %q; want bearer", sess.Type)
			}
			if sess.UserID != body.UserID {
				t.Fatal("token session user mismatch")
			}
		})
	}
}

func TestOAuthCallbackIssuesCSRF(t *testing.T) {
	csrfInfo := &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-csrf", Email: "csrf@example.com", EmailVerified: true}

	t.Run("302 sets CSRF cookie", func(t *testing.T) {
		_, h := oauthTestEnv(t, csrfInfo)
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d; want 302 (%s)", rec.Code, rec.Body.String())
		}
		cfg := oauthTestConfig()
		found := ""
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.CSRFCookieName {
				found = c.Value
			}
		}
		if found == "" {
			t.Fatal("302 branch issued no CSRF cookie")
		}
	})

	t.Run("JSON returns csrf_token matching cookie", func(t *testing.T) {
		_, h := oauthTestEnv(t, csrfInfo)
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.Header.Set("Accept", "application/json")
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; want 200 (%s)", rec.Code, rec.Body.String())
		}
		var body struct {
			CSRFToken string `json:"csrf_token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.CSRFToken == "" {
			t.Fatal("JSON branch returned no csrf_token")
		}
		cfg := oauthTestConfig()
		cookieVal := ""
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.CSRFCookieName {
				cookieVal = c.Value
			}
		}
		if cookieVal == "" {
			t.Fatal("JSON branch issued no CSRF cookie")
		}
		if body.CSRFToken != cookieVal {
			t.Fatal("csrf_token body does not match CSRF cookie")
		}
	})
}

func TestOAuthCallbackFormPostProviderError(t *testing.T) {
	_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-err", Email: "err@example.com", EmailVerified: true})
	state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
	form := url.Values{"error": {"access_denied"}, "state": {state}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth/google/callback",
		strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(stateCookie(t, cookies))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d; want 502", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != errors.CodeOAuthProviderError {
		t.Fatalf("code = %s; want OAUTH_PROVIDER_ERROR", code)
	}
}

func TestOAuthCallbackCookieJSONSetsNoStore(t *testing.T) {
	_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-nostore-json", Email: "nostore-json@example.com", EmailVerified: true})
	state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(stateCookie(t, cookies))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
}

func TestOAuthCallbackRedirectSetsNoStore(t *testing.T) {
	_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-nostore-302", Email: "nostore-302@example.com", EmailVerified: true})
	state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
	req.AddCookie(stateCookie(t, cookies))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302 (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
}

func TestOAuthCallbackFailureHasNoCacheHeaders(t *testing.T) {
	database, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-nostore-fail", Email: "nostore-fail@example.com"})
	existing := db.User{ID: uuid.New(), Email: "nostore-fail@example.com", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&existing).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
	req.AddCookie(stateCookie(t, cookies))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != errors.CodeOAuthEmailUnverified {
		t.Fatalf("code = %s; want OAUTH_EMAIL_UNVERIFIED", code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control = %q; want empty on failure", got)
	}
	if got := rec.Header().Get("Pragma"); got != "" {
		t.Errorf("Pragma = %q; want empty on failure", got)
	}
}

type stubCallbackOAuthService struct {
	callbackFn func(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string, sessType db.SessionType) (*session.Session, string, string, error)
}

func (s *stubCallbackOAuthService) InitiateFlow(w http.ResponseWriter, r *http.Request, providerID string) (string, error) {
	return "https://example.com/auth", nil
}

func (s *stubCallbackOAuthService) HandleCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string, sessType db.SessionType) (*session.Session, string, string, error) {
	if s.callbackFn != nil {
		return s.callbackFn(ctx, w, r, providerID, code, state, sessType)
	}
	return nil, "", "", nil
}

func TestOAuthRateLimited(t *testing.T) {
	rlInfo := &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-rl", Email: "rl@example.com", EmailVerified: true}

	t.Run("initiate throttled per IP", func(t *testing.T) {
		_, h := oauthTestEnv(t, rlInfo, WithOAuthIPLimiters(ratelimit.NewLimiter(time.Minute, 1)))
		first := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
		firstRec := httptest.NewRecorder()
		h.ServeHTTP(firstRec, first)
		if firstRec.Code != http.StatusFound {
			t.Fatalf("first initiate: status = %d; want 302", firstRec.Code)
		}
		second := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
		secondRec := httptest.NewRecorder()
		h.ServeHTTP(secondRec, second)
		if secondRec.Code != http.StatusTooManyRequests {
			t.Fatalf("second initiate: status = %d; want 429", secondRec.Code)
		}
		if code := decodeErrCode(t, secondRec); code != errors.CodeRateLimitExceeded {
			t.Fatalf("code = %s; want RATE_LIMIT_EXCEEDED", code)
		}
	})

	t.Run("callback throttled per IP", func(t *testing.T) {
		_, h := oauthTestEnv(t, rlInfo, WithOAuthIPLimiters(ratelimit.NewLimiter(time.Minute, 1)))
		state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback?code=c&state="+state, nil)
		req.AddCookie(stateCookie(t, cookies))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("callback: status = %d; want 429", rec.Code)
		}
		if code := decodeErrCode(t, rec); code != errors.CodeRateLimitExceeded {
			t.Fatalf("code = %s; want RATE_LIMIT_EXCEEDED", code)
		}
	})

	t.Run("default limiter allows normal use", func(t *testing.T) {
		_, h := oauthTestEnv(t, rlInfo)
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("initiate with default limiter: status = %d; want 302", rec.Code)
		}
	})

	t.Run("upstream rate limit with Retry-After header", func(t *testing.T) {
		mockSvc := &stubCallbackOAuthService{
			callbackFn: func(ctx context.Context, w http.ResponseWriter, r *http.Request, providerID, code, state string, sessType db.SessionType) (*session.Session, string, string, error) {
				return nil, "", "", &oauth.RateLimitError{RetryAfter: 42, Err: errors.ErrOAuthRateLimitExceeded}
			},
		}
		h := New(nil, config.DefaultConfig(), nil, WithOAuthService(mockSvc, map[string]oauth.Provider{"x": &stubOAuthProvider{id: "x"}}))
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/x/callback?code=c&state=s", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 Too Many Requests, got %d", rec.Code)
		}
		if ra := rec.Header().Get("Retry-After"); ra != "42" {
			t.Fatalf("expected Retry-After 42, got %q", ra)
		}
	})
}

func TestOAuthTransportSelection(t *testing.T) {
	t.Run("selector truth table", func(t *testing.T) {
		cases := []struct {
			name       string
			method     string
			target     string
			headers    map[string]string
			body       string
			wantBearer bool
			wantJSON   bool
		}{
			{"cookie default", http.MethodGet, "/auth/oauth/google/callback",
				nil, "", false, false},
			{"bearer header", http.MethodGet, "/auth/oauth/google/callback",
				map[string]string{"X-Auth-Type": "bearer"}, "", true, true},
			{"bearer query", http.MethodGet, "/auth/oauth/google/callback?type=bearer",
				nil, "", true, true},
			{"json accept", http.MethodGet, "/auth/oauth/google/callback",
				map[string]string{"Accept": "application/json"}, "", false, true},
			{"both selectors", http.MethodGet, "/auth/oauth/google/callback?type=bearer",
				map[string]string{"Accept": "application/json"}, "", true, true},
			{"post form_post bearer query", http.MethodPost, "/api/auth/oauth/apple/callback?type=bearer",
				map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "code=c", true, true},
			{"post form_post body type ignored", http.MethodPost, "/api/auth/oauth/apple/callback",
				map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "code=c&type=bearer", false, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var body *strings.Reader
				if tc.body != "" {
					body = strings.NewReader(tc.body)
				} else {
					body = strings.NewReader("")
				}
				req := httptest.NewRequest(tc.method, tc.target, body)
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				bearer, wantJSON := oauthTransport(req)
				if bearer != tc.wantBearer || wantJSON != tc.wantJSON {
					t.Fatalf("oauthTransport = (%v,%v); want (%v,%v)", bearer, wantJSON, tc.wantBearer, tc.wantJSON)
				}
			})
		}
	})

	t.Run("post form_post bearer query mints bearer session", func(t *testing.T) {
		database, h := oauthTestEnv(t,
			&oauth.UserInfo{ProviderID: "apple", ProviderUserID: "sub-post-bearer", Email: "post-bearer@example.com", EmailVerified: true})
		state, cookies, _ := driveInitiate(t, h, "/api/auth/oauth/apple")
		req := httptest.NewRequest(http.MethodPost, "https://example.com/api/auth/oauth/apple/callback?type=bearer",
			strings.NewReader(url.Values{"code": {"c"}, "state": {state}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		attachBrowserCookies(req, cookies)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; want 200 (%s)", rec.Code, rec.Body.String())
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Token == "" {
			t.Fatal("bearer branch returned no token")
		}
		cfg := oauthTestConfig()
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.SessionCookieName {
				t.Fatal("bearer branch must not set a session cookie")
			}
		}
		var sessions int64
		if err := database.Model(&db.Session{}).Count(&sessions).Error; err != nil || sessions != 1 {
			t.Fatalf("sessions = %d, err = %v; want 1", sessions, err)
		}
	})
}

func TestSafeOAuthRedirect(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string
	}{
		{"empty defaults to root", "", "/"},
		{"absolute url rejected", "http://evil.example/phish", "/"},
		{"protocol relative rejected", "//evil.example", "/"},
		{"slash backslash rejected", "/\\evil.example", "/"},
		{"double backslash rejected", "\\\\evil.example", "/"},
		{"space prefix rejected", " /path", "/"},
		{"tab prefix rejected", "\t/path", "/"},
		{"cr suffix rejected", "/path\r", "/"},
		{"lf suffix rejected", "/path\n", "/"},
		{"relative path allowed", "/path", "/path"},
		{"query string allowed", "/?q=1", "/?q=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeOAuthRedirect(tc.target); got != tc.want {
				t.Fatalf("safeOAuthRedirect(%q) = %q; want %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestOAuthCallbackFormPostOversize(t *testing.T) {
	_, h := oauthTestEnv(t, &oauth.UserInfo{ProviderID: "google", ProviderUserID: "sub-oversize", Email: "oversize@example.com", EmailVerified: true})
	state, cookies, _ := driveInitiate(t, h, "/auth/oauth/google")
	oversized := "code=c&state=" + state + "&pad=" + strings.Repeat("a", 1<<20)
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth/google/callback", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(stateCookie(t, cookies))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400 (%s)", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != errors.CodeValidationError {
		t.Fatalf("code = %s; want VALIDATION_ERROR", code)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "oauth_state" && c.MaxAge == -1 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("state cookie not cleared on unreadable form")
	}
}
