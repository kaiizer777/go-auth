//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

// testTokenKEK is the fixed valid keyring the OAuth service seals grants with.
const testTokenKEK = "test-kid:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// TestOAuthVerification_UnverifiedLinkSeveredByPasswordSignup is the only e2e
// journey that runs against the real embedded migrations (up) instead of a
// sqlite DDL fixture. It proves 000009 exists and is used: the link insert and
// the link trust check read oauth_accounts.verified.
func TestOAuthVerification_UnverifiedLinkSeveredByPasswordSignup(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = resolveDatabaseURL()
	cfg.BaseURL = "http://127.0.0.1:8080"
	cfg.OAuth.StateSecret = "super-secret-e2e-postgres-state-key-32b"
	cfg.OAuth.TokenKEK = testTokenKEK
	cfg.SessionCookieSecure = false
	cfg.DisableAsyncEmailDispatch = true
	cfg.Argon2 = config.Argon2Config{
		Memory:      19456,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	database, err := db.Connect(cfg)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to connect to postgres and run migrations at %s: %v", sanitizeURL(cfg.DatabaseURL), err)
		}
		t.Skipf("Postgres not available at %s, skipping migration-backed oauth journey: %v", sanitizeURL(cfg.DatabaseURL), err)
	}
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	truncateTables(t, sqlDB)

	idp := oauthmock.NewFacebookIdP(cfg.BaseURL + "/auth/oauth/facebook/callback")
	t.Cleanup(idp.Close)
	idp.UserID = "fb-postgres-uid-1"
	idp.Email = "pending-pg@example.com"

	provider := oauth.NewFacebookProvider(config.FacebookConfig{
		AppID:       idp.AppID,
		AppSecret:   idp.AppSecret,
		RedirectURI: cfg.BaseURL + "/auth/oauth/facebook/callback",
	}, oauth.FacebookEndpoints(oauth.EndpointOverride{
		AuthorizeURL: idp.Server.URL + "/v19.0/dialog/oauth",
		TokenURL:     idp.Server.URL + "/v19.0/oauth/access_token",
		UserInfoURL:  idp.Server.URL + "/v19.0/me",
		DebugURL:     idp.Server.URL + "/debug_token",
	}))

	server, client := oauthJourneyServer(t, database, cfg, provider)

	login := func() *http.Response {
		return oauthJourneyLogin(t, client, server.URL)
	}

	for i := 1; i <= 2; i++ {
		resp := login()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("unverified login %d = %d; want 302", i, resp.StatusCode)
		}
		if findCookie(resp, cfg.SessionCookieName) == nil {
			t.Fatalf("unverified login %d set no session cookie", i)
		}
	}

	var user db.User
	if err := database.Where("email = ?", "pending-pg@example.com").First(&user).Error; err != nil {
		t.Fatalf("load unverified owner: %v", err)
	}
	if user.EmailVerified {
		t.Fatal("an unverified provider address must not verify the account")
	}
	var link db.OAuthAccount
	if err := database.Where("user_id = ? AND provider_id = ?", user.ID, "facebook").First(&link).Error; err != nil {
		t.Fatalf("load unverified link: %v", err)
	}
	if link.Verified {
		t.Fatal("migration 000009 must persist verified=false for an unverified link")
	}

	authSvc, err := auth.New(cfg, database, cfg.EmailHooks)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	if _, _, err := authSvc.Signup(context.Background(), db.SignupRequest{
		Email:    "pending-pg@example.com",
		Password: "CorrectHorseBattery9!",
	}); err != nil {
		t.Fatalf("password signup: %v", err)
	}
	// An unverified link must not survive a password claim. Setting a password
	// on the account atomically purges any unverified OAuth links on that account.
	var linkCount int64
	if err := database.Model(&db.OAuthAccount{}).Where("user_id = ?", user.ID).Count(&linkCount).Error; err != nil || linkCount != 0 {
		t.Fatalf("expected the unverified link to be purged by password signup, got count=%d err=%v", linkCount, err)
	}

	resp := login()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("login after a password-only signup = %d; want 400", resp.StatusCode)
	}
	if code := responseErrorCode(t, resp); code != "OAUTH_EMAIL_UNVERIFIED" {
		t.Fatalf("error code = %q; want OAUTH_EMAIL_UNVERIFIED", code)
	}

	// The reset token is delivered to the mailbox, so consuming it proves the
	// address: the account is claimed and email verified.
	resetToken, err := authSvc.RequestPasswordReset(context.Background(), db.PasswordResetRequest{Email: "pending-pg@example.com"})
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if _, err := authSvc.ResetPassword(context.Background(), db.PasswordResetConfirmRequest{
		Token: resetToken, NewPassword: "OwnerPassword#2026!",
	}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if err := database.Model(&db.OAuthAccount{}).Where("user_id = ?", user.ID).Count(&linkCount).Error; err != nil || linkCount != 0 {
		t.Fatalf("expected link count to remain 0, got count=%d err=%v", linkCount, err)
	}

	resp = login()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("login through a spent unverified link = %d; want 400", resp.StatusCode)
	}
	if code := responseErrorCode(t, resp); code != "OAUTH_EMAIL_UNVERIFIED" {
		t.Fatalf("error code = %q; want OAUTH_EMAIL_UNVERIFIED", code)
	}

	var claimed db.User
	if err := database.Where("id = ?", user.ID).First(&claimed).Error; err != nil {
		t.Fatalf("reload claimed user: %v", err)
	}
	if !claimed.EmailVerified || claimed.PasswordHash == "" {
		t.Fatalf("recovered account verified=%v hasPassword=%v; want a proven address with a password",
			claimed.EmailVerified, claimed.PasswordHash != "")
	}
}

// oauthJourneyServer builds the full HTTP stack over the migrated database and
// registers provider before any route is served.
func oauthJourneyServer(t *testing.T, database *gorm.DB, cfg config.Config, provider oauth.Provider) (*httptest.Server, *http.Client) {
	t.Helper()
	authSvc, err := auth.New(cfg, database, cfg.EmailHooks)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	sessionSvc := session.NewService(database, &cfg)
	registry := oauth.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatalf("register provider: %v", err)
	}
	oauthSvc := oauth.NewServiceWithRegistry(gormstore.New(database), sessionSvc, registry, &cfg)
	h := handler.New(database, cfg, authSvc,
		handler.WithSessionService(sessionSvc),
		handler.WithOAuthRegistry(oauthSvc, registry),
		handler.WithOAuthService(oauthSvc, nil),
	)
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return server, client
}

func oauthJourneyLogin(t *testing.T, client *http.Client, serverURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(serverURL + "/auth/oauth/facebook")
	if err != nil {
		t.Fatalf("initiate oauth: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("initiate oauth = %d; want 302", resp.StatusCode)
	}
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	_ = resp.Body.Close()

	providerClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	authResp, err := providerClient.Get(authorizeURL.String())
	if err != nil {
		t.Fatalf("provider authorize: %v", err)
	}
	defer func() { _ = authResp.Body.Close() }()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("provider authorize = %d; want 302", authResp.StatusCode)
	}
	callback, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}

	cbResp, err := client.Get(serverURL + callback.RequestURI())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return cbResp
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func responseErrorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return body.Code
}
