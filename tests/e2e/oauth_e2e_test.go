package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

// testTokenKEK is the fixed valid keyring the OAuth service seals grants with.
const testTokenKEK = "test-kid:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func setupOAuthE2EStack(t *testing.T, mutate ...func(*config.Config)) (http.Handler, *gorm.DB, *oauth.Registry, config.Config) {
	t.Helper()
	name := fmt.Sprintf("file:oauth_e2e_%s?mode=memory&cache=shared", uuid.New().String())
	database, err := gorm.Open(sqlite.Open(name), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := database.Exec(sqliteSchema).Error; err != nil {
		t.Fatalf("schema error: %v", err)
	}
	// PRAGMA is per-connection while database/sql pools connections: pin the
	// pool so FK enforcement cannot pass or fail by connection reuse.
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	sqlDB.SetMaxOpenConns(1)
	if err := database.Exec("PRAGMA foreign_keys = ON;").Error; err != nil {
		t.Fatalf("enable foreign_keys: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"
	cfg.OAuth.StateSecret = "super-secret-e2e-state-signing-key-32b"
	cfg.OAuth.TokenKEK = testTokenKEK
	cfg.SessionCookieSecure = false
	for _, fn := range mutate {
		fn(&cfg)
	}

	authSvc, err := auth.New(cfg, database, cfg.EmailHooks)
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}
	sessionSvc := session.NewService(database, &cfg)

	reg := oauth.NewRegistry()
	store := gormstore.New(database)
	oauthSvc := oauth.NewServiceWithRegistry(store, sessionSvc, reg, &cfg)

	oauthHandler := handler.New(database, cfg, authSvc,
		handler.WithSessionService(sessionSvc),
		handler.WithOAuthRegistry(oauthSvc, reg),
		handler.WithOAuthService(oauthSvc, nil),
	)

	return oauthHandler, database, &reg, cfg
}

// initiateOAuth requests the login redirect and returns the provider authorize
// URL plus the cookies the browser must replay on the callback.
func initiateOAuth(t *testing.T, h http.Handler, provider, query string, cookies ...*http.Cookie) (*url.URL, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+provider+query, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("initiate %s = %d (%s); want 302", provider, rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse %s authorize URL: %v", provider, err)
	}
	if loc.Query().Get("state") == "" {
		t.Fatalf("%s authorize URL missing state: %s", provider, loc)
	}
	return loc, rec.Result().Cookies()
}

// authorizeAtIdP plays the browser: it visits the adapter's authorize URL at the
// loopback IdP and returns the callback URL carrying the issued code.
func authorizeAtIdP(t *testing.T, authorizeURL *url.URL) *url.URL {
	t.Helper()
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(authorizeURL.String())
	if err != nil {
		t.Fatalf("provider authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("provider authorize = %d; want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse provider redirect: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("provider redirect missing code: %s", loc)
	}
	return loc
}

func callbackOAuth(t *testing.T, h http.Handler, callback *url.URL, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, callback.RequestURI(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// probeIdentity drives the same adapter instance the journey registered, so
// assertions read adapter output (identity, verification, raw claims) rather
// than a fixture.
func probeIdentity(t *testing.T, p oauth.Provider) *oauth.UserInfo {
	t.Helper()
	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	authorizeURL, err := url.Parse(p.AuthURL("probe-state", pkce.Challenge))
	if err != nil {
		t.Fatalf("parse probe authorize URL: %v", err)
	}
	callback := authorizeAtIdP(t, authorizeURL)
	tokens, err := p.ExchangeCode(context.Background(), callback.Query().Get("code"), pkce.Verifier)
	if err != nil {
		t.Fatalf("%s ExchangeCode: %v", p.ID(), err)
	}
	info, err := p.FetchUserInfo(context.Background(), tokens)
	if err != nil {
		t.Fatalf("%s FetchUserInfo: %v", p.ID(), err)
	}
	return info
}

// envelopeField decodes one string field from a sealed token envelope.
func envelopeField(t *testing.T, raw, field string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("decode token envelope: %v", err)
	}
	value, _ := doc[field].(string)
	if value == "" {
		t.Fatalf("token envelope missing %q", field)
	}
	return value
}

func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	if body.Code != want {
		t.Fatalf("error code = %q; want %q (%s)", body.Code, want, rec.Body.String())
	}
}

func microsoftEndpoints(idp *oauthmock.MicrosoftIdP) oauth.EndpointOverride {
	return oauth.EndpointOverride{
		AuthorizeURL: idp.Server.URL + "/authorize",
		TokenURL:     idp.Server.URL + "/token",
		UserInfoURL:  idp.Server.URL + "/userinfo",
		JWKSURL:      idp.Server.URL + "/keys",
	}
}

func facebookEndpoints(idp *oauthmock.FacebookIdP) oauth.EndpointOverride {
	return oauth.EndpointOverride{
		AuthorizeURL: idp.Server.URL + "/v19.0/dialog/oauth",
		TokenURL:     idp.Server.URL + "/v19.0/oauth/access_token",
		UserInfoURL:  idp.Server.URL + "/v19.0/me",
		DebugURL:     idp.Server.URL + "/debug_token",
	}
}

func TestE2E_FullBrowserOAuthJourneys(t *testing.T) {
	t.Parallel()

	// Journeys 1-6 and 8-13 register a production adapter pointed at a loopback
	// IdP (tests/oauthmock), so authorize -> callback -> exchange -> identity ->
	// link -> session runs through the real adapter; a failure there is an
	// adapter regression, not fixture drift. Journey 7 drives the store directly
	// and covers the delete cascade, not an adapter.

	// 1. Journey 1: Microsoft Enterprise Login
	t.Run("journey 1: microsoft enterprise login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		const tenant = "22222222-2222-2222-2222-222222222222"
		idp, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer idp.Close()
		idp.TenantID = tenant
		idp.OID = "ms-user-oid-1"
		idp.Subject = "ms-user-sub-1"
		idp.Email = "corp-user@example.com"

		provider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       idp.ClientID,
			ClientSecret:   idp.ClientSecret,
			RedirectURI:    cfg.BaseURL + "/auth/oauth/microsoft/callback",
			Tenant:         tenant,
			TrustedTenants: []string{tenant},
		}, oauth.WithEndpoints(microsoftEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register microsoft adapter: %v", err)
		}

		// Fails if the adapter stops verifying the id_token signature, keys
		// the identity on oid instead of sub, drops the tenant scope, or stops
		// inheriting verification from the admitted tenant.
		info := probeIdentity(t, provider)
		if info.ProviderUserID != "ms-user-sub-1" {
			t.Fatalf("adapter ProviderUserID = %q; want %q", info.ProviderUserID, "ms-user-sub-1")
		}
		if info.ProviderTenantID != tenant {
			t.Fatalf("adapter ProviderTenantID = %q; want %q", info.ProviderTenantID, tenant)
		}
		if !info.EmailVerified {
			t.Fatal("adapter EmailVerified = false for a verified-tenant id_token")
		}
		if tid, _ := info.RawClaims["tid"].(string); tid != tenant {
			t.Fatalf("adapter RawClaims[tid] = %v; want %q", info.RawClaims["tid"], tenant)
		}

		authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "?redirect_url=/welcome")
		if authorizeURL.Host != idp.Server.Listener.Addr().String() {
			t.Fatalf("authorize host = %q; want loopback IdP %q", authorizeURL.Host, idp.Server.Listener.Addr())
		}
		callback := authorizeAtIdP(t, authorizeURL)
		cbRec := callbackOAuth(t, h, callback, cookies...)
		if cbRec.Code != http.StatusFound {
			t.Fatalf("callback = %d (%s); want 302", cbRec.Code, cbRec.Body.String())
		}
		if got := cbRec.Header().Get("Location"); got != "/welcome" {
			t.Fatalf("callback redirect = %q; want %q", got, "/welcome")
		}
		sessionCookie := responseCookie(t, cbRec, cfg.SessionCookieName)
		if sessionCookie == nil {
			t.Fatal("expected session cookie set on successful callback")
		}

		sessReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
		sessReq.AddCookie(sessionCookie)
		sessRec := httptest.NewRecorder()
		h.ServeHTTP(sessRec, sessReq)
		if sessRec.Code != http.StatusOK {
			t.Fatalf("GET /auth/session = %d (%s); want 200", sessRec.Code, sessRec.Body.String())
		}
		var sessResp struct {
			Session struct {
				SessionID string `json:"session_id"`
			} `json:"session"`
		}
		_ = json.Unmarshal(sessRec.Body.Bytes(), &sessResp)
		if sessResp.Session.SessionID == "" {
			t.Fatal("expected non-empty session_id from /auth/session")
		}

		var user db.User
		if err := dbConn.Where("email = ?", "corp-user@example.com").First(&user).Error; err != nil {
			t.Fatalf("user record not found: %v", err)
		}
		if !user.EmailVerified {
			t.Fatal("created user must inherit the verified tenant's email_verified")
		}
		var link db.OAuthAccount
		if err := dbConn.Where("provider_id = ? AND user_id = ?", "microsoft", user.ID).First(&link).Error; err != nil {
			t.Fatalf("link record not found: %v", err)
		}
		if link.ProviderUserID != "ms-user-sub-1" {
			t.Fatalf("link provider_user_id = %q; want %q", link.ProviderUserID, "ms-user-sub-1")
		}
		if link.ProviderTenantID != tenant {
			t.Fatalf("link provider_tenant_id = %q; want %q", link.ProviderTenantID, tenant)
		}
	})

	// 2. Journey 2: Discord Account Linking to existing active authenticated session
	t.Run("journey 2: discord account linking to active session", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		msIdP, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer msIdP.Close()
		msIdP.TenantID = oauth.MicrosoftConsumerTenantGUID
		msIdP.OID = "ms-user-oid-2"
		msIdP.Subject = "ms-user-sub-2"
		msIdP.Email = "existing-user@example.com"

		msProvider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       msIdP.ClientID,
			ClientSecret:   msIdP.ClientSecret,
			RedirectURI:    cfg.BaseURL + "/auth/oauth/microsoft/callback",
			TrustedTenants: []string{msIdP.TenantID},
		}, oauth.WithEndpoints(microsoftEndpoints(msIdP)))

		discordIdP := oauthmock.NewDiscordIdP(cfg.BaseURL + "/auth/oauth/discord/callback")
		defer discordIdP.Close()
		discordIdP.UserID = "discord-snowflake-888"
		discordIdP.Email = "existing-user@example.com"

		discordProvider := oauth.NewDiscordProvider(config.DiscordConfig{
			ClientID:     discordIdP.ClientID,
			ClientSecret: discordIdP.ClientSecret,
			RedirectURI:  cfg.BaseURL + "/auth/oauth/discord/callback",
		}, oauth.WithEndpoints(oauth.EndpointOverride{
			AuthorizeURL: discordIdP.Server.URL + "/oauth2/authorize",
			TokenURL:     discordIdP.Server.URL + "/api/v10/oauth2/token",
			UserInfoURL:  discordIdP.Server.URL + "/api/v10/users/@me",
		}))

		for _, p := range []oauth.Provider{msProvider, discordProvider} {
			if err := (*pReg).Register(p); err != nil {
				t.Fatalf("register %s adapter: %v", p.ID(), err)
			}
		}

		// Create the user and active session through a real Microsoft login.
		authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		sessionCookie := responseCookie(t, cbRec, cfg.SessionCookieName)
		if sessionCookie == nil {
			t.Fatalf("microsoft login failed, no session cookie: %d (%s)", cbRec.Code, cbRec.Body.String())
		}

		// Explicit link intent: the state carries the signed-in user and the
		// callback must resolve the same live session.
		linkAuthorizeURL, linkCookies := initiateOAuth(t, h, "discord", "?link=true", sessionCookie)
		if linkAuthorizeURL.Host != discordIdP.Server.Listener.Addr().String() {
			t.Fatalf("discord authorize host = %q; want loopback IdP %q", linkAuthorizeURL.Host, discordIdP.Server.Listener.Addr())
		}
		linkCallback := authorizeAtIdP(t, linkAuthorizeURL)
		linkRec := callbackOAuth(t, h, linkCallback, append(linkCookies, sessionCookie)...)
		if linkRec.Code != http.StatusFound {
			t.Fatalf("discord link callback = %d (%s); want 302", linkRec.Code, linkRec.Body.String())
		}

		var user db.User
		if err := dbConn.Where("email = ?", "existing-user@example.com").First(&user).Error; err != nil {
			t.Fatalf("user not found: %v", err)
		}
		var links []db.OAuthAccount
		if err := dbConn.Where("user_id = ?", user.ID).Find(&links).Error; err != nil {
			t.Fatalf("query links: %v", err)
		}
		if len(links) != 2 {
			t.Fatalf("expected 2 linked identities (microsoft and discord), got %d", len(links))
		}
		gotKeys := map[string]string{}
		gotTenants := map[string]string{}
		for _, l := range links {
			gotKeys[l.ProviderID] = l.ProviderUserID
			gotTenants[l.ProviderID] = l.ProviderTenantID
		}
		if gotKeys["microsoft"] != "ms-user-sub-2" {
			t.Fatalf("microsoft link provider_user_id = %q; want %q", gotKeys["microsoft"], "ms-user-sub-2")
		}
		if gotTenants["microsoft"] != oauth.MicrosoftConsumerTenantGUID {
			t.Fatalf("microsoft link provider_tenant_id = %q; want the consumer tenant %q", gotTenants["microsoft"], oauth.MicrosoftConsumerTenantGUID)
		}
		if gotTenants["discord"] != "" {
			t.Fatalf("discord link provider_tenant_id = %q; want no tenant scope", gotTenants["discord"])
		}
		if gotKeys["discord"] != "discord-snowflake-888" {
			t.Fatalf("discord link provider_user_id = %q; want %q", gotKeys["discord"], "discord-snowflake-888")
		}
	})

	// 3. Journey 3: X (Twitter) missing email fail closed + returning user login
	t.Run("journey 3: x missing email fail closed and returning user login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		idp := oauthmock.NewXIdP(cfg.BaseURL + "/auth/oauth/x/callback")
		defer idp.Close()
		idp.UserID = "x-user-snowflake-333"

		provider := oauth.NewXProvider(config.XConfig{
			ClientID:     idp.ClientID,
			ClientSecret: idp.ClientSecret,
			RedirectURI:  cfg.BaseURL + "/auth/oauth/x/callback",
		}, oauth.WithEndpoints(oauth.EndpointOverride{
			AuthorizeURL: idp.Server.URL + "/i/oauth2/authorize",
			TokenURL:     idp.Server.URL + "/2/oauth2/token",
			UserInfoURL:  idp.Server.URL + "/2/users/me",
		}))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register x adapter: %v", err)
		}

		// Fails if the adapter starts inventing an email or a verified flag for
		// a profile that has none.
		info := probeIdentity(t, provider)
		if info.ProviderUserID != "x-user-snowflake-333" {
			t.Fatalf("adapter ProviderUserID = %q; want %q", info.ProviderUserID, "x-user-snowflake-333")
		}
		if info.Email != "" || info.EmailVerified {
			t.Fatalf("adapter email = %q verified=%v; want empty and unverified", info.Email, info.EmailVerified)
		}

		authorizeURL, cookies := initiateOAuth(t, h, "x", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusBadRequest {
			t.Fatalf("unauthenticated X registration without email = %d (%s); want 400", cbRec.Code, cbRec.Body.String())
		}
		assertErrorCode(t, cbRec, "OAUTH_EMAIL_REQUIRED")

		var userCount, linkCount int64
		if err := dbConn.Model(&db.User{}).Count(&userCount).Error; err != nil || userCount != 0 {
			t.Fatalf("expected no users after failed registration, got count=%d err=%v", userCount, err)
		}
		if err := dbConn.Model(&db.OAuthAccount{}).Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected no links after failed registration, got count=%d err=%v", linkCount, err)
		}

		// Pre-link the identity to prove returning users sign in without email.
		seededUser := db.User{
			ID:            uuid.New(),
			Email:         "seeded-x-owner@example.com",
			EmailVerified: true,
		}
		if err := dbConn.Create(&seededUser).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		if err := dbConn.Create(&db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         seededUser.ID,
			ProviderID:     "x",
			ProviderUserID: "x-user-snowflake-333",
			Email:          "seeded-x-owner@example.com",
			Verified:       true,
		}).Error; err != nil {
			t.Fatalf("seed link: %v", err)
		}

		retAuthorizeURL, retCookies := initiateOAuth(t, h, "x", "")
		retRec := callbackOAuth(t, h, authorizeAtIdP(t, retAuthorizeURL), retCookies...)
		if retRec.Code != http.StatusFound {
			t.Fatalf("returning X callback = %d (%s); want 302", retRec.Code, retRec.Body.String())
		}
		if responseCookie(t, retRec, cfg.SessionCookieName) == nil {
			t.Fatal("expected session cookie for returning user")
		}

		// The login stores sealed envelopes, not provider plaintext, and the
		// access envelope names the keyring's active key.
		var link db.OAuthAccount
		if err := dbConn.Where("provider_id = ? AND user_id = ?", "x", seededUser.ID).First(&link).Error; err != nil {
			t.Fatalf("load x link: %v", err)
		}
		if link.AccessTokenCiphertext == "" || link.RefreshTokenCiphertext == "" {
			t.Fatal("returning login must store sealed access and refresh envelopes")
		}
		if strings.Contains(link.AccessTokenCiphertext, "x-idp-access-token") ||
			strings.Contains(link.RefreshTokenCiphertext, "x-idp-refresh-token") {
			t.Fatal("oauth_accounts columns must not hold provider plaintext tokens")
		}
		ring, err := crypto.ParseKeyring(cfg.OAuth.TokenKEK)
		if err != nil {
			t.Fatalf("ParseKeyring: %v", err)
		}
		if got, want := envelopeField(t, link.AccessTokenCiphertext, "kid"), ring.ActiveKeyID(); got != want {
			t.Fatalf("access envelope kid = %q; want the active key %q", got, want)
		}
		sealer := crypto.NewTokenSealer(ring)
		issuedRefresh, err := sealer.OpenRefreshToken("x", link.ID.String(), link.RefreshTokenCiphertext)
		if err != nil {
			t.Fatalf("open issued refresh token: %v", err)
		}

		// Force expiry: the next accessor call must renew exactly once and
		// rewrite the stored pair with the rotated grant.
		if err := dbConn.Model(&db.OAuthAccount{}).Where("id = ?", link.ID).
			Update("token_expires_at", time.Now().Add(-time.Hour)).Error; err != nil {
			t.Fatalf("expire x link: %v", err)
		}
		accessor := oauth.NewServiceWithRegistry(gormstore.New(dbConn), session.NewService(dbConn, &cfg), *pReg, &cfg)
		token, err := accessor.LinkedAccountToken(context.Background(), seededUser.ID, "x")
		if err != nil {
			t.Fatalf("LinkedAccountToken: %v", err)
		}
		if token.AccessToken != "x-idp-access-token" || !strings.EqualFold(token.TokenType, "bearer") {
			t.Fatalf("accessor token = %q %q; want the provider access token and a bearer type", token.AccessToken, token.TokenType)
		}
		if token.RefreshToken != "" {
			t.Fatal("accessor must not return the refresh token")
		}
		if got := idp.RefreshCalls.Load(); got != 1 {
			t.Fatalf("refresh POSTs at the IdP = %d; want exactly 1", got)
		}

		var rotated db.OAuthAccount
		if err := dbConn.Where("id = ?", link.ID).First(&rotated).Error; err != nil {
			t.Fatalf("reload x link: %v", err)
		}
		if rotated.AccessTokenCiphertext == link.AccessTokenCiphertext ||
			rotated.RefreshTokenCiphertext == link.RefreshTokenCiphertext {
			t.Fatal("refresh must rewrite both stored envelopes")
		}
		if rotated.TokenExpiresAt == nil || !rotated.TokenExpiresAt.After(time.Now()) {
			t.Fatalf("refreshed expiry = %v; want a future timestamp", rotated.TokenExpiresAt)
		}
		rotatedRefresh, err := sealer.OpenRefreshToken("x", link.ID.String(), rotated.RefreshTokenCiphertext)
		if err != nil {
			t.Fatalf("open rotated refresh token: %v", err)
		}
		if rotatedRefresh == issuedRefresh {
			t.Fatal("refresh must rotate the stored refresh token")
		}
	})

	// 4. Journey 4: Facebook first-time signup with a provider-supplied email
	t.Run("journey 4: facebook login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		idp := oauthmock.NewFacebookIdP(cfg.BaseURL + "/auth/oauth/facebook/callback")
		defer idp.Close()
		idp.UserID = "fb-app-scoped-uid-444"
		idp.Email = "fb-user@example.com"

		provider := oauth.NewFacebookProvider(config.FacebookConfig{
			AppID:       idp.AppID,
			AppSecret:   idp.AppSecret,
			RedirectURI: cfg.BaseURL + "/auth/oauth/facebook/callback",
		}, oauth.FacebookEndpoints(facebookEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register facebook adapter: %v", err)
		}

		// Fails if the adapter stops validating the token via /debug_token,
		// stops sending appsecret_proof to /me, or claims the Graph address is
		// attested when Meta documents no such guarantee.
		info := probeIdentity(t, provider)
		if info.ProviderUserID != "fb-app-scoped-uid-444" {
			t.Fatalf("adapter ProviderUserID = %q; want %q", info.ProviderUserID, "fb-app-scoped-uid-444")
		}
		if info.Email != "fb-user@example.com" || info.EmailVerified {
			t.Fatalf("adapter identity = %q verified=%v; want fb-user@example.com and unverified", info.Email, info.EmailVerified)
		}

		authorizeURL, cookies := initiateOAuth(t, h, "facebook", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusFound {
			t.Fatalf("facebook callback = %d (%s); want 302", cbRec.Code, cbRec.Body.String())
		}
		if responseCookie(t, cbRec, cfg.SessionCookieName) == nil {
			t.Fatal("expected session cookie set on Facebook callback")
		}

		var user db.User
		if err := dbConn.Where("email = ?", "fb-user@example.com").First(&user).Error; err != nil {
			t.Fatalf("user record not found: %v", err)
		}
		if user.EmailVerified {
			t.Fatal("an unverified Graph email must not create a verified user")
		}
		var linkCount int64
		if err := dbConn.Model(&db.OAuthAccount{}).Where("provider_id = ?", "facebook").Count(&linkCount).Error; err != nil || linkCount != 1 {
			t.Fatalf("expected 1 unverified facebook link for the first signup, got count=%d err=%v", linkCount, err)
		}
		var fbLink db.OAuthAccount
		if err := dbConn.Where("provider_id = ?", "facebook").First(&fbLink).Error; err != nil {
			t.Fatalf("load facebook link: %v", err)
		}
		if fbLink.Verified {
			t.Fatal("unverified Graph email must persist a verified=false link")
		}

		var sessCount int64
		if err := dbConn.Model(&db.Session{}).Where("user_id = ?", user.ID).Count(&sessCount).Error; err != nil || sessCount != 1 {
			t.Fatalf("expected 1 session row for facebook user, got count=%d, err=%v", sessCount, err)
		}
	})

	// 5. Journey 5: an unverified provider email never merges into an existing account
	t.Run("journey 5: facebook unverified email cannot merge", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		idp := oauthmock.NewFacebookIdP(cfg.BaseURL + "/auth/oauth/facebook/callback")
		defer idp.Close()
		idp.UserID = "fb-unverified-uid-555"
		idp.Email = "squatted@example.com"

		provider := oauth.NewFacebookProvider(config.FacebookConfig{
			AppID:       idp.AppID,
			AppSecret:   idp.AppSecret,
			RedirectURI: cfg.BaseURL + "/auth/oauth/facebook/callback",
		}, oauth.FacebookEndpoints(facebookEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register facebook adapter: %v", err)
		}

		owner := db.User{
			ID:            uuid.New(),
			Email:         "squatted@example.com",
			PasswordHash:  "existing-password-hash",
			EmailVerified: true,
		}
		if err := dbConn.Create(&owner).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}

		// Fails if the adapter starts treating the Graph address as attested by
		// default: the merge gate below must see the false the adapter produces.
		info := probeIdentity(t, provider)
		if info.Email != "squatted@example.com" || info.EmailVerified {
			t.Fatalf("adapter identity = %q verified=%v; want non-empty unverified email", info.Email, info.EmailVerified)
		}

		authorizeURL, cookies := initiateOAuth(t, h, "facebook", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusBadRequest {
			t.Fatalf("unverified merge callback = %d (%s); want 400", cbRec.Code, cbRec.Body.String())
		}
		assertErrorCode(t, cbRec, "OAUTH_EMAIL_UNVERIFIED")

		var linkCount int64
		if err := dbConn.Model(&db.OAuthAccount{}).Where("provider_id = ?", "facebook").Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected no facebook link after unverified merge, got count=%d err=%v", linkCount, err)
		}
		var got db.User
		if err := dbConn.Where("id = ?", owner.ID).First(&got).Error; err != nil {
			t.Fatalf("owner disappeared: %v", err)
		}
		if got.PasswordHash != "existing-password-hash" {
			t.Fatalf("owner password hash changed to %q", got.PasswordHash)
		}
		var sessCount int64
		if err := dbConn.Model(&db.Session{}).Where("user_id = ?", owner.ID).Count(&sessCount).Error; err != nil || sessCount != 0 {
			t.Fatalf("expected no session for rejected merge, got count=%d err=%v", sessCount, err)
		}
	})

	// 6. Journey 6: Microsoft untrusted tenant is rejected by the allowlist
	t.Run("journey 6: microsoft untrusted tenant rejected", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		const trustedTenant = "44444444-4444-4444-4444-444444444444"
		const attackerTenant = "55555555-5555-5555-5555-555555555555"
		idp, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer idp.Close()
		idp.TenantID = attackerTenant
		idp.OID = "ms-attacker-oid-666"
		idp.Subject = "ms-attacker-sub-666"
		idp.Email = "victim@example.com"
		idp.AttestDomain() // domain attestation must not override the allowlist
		provider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       idp.ClientID,
			ClientSecret:   idp.ClientSecret,
			RedirectURI:    cfg.BaseURL + "/auth/oauth/microsoft/callback",
			TrustedTenants: []string{trustedTenant},
		}, oauth.WithEndpoints(microsoftEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register microsoft adapter: %v", err)
		}

		victim := db.User{
			ID:            uuid.New(),
			Email:         "victim@example.com",
			PasswordHash:  "victim-password-hash",
			EmailVerified: true,
		}
		if err := dbConn.Create(&victim).Error; err != nil {
			t.Fatalf("seed victim: %v", err)
		}

		// Microsoft separates tenant admission from email attestation: an
		// unlisted tenant is rejected through untrusted_tenant even when it
		// presents xms_edov, so that marker is the gate this journey asserts.
		info := probeIdentity(t, provider)
		if untrusted, _ := info.RawClaims["untrusted_tenant"].(bool); !untrusted {
			t.Fatalf("adapter RawClaims[untrusted_tenant] = %v; want true", info.RawClaims["untrusted_tenant"])
		}
		if info.ProviderUserID != "ms-attacker-sub-666" {
			t.Fatalf("adapter ProviderUserID = %q; want %q", info.ProviderUserID, "ms-attacker-sub-666")
		}
		if info.ProviderTenantID != attackerTenant {
			t.Fatalf("adapter ProviderTenantID = %q; want the token tenant %q", info.ProviderTenantID, attackerTenant)
		}

		authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusBadRequest {
			t.Fatalf("untrusted tenant callback = %d (%s); want 400", cbRec.Code, cbRec.Body.String())
		}
		assertErrorCode(t, cbRec, "OAUTH_TENANT_INVALID")

		var linkCount int64
		if err := dbConn.Model(&db.OAuthAccount{}).Where("provider_id = ?", "microsoft").Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected no microsoft link for untrusted tenant, got count=%d err=%v", linkCount, err)
		}
		var got db.User
		if err := dbConn.Where("id = ?", victim.ID).First(&got).Error; err != nil {
			t.Fatalf("victim disappeared: %v", err)
		}
		if got.PasswordHash != "victim-password-hash" {
			t.Fatalf("victim password hash changed to %q", got.PasswordHash)
		}
	})

	// 7. Journey 7: Hard delete cascade
	t.Run("journey 7: hard delete cascade deletes oauth_accounts", func(t *testing.T) {
		_, dbConn, _, _ := setupOAuthE2EStack(t)
		ctx := context.Background()
		store := gormstore.New(dbConn)

		u := db.User{
			ID:            uuid.New(),
			Email:         "cascade-test@example.com",
			EmailVerified: true,
		}
		if err := store.Users().Create(ctx, &u); err != nil {
			t.Fatalf("create user failed: %v", err)
		}
		if err := store.OAuthAccounts().Create(ctx, &db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         u.ID,
			ProviderID:     "microsoft",
			ProviderUserID: "ms-cascade-sub",
			Email:          u.Email,
			Verified:       true,
		}); err != nil {
			t.Fatalf("create link failed: %v", err)
		}
		if err := dbConn.Create(&db.Session{
			ID:                uuid.New(),
			UserID:            u.ID,
			IDHash:            uuid.NewString(),
			SessionType:       db.SessionTypeCookie,
			LastActiveAt:      time.Now().UTC(),
			AbsoluteExpiresAt: time.Now().UTC().Add(time.Hour),
		}).Error; err != nil {
			t.Fatalf("create session failed: %v", err)
		}

		var count int64
		if err := dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("expected 1 link row, got count=%d, err=%v", count, err)
		}
		if err := dbConn.Model(&db.Session{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("expected 1 session row, got count=%d, err=%v", count, err)
		}

		// Delete through the product path, not raw SQL.
		if err := store.Users().Delete(ctx, u.ID); err != nil {
			t.Fatalf("delete user failed: %v", err)
		}

		if _, err := store.Users().GetByID(ctx, u.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("expected user to be gone, got err=%v", err)
		}
		if err := dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("expected 0 link rows after cascade delete, got count=%d, err=%v", count, err)
		}
		if err := dbConn.Model(&db.Session{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("expected 0 session rows after cascade delete, got count=%d, err=%v", count, err)
		}
	})

	// 8. Journey 8: a Microsoft tenant the allowlist admits but whose token
	// carries no domain attestation
	t.Run("journey 8: microsoft admitted tenant without attestation", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		const tenant = "66666666-6666-6666-6666-666666666666"
		idp, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer idp.Close()
		idp.TenantID = tenant
		idp.OID = "ms-unattested-oid-8"
		idp.Subject = "ms-unattested-sub-8"
		idp.Email = "squatted-ms@example.com"

		// The authority stays "common" while the allowlist admits this tenant,
		// so admission is real and attestation is absent: exactly the pair the
		// nOauth gate has to keep apart.
		provider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       idp.ClientID,
			ClientSecret:   idp.ClientSecret,
			RedirectURI:    cfg.BaseURL + "/auth/oauth/microsoft/callback",
			TrustedTenants: []string{tenant},
		}, oauth.WithEndpoints(microsoftEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register microsoft adapter: %v", err)
		}

		// Fails if tenant admission is reported as address attestation.
		info := probeIdentity(t, provider)
		if info.EmailVerified {
			t.Fatal("an admitted tenant must not attest the address without xms_edov")
		}
		if untrusted, _ := info.RawClaims["untrusted_tenant"].(bool); untrusted {
			t.Fatal("the allowlisted tenant must be admitted")
		}

		owner := db.User{
			ID:            uuid.New(),
			Email:         "squatted-ms@example.com",
			PasswordHash:  "squat-password-hash",
			EmailVerified: true,
		}
		if err := dbConn.Create(&owner).Error; err != nil {
			t.Fatalf("seed owner: %v", err)
		}

		authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusBadRequest {
			t.Fatalf("unattested merge callback = %d (%s); want 400", cbRec.Code, cbRec.Body.String())
		}
		assertErrorCode(t, cbRec, "OAUTH_EMAIL_UNVERIFIED")
		var linkCount int64
		if err := dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", owner.ID).Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected no link on the squatted account, got count=%d err=%v", linkCount, err)
		}

		// Login still succeeds on an address nobody owns: an admitted but
		// unattested tenant registers unverified rather than failing.
		idp.Email = "fresh-ms@example.com"
		freshAuthorizeURL, freshCookies := initiateOAuth(t, h, "microsoft", "")
		freshRec := callbackOAuth(t, h, authorizeAtIdP(t, freshAuthorizeURL), freshCookies...)
		if freshRec.Code != http.StatusFound {
			t.Fatalf("unattested registration = %d (%s); want 302", freshRec.Code, freshRec.Body.String())
		}
		if responseCookie(t, freshRec, cfg.SessionCookieName) == nil {
			t.Fatal("expected a session cookie for the unattested registration")
		}
		var fresh db.User
		if err := dbConn.Where("email = ?", "fresh-ms@example.com").First(&fresh).Error; err != nil {
			t.Fatalf("load unattested user: %v", err)
		}
		if fresh.EmailVerified {
			t.Fatal("an unattested login must not verify the address")
		}
		var link db.OAuthAccount
		if err := dbConn.Where("provider_id = ? AND user_id = ?", "microsoft", fresh.ID).First(&link).Error; err != nil {
			t.Fatalf("load unattested link: %v", err)
		}
		if link.Verified {
			t.Fatal("an unattested login must persist a verified=false link")
		}
	})

	// 9. Journey 9: Microsoft token without id_token under the multi-tenant default
	t.Run("journey 9: microsoft userinfo-only rejected without a pinned tenant", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		idp, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer idp.Close()
		idp.OmitIDToken = true
		idp.Subject = "ms-userinfo-sub-9"
		idp.OID = "ms-userinfo-oid-9"
		idp.Email = "userinfo-only@example.com"

		// The default authority is common. /oidc/userinfo is unsigned and names
		// no tenant, so no tenant-qualified key can be formed: the adapter fails
		// before the request instead of storing a tenant-blind identity. The
		// envelope masks CodeInvalidConfig to INTERNAL_ERROR, so the 500 plus the
		// zero rows below are the observable fail-closed signal.
		provider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:     idp.ClientID,
			ClientSecret: idp.ClientSecret,
			RedirectURI:  cfg.BaseURL + "/auth/oauth/microsoft/callback",
		}, oauth.WithEndpoints(microsoftEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register microsoft adapter: %v", err)
		}

		authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusInternalServerError {
			t.Fatalf("userinfo-only callback = %d (%s); want 500", cbRec.Code, cbRec.Body.String())
		}
		assertErrorCode(t, cbRec, "INTERNAL_ERROR")

		var userCount, linkCount int64
		if err := dbConn.Model(&db.User{}).Count(&userCount).Error; err != nil || userCount != 0 {
			t.Fatalf("expected no user for the rejected userinfo login, got count=%d err=%v", userCount, err)
		}
		if err := dbConn.Model(&db.OAuthAccount{}).Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected no link for the rejected userinfo login, got count=%d err=%v", linkCount, err)
		}
	})

	// 9b. Journey 9b: Microsoft userinfo-only under a pinned tenant
	t.Run("journey 9b: microsoft userinfo-only uses the pinned tenant", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		const tenant = "88888888-8888-8888-8888-888888888888"
		idp, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer idp.Close()
		idp.OmitIDToken = true
		idp.TenantID = tenant
		idp.Subject = "ms-userinfo-sub-9b"
		idp.OID = "ms-userinfo-oid-9b"
		idp.Email = "userinfo-pinned@example.com"

		// A pinned authority names the tenant in configuration, so the unsigned
		// userinfo payload can still be keyed by it. Fails if the identity is
		// stored without a tenant or if the /userinfo payload is trusted to name
		// one.
		provider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:     idp.ClientID,
			ClientSecret: idp.ClientSecret,
			RedirectURI:  cfg.BaseURL + "/auth/oauth/microsoft/callback",
			Tenant:       tenant,
		}, oauth.WithEndpoints(microsoftEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register microsoft adapter: %v", err)
		}

		info := probeIdentity(t, provider)
		if info.ProviderUserID != "ms-userinfo-sub-9b" {
			t.Fatalf("userinfo ProviderUserID = %q; want the sub %q", info.ProviderUserID, "ms-userinfo-sub-9b")
		}
		if info.ProviderTenantID != tenant {
			t.Fatalf("userinfo ProviderTenantID = %q; want the configured tenant %q", info.ProviderTenantID, tenant)
		}
		if info.EmailVerified {
			t.Fatal("userinfo alone cannot attest nOauth domain ownership")
		}

		authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusFound {
			t.Fatalf("userinfo-only callback = %d (%s); want 302", cbRec.Code, cbRec.Body.String())
		}
		if responseCookie(t, cbRec, cfg.SessionCookieName) == nil {
			t.Fatal("expected a session cookie for the pinned userinfo login")
		}

		var user db.User
		if err := dbConn.Where("email = ?", "userinfo-pinned@example.com").First(&user).Error; err != nil {
			t.Fatalf("load pinned userinfo user: %v", err)
		}
		if user.EmailVerified {
			t.Fatal("userinfo-only login must not verify the address")
		}
		var link db.OAuthAccount
		if err := dbConn.Where("provider_id = ? AND user_id = ?", "microsoft", user.ID).First(&link).Error; err != nil {
			t.Fatalf("load pinned userinfo link: %v", err)
		}
		if link.ProviderUserID != "ms-userinfo-sub-9b" || link.ProviderTenantID != tenant {
			t.Fatalf("link key = (%q, %q); want (%q, %q)", link.ProviderTenantID, link.ProviderUserID, tenant, "ms-userinfo-sub-9b")
		}
	})

	// 10. Journey 10: the same missing id_token under a tenant-scoped deployment
	t.Run("journey 10: microsoft userinfo-only fails closed when tenant scoped", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		const tenant = "77777777-7777-7777-7777-777777777777"
		idp, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer idp.Close()
		idp.OmitIDToken = true
		idp.TenantID = tenant
		idp.Email = "scoped-userinfo@example.com"

		provider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:       idp.ClientID,
			ClientSecret:   idp.ClientSecret,
			RedirectURI:    cfg.BaseURL + "/auth/oauth/microsoft/callback",
			TrustedTenants: []string{tenant},
		}, oauth.WithEndpoints(microsoftEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register microsoft adapter: %v", err)
		}

		// Fails if the adapter starts trusting an unsigned /userinfo payload
		// under a deployment that restricts tenants. The envelope masks the
		// CodeInvalidConfig detail to INTERNAL_ERROR, so the 500 plus the zero
		// rows below are the observable fail-closed signal.
		authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "")
		cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		if cbRec.Code != http.StatusInternalServerError {
			t.Fatalf("tenant-scoped userinfo-only callback = %d (%s); want 500", cbRec.Code, cbRec.Body.String())
		}
		assertErrorCode(t, cbRec, "INTERNAL_ERROR")

		var userCount, linkCount int64
		if err := dbConn.Model(&db.User{}).Count(&userCount).Error; err != nil || userCount != 0 {
			t.Fatalf("expected no user for the rejected userinfo login, got count=%d err=%v", userCount, err)
		}
		if err := dbConn.Model(&db.OAuthAccount{}).Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected no link for the rejected userinfo login, got count=%d err=%v", linkCount, err)
		}
	})

	// 11. Journey 11: /debug_token verdicts that do not name this app
	t.Run("journey 11: facebook confused deputy token rejected", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			debug oauthmock.DebugToken
		}{
			{name: "foreign app_id", debug: oauthmock.DebugToken{AppID: "fb-someone-elses-app", IsValid: true}},
			{name: "invalid token", debug: oauthmock.DebugToken{IsValid: false}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

				idp := oauthmock.NewFacebookIdP(cfg.BaseURL + "/auth/oauth/facebook/callback")
				defer idp.Close()
				idp.Email = "confused-deputy@example.com"
				idp.Debug = tc.debug

				provider := oauth.NewFacebookProvider(config.FacebookConfig{
					AppID:       idp.AppID,
					AppSecret:   idp.AppSecret,
					RedirectURI: cfg.BaseURL + "/auth/oauth/facebook/callback",
				}, oauth.FacebookEndpoints(facebookEndpoints(idp)))
				if err := (*pReg).Register(provider); err != nil {
					t.Fatalf("register facebook adapter: %v", err)
				}

				authorizeURL, cookies := initiateOAuth(t, h, "facebook", "")
				cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
				if cbRec.Code != http.StatusBadGateway {
					t.Fatalf("confused-deputy callback = %d (%s); want 502", cbRec.Code, cbRec.Body.String())
				}
				assertErrorCode(t, cbRec, "OAUTH_TOKEN_EXCHANGE_FAILED")

				var userCount, linkCount int64
				if err := dbConn.Model(&db.User{}).Count(&userCount).Error; err != nil || userCount != 0 {
					t.Fatalf("expected no user, got count=%d err=%v", userCount, err)
				}
				if err := dbConn.Model(&db.OAuthAccount{}).Count(&linkCount).Error; err != nil || linkCount != 0 {
					t.Fatalf("expected no link, got count=%d err=%v", linkCount, err)
				}
			})
		}
	})

	// 12. Journey 12: Microsoft id_token rejections
	t.Run("journey 12: microsoft invalid id_token rejected", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			fault      oauthmock.IDTokenFault
			wantStatus int
			wantCode   string
		}{
			{name: "bad issuer", fault: oauthmock.FaultBadIssuer, wantStatus: http.StatusBadRequest, wantCode: "OAUTH_TENANT_INVALID"},
			{name: "bad audience", fault: oauthmock.FaultBadAudience, wantStatus: http.StatusUnauthorized, wantCode: "OAUTH_ID_TOKEN_INVALID"},
			{name: "bad signature", fault: oauthmock.FaultBadSignature, wantStatus: http.StatusUnauthorized, wantCode: "OAUTH_ID_TOKEN_INVALID"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

				const tenant = "88888888-8888-8888-8888-888888888888"
				idp, err := oauthmock.NewMicrosoftIdP(cfg.BaseURL + "/auth/oauth/microsoft/callback")
				if err != nil {
					t.Fatalf("NewMicrosoftIdP: %v", err)
				}
				defer idp.Close()
				idp.TenantID = tenant
				idp.Email = "bad-token@example.com"
				idp.Fault = tc.fault

				provider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
					ClientID:       idp.ClientID,
					ClientSecret:   idp.ClientSecret,
					RedirectURI:    cfg.BaseURL + "/auth/oauth/microsoft/callback",
					Tenant:         tenant,
					TrustedTenants: []string{tenant},
				}, oauth.WithEndpoints(microsoftEndpoints(idp)))
				if err := (*pReg).Register(provider); err != nil {
					t.Fatalf("register microsoft adapter: %v", err)
				}

				authorizeURL, cookies := initiateOAuth(t, h, "microsoft", "")
				cbRec := callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
				if cbRec.Code != tc.wantStatus {
					t.Fatalf("%s callback = %d (%s); want %d", tc.name, cbRec.Code, cbRec.Body.String(), tc.wantStatus)
				}
				assertErrorCode(t, cbRec, tc.wantCode)

				var userCount, linkCount int64
				if err := dbConn.Model(&db.User{}).Count(&userCount).Error; err != nil || userCount != 0 {
					t.Fatalf("expected no user, got count=%d err=%v", userCount, err)
				}
				if err := dbConn.Model(&db.OAuthAccount{}).Count(&linkCount).Error; err != nil || linkCount != 0 {
					t.Fatalf("expected no link, got count=%d err=%v", linkCount, err)
				}
			})
		}
	})

	// 13. Journey 13: an unverified link survives repeated logins and a
	// password-only signup, and is severed once the owner proves the mailbox
	t.Run("journey 13: unverified link is severed by a password reset", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t, func(c *config.Config) {
			c.DisableAsyncEmailDispatch = true
		})

		const addr = "pending-fb@example.com"
		idp := oauthmock.NewFacebookIdP(cfg.BaseURL + "/auth/oauth/facebook/callback")
		defer idp.Close()
		idp.UserID = "fb-pending-uid-13"
		idp.Email = addr

		provider := oauth.NewFacebookProvider(config.FacebookConfig{
			AppID:       idp.AppID,
			AppSecret:   idp.AppSecret,
			RedirectURI: cfg.BaseURL + "/auth/oauth/facebook/callback",
		}, oauth.FacebookEndpoints(facebookEndpoints(idp)))
		if err := (*pReg).Register(provider); err != nil {
			t.Fatalf("register facebook adapter: %v", err)
		}

		login := func() *httptest.ResponseRecorder {
			authorizeURL, cookies := initiateOAuth(t, h, "facebook", "")
			return callbackOAuth(t, h, authorizeAtIdP(t, authorizeURL), cookies...)
		}

		// Fails if the unverified link stops signing in its owner while the
		// account still holds no proven credential.
		for i := 1; i <= 2; i++ {
			rec := login()
			if rec.Code != http.StatusFound {
				t.Fatalf("unverified login %d = %d (%s); want 302", i, rec.Code, rec.Body.String())
			}
			if responseCookie(t, rec, cfg.SessionCookieName) == nil {
				t.Fatalf("unverified login %d set no session cookie", i)
			}
		}

		var user db.User
		if err := dbConn.Where("email = ?", addr).First(&user).Error; err != nil {
			t.Fatalf("load unverified owner: %v", err)
		}
		if user.EmailVerified {
			t.Fatal("an unverified provider address must not verify the account")
		}

		// Once password signup claims the address, the unverified link is deleted.
		authSvc, err := auth.New(cfg, dbConn, cfg.EmailHooks)
		if err != nil {
			t.Fatalf("auth.New: %v", err)
		}
		if _, _, err := authSvc.Signup(context.Background(), db.SignupRequest{Email: addr, Password: "CorrectHorseBattery9!"}); err != nil {
			t.Fatalf("password signup: %v", err)
		}

		var linkCount int64
		if err := dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", user.ID).Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected unverified link to be deleted on password signup, got count=%d err=%v", linkCount, err)
		}

		rec := login()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("login after password signup = %d (%s); want 400", rec.Code, rec.Body.String())
		}
		assertErrorCode(t, rec, "OAUTH_EMAIL_UNVERIFIED")

		// Re-seed an unverified link to explicitly test that ResetPassword purges it.
		if err := dbConn.Create(&db.OAuthAccount{
			UserID:         user.ID,
			ProviderID:     "facebook",
			ProviderUserID: idp.UserID,
			Email:          addr,
			Verified:       false,
		}).Error; err != nil {
			t.Fatalf("seed unverified link before reset: %v", err)
		}

		if err := dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", user.ID).Count(&linkCount).Error; err != nil || linkCount != 1 {
			t.Fatalf("expected 1 unverified link before password reset, got count=%d err=%v", linkCount, err)
		}

		// The reset token is delivered to the mailbox, so consuming it proves the
		// address: the account is claimed and the unverified link is deleted.
		resetToken, err := authSvc.RequestPasswordReset(context.Background(), db.PasswordResetRequest{Email: addr})
		if err != nil {
			t.Fatalf("RequestPasswordReset: %v", err)
		}
		if _, err := authSvc.ResetPassword(context.Background(), db.PasswordResetConfirmRequest{
			Token: resetToken, NewPassword: "OwnerPassword#2026!",
		}); err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}

		if err := dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", user.ID).Count(&linkCount).Error; err != nil || linkCount != 0 {
			t.Fatalf("expected the spent link to be deleted, got count=%d err=%v", linkCount, err)
		}

		rec = login()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("login through a spent unverified link = %d (%s); want 400", rec.Code, rec.Body.String())
		}
		assertErrorCode(t, rec, "OAUTH_EMAIL_UNVERIFIED")

		var sessCount int64
		if err := dbConn.Model(&db.Session{}).Where("user_id = ?", user.ID).Count(&sessCount).Error; err != nil || sessCount != 0 {
			t.Fatalf("expected no live session after the rejected login, got count=%d err=%v", sessCount, err)
		}
		var claimed db.User
		if err := dbConn.Where("id = ?", user.ID).First(&claimed).Error; err != nil {
			t.Fatalf("reload claimed user: %v", err)
		}
		if !claimed.EmailVerified || claimed.PasswordHash == "" {
			t.Fatalf("recovered account verified=%v hasPassword=%v; want a proven address with a password",
				claimed.EmailVerified, claimed.PasswordHash != "")
		}
	})
}
