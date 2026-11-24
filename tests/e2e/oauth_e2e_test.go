package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

func setupOAuthE2EStack(t *testing.T) (http.Handler, *gorm.DB, *oauth.Registry, config.Config) {
	t.Helper()
	name := fmt.Sprintf("file:oauth_e2e_%s?mode=memory&cache=shared", uuid.New().String())
	database, err := gorm.Open(sqlite.Open(name), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY, email TEXT COLLATE NOCASE UNIQUE NOT NULL, password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0, email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME, updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider_id VARCHAR(32) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME, updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_uid UNIQUE (provider_id, provider_user_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS verification_tokens (
		token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie', ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '', credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL, absolute_expires_at DATETIME NOT NULL, created_at DATETIME,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("schema error: %v", err)
	}
	// PRAGMA is per-connection while database/sql pools connections: pin the
	// pool so FK enforcement cannot pass or fail by connection reuse.
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := database.Exec("PRAGMA foreign_keys = ON;").Error; err != nil {
		t.Fatalf("enable foreign_keys: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"
	cfg.OAuth.StateSecret = "super-secret-e2e-state-signing-key-32b"
	cfg.SessionCookieSecure = false

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

	// Every journey registers a production adapter pointed at a loopback IdP
	// (tests/oauthmock), so authorize -> callback -> exchange -> identity ->
	// link -> session runs through the real adapter. A failure here is an
	// adapter regression, not fixture drift.

	// 1. Journey 1: Microsoft Enterprise Login
	t.Run("journey 1: microsoft enterprise login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		const tenant = "22222222-2222-2222-2222-222222222222"
		idp, err := oauthmock.NewMicrosoftIdP()
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
		// the identity on oid instead of sub, or trusts the attestation for
		// this tenant.
		info := probeIdentity(t, provider)
		if info.ProviderUserID != "ms-user-sub-1" {
			t.Fatalf("adapter ProviderUserID = %q; want %q", info.ProviderUserID, "ms-user-sub-1")
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
	})

	// 2. Journey 2: Discord Account Linking to existing active authenticated session
	t.Run("journey 2: discord account linking to active session", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		msIdP, err := oauthmock.NewMicrosoftIdP()
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer msIdP.Close()
		msIdP.TenantID = oauth.MicrosoftConsumerTenantGUID
		msIdP.OID = "ms-user-oid-2"
		msIdP.Subject = "ms-user-sub-2"
		msIdP.Email = "existing-user@example.com"

		msProvider := oauth.NewMicrosoftProvider(config.MicrosoftConfig{
			ClientID:     msIdP.ClientID,
			ClientSecret: msIdP.ClientSecret,
			RedirectURI:  cfg.BaseURL + "/auth/oauth/microsoft/callback",
		}, oauth.WithEndpoints(microsoftEndpoints(msIdP)))

		discordIdP := oauthmock.NewDiscordIdP()
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
		for _, l := range links {
			gotKeys[l.ProviderID] = l.ProviderUserID
		}
		if gotKeys["microsoft"] != "ms-user-sub-2" {
			t.Fatalf("microsoft link provider_user_id = %q; want %q", gotKeys["microsoft"], "ms-user-sub-2")
		}
		if gotKeys["discord"] != "discord-snowflake-888" {
			t.Fatalf("discord link provider_user_id = %q; want %q", gotKeys["discord"], "discord-snowflake-888")
		}
	})

	// 3. Journey 3: X (Twitter) missing email fail closed + returning user login
	t.Run("journey 3: x missing email fail closed and returning user login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		idp := oauthmock.NewXIdP()
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
	})

	// 4. Journey 4: Facebook first-time signup with a provider-supplied email
	t.Run("journey 4: facebook login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		idp := oauthmock.NewFacebookIdP()
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

		idp := oauthmock.NewFacebookIdP()
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
		idp, err := oauthmock.NewMicrosoftIdP()
		if err != nil {
			t.Fatalf("NewMicrosoftIdP: %v", err)
		}
		defer idp.Close()
		idp.TenantID = attackerTenant
		idp.OID = "ms-attacker-oid-666"
		idp.Subject = "ms-attacker-sub-666"
		idp.Email = "victim@example.com"
		idp.EDov = "1" // domain attestation must not override the allowlist

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
}
