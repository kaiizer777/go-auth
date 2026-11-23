package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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
		id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0, email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME, updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider_id VARCHAR(32) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
		created_at DATETIME, updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_uid UNIQUE (provider_id, provider_user_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, id_hash CHAR(64) UNIQUE NOT NULL,
		session_type VARCHAR(10) NOT NULL DEFAULT 'cookie', ip_address VARCHAR(45) NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '', credential_version INTEGER NOT NULL DEFAULT 0,
		last_active_at DATETIME NOT NULL, absolute_expires_at DATETIME NOT NULL, created_at DATETIME
	);`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("schema error: %v", err)
	}
	_ = database.Exec("PRAGMA foreign_keys = ON;")

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

func TestE2E_FullBrowserOAuthJourneys(t *testing.T) {
	t.Parallel()

	// Journeys use the stub (real loopback HTTP with PKCE binding); production
	// adapters cannot point at loopback without an exported endpoint override,
	// which does not exist. Request-shape coverage: oauth/microsoft_test.go.

	// 1. Journey 1: Microsoft Enterprise Login
	t.Run("journey 1: microsoft enterprise login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		mockMS := oauthmock.New("microsoft", "ms-user-oid-1", "corp-user@example.com", true)
		defer mockMS.Close()
		_ = (*pReg).Register(mockMS)

		// Step 1: GET /auth/oauth/microsoft -> 302 Redirect to provider
		initReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft?redirect_url=/welcome", nil)
		initRec := httptest.NewRecorder()
		h.ServeHTTP(initRec, initReq)

		if initRec.Code != http.StatusFound {
			t.Fatalf("expected 302 redirect from initiate, got %d (%s)", initRec.Code, initRec.Body.String())
		}
		loc, err := url.Parse(initRec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("invalid redirect location: %v", err)
		}
		stateParam := loc.Query().Get("state")
		if stateParam == "" {
			t.Fatal("expected state parameter in redirect URL")
		}

		var stateCookie *http.Cookie
		for _, c := range initRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				stateCookie = c
				break
			}
		}
		if stateCookie == nil {
			t.Fatal("expected state cookie in initiate response")
		}

		// Step 2: Callback GET /auth/oauth/microsoft/callback?code=code-1&state=stateParam
		cbReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/microsoft/callback?code=code-1&state=%s", stateParam), nil)
		cbReq.AddCookie(stateCookie)
		cbRec := httptest.NewRecorder()
		h.ServeHTTP(cbRec, cbReq)

		if cbRec.Code != http.StatusFound {
			t.Fatalf("expected 302 redirect on callback, got %d (%s)", cbRec.Code, cbRec.Body.String())
		}

		var sessionCookie *http.Cookie
		for _, c := range cbRec.Result().Cookies() {
			if c.Name == cfg.SessionCookieName {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatal("expected session cookie set on successful callback")
		}

		// Step 3: GET /auth/session with session cookie -> 200 OK
		sessReq := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
		sessReq.AddCookie(sessionCookie)
		sessRec := httptest.NewRecorder()
		h.ServeHTTP(sessRec, sessReq)

		if sessRec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from /auth/session, got %d (%s)", sessRec.Code, sessRec.Body.String())
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

		// Verify database records
		var user db.User
		if err := dbConn.Where("email = ?", "corp-user@example.com").First(&user).Error; err != nil {
			t.Fatalf("user record not found: %v", err)
		}
		var link db.OAuthAccount
		if err := dbConn.Where("provider_id = ? AND user_id = ?", "microsoft", user.ID).First(&link).Error; err != nil {
			t.Fatalf("link record not found: %v", err)
		}
		if link.ProviderUserID != "ms-user-oid-1" {
			t.Fatalf("link provider_user_id = %q; want %q", link.ProviderUserID, "ms-user-oid-1")
		}
	})

	// 2. Journey 2: Discord Account Linking to existing active authenticated session
	t.Run("journey 2: discord account linking to active session", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		mockMS := oauthmock.New("microsoft", "ms-user-oid-2", "existing-user@example.com", true)
		defer mockMS.Close()
		mockDiscord := oauthmock.New("discord", "discord-snowflake-888", "existing-user@example.com", true)
		defer mockDiscord.Close()
		_ = (*pReg).Register(mockMS)
		_ = (*pReg).Register(mockDiscord)

		// Create user with active session via initial Microsoft login
		initRec := httptest.NewRecorder()
		h.ServeHTTP(initRec, httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft", nil))
		loc, _ := url.Parse(initRec.Header().Get("Location"))
		stateParam := loc.Query().Get("state")

		var stateCookie *http.Cookie
		for _, c := range initRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				stateCookie = c
				break
			}
		}

		cbRec := httptest.NewRecorder()
		cbReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/microsoft/callback?code=c1&state=%s", stateParam), nil)
		cbReq.AddCookie(stateCookie)
		h.ServeHTTP(cbRec, cbReq)

		var sessionCookie *http.Cookie
		for _, c := range cbRec.Result().Cookies() {
			if c.Name == cfg.SessionCookieName {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatal("session cookie required")
		}

		// Now initiate Discord linking while authenticated
		linkInitRec := httptest.NewRecorder()
		linkInitReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/discord", nil)
		linkInitReq.AddCookie(sessionCookie)
		h.ServeHTTP(linkInitRec, linkInitReq)

		if linkInitRec.Code != http.StatusFound {
			t.Fatalf("expected 302 on linking initiate, got %d", linkInitRec.Code)
		}
		locDiscord, _ := url.Parse(linkInitRec.Header().Get("Location"))
		stateDiscord := locDiscord.Query().Get("state")

		var discordStateCookie *http.Cookie
		for _, c := range linkInitRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				discordStateCookie = c
				break
			}
		}

		linkCbRec := httptest.NewRecorder()
		linkCbReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/discord/callback?code=c2&state=%s", stateDiscord), nil)
		linkCbReq.AddCookie(discordStateCookie)
		linkCbReq.AddCookie(sessionCookie)
		h.ServeHTTP(linkCbRec, linkCbReq)

		if linkCbRec.Code != http.StatusFound {
			t.Fatalf("expected 302 on linking callback, got %d (%s)", linkCbRec.Code, linkCbRec.Body.String())
		}

		// Verify both Microsoft and Discord are linked to the same user
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
		if gotKeys["microsoft"] != "ms-user-oid-2" {
			t.Fatalf("microsoft link provider_user_id = %q; want %q", gotKeys["microsoft"], "ms-user-oid-2")
		}
		if gotKeys["discord"] != "discord-snowflake-888" {
			t.Fatalf("discord link provider_user_id = %q; want %q", gotKeys["discord"], "discord-snowflake-888")
		}
	})

	// 3. Journey 3: X (Twitter) missing email fail closed + returning user login
	t.Run("journey 3: x missing email fail closed and returning user login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		mockX := oauthmock.New("x", "x-user-snowflake-333", "", false) // No email
		defer mockX.Close()
		_ = (*pReg).Register(mockX)

		// Unauthenticated registration fails closed with 400 Bad Request
		initRec := httptest.NewRecorder()
		h.ServeHTTP(initRec, httptest.NewRequest(http.MethodGet, "/auth/oauth/x", nil))
		loc, _ := url.Parse(initRec.Header().Get("Location"))
		stateParam := loc.Query().Get("state")

		var stateCookie *http.Cookie
		for _, c := range initRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				stateCookie = c
				break
			}
		}

		cbRec := httptest.NewRecorder()
		cbReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/x/callback?code=cx&state=%s", stateParam), nil)
		cbReq.AddCookie(stateCookie)
		h.ServeHTTP(cbRec, cbReq)

		if cbRec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for unauthenticated X registration without email, got %d (%s)", cbRec.Code, cbRec.Body.String())
		}

		// Pre-link an account manually for returning user flow
		seededUser := db.User{
			ID:            uuid.New(),
			Email:         "seeded-x-owner@example.com",
			EmailVerified: true,
		}
		_ = dbConn.Create(&seededUser)
		_ = dbConn.Create(&db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         seededUser.ID,
			ProviderID:     "x",
			ProviderUserID: "x-user-snowflake-333",
			Email:          "seeded-x-owner@example.com",
		})

		// Returning user logs in: provider tuple ("x", "x-user-snowflake-333") matches existing row
		retInitRec := httptest.NewRecorder()
		h.ServeHTTP(retInitRec, httptest.NewRequest(http.MethodGet, "/auth/oauth/x", nil))
		retLoc, _ := url.Parse(retInitRec.Header().Get("Location"))
		retState := retLoc.Query().Get("state")

		var retCookie *http.Cookie
		for _, c := range retInitRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				retCookie = c
				break
			}
		}

		retCbRec := httptest.NewRecorder()
		retCbReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/x/callback?code=cx2&state=%s", retState), nil)
		retCbReq.AddCookie(retCookie)
		h.ServeHTTP(retCbRec, retCbReq)

		// Returning user succeeds (302 redirect with valid session cookie)
		if retCbRec.Code != http.StatusFound {
			t.Fatalf("expected 302 Found on returning user callback, got %d (%s)", retCbRec.Code, retCbRec.Body.String())
		}

		var retSessionCookie *http.Cookie
		for _, c := range retCbRec.Result().Cookies() {
			if c.Name == cfg.SessionCookieName {
				retSessionCookie = c
				break
			}
		}
		if retSessionCookie == nil {
			t.Fatal("expected session cookie for returning user")
		}
	})

	// 4. Journey 4: Facebook Login
	t.Run("journey 4: facebook login", func(t *testing.T) {
		h, dbConn, pReg, cfg := setupOAuthE2EStack(t)

		mockFB := oauthmock.New("facebook", "fb-app-scoped-uid-444", "fb-user@example.com", true)
		defer mockFB.Close()
		_ = (*pReg).Register(mockFB)

		initRec := httptest.NewRecorder()
		h.ServeHTTP(initRec, httptest.NewRequest(http.MethodGet, "/auth/oauth/facebook", nil))
		loc, _ := url.Parse(initRec.Header().Get("Location"))
		stateParam := loc.Query().Get("state")

		var stateCookie *http.Cookie
		for _, c := range initRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				stateCookie = c
				break
			}
		}

		cbRec := httptest.NewRecorder()
		cbReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/facebook/callback?code=cfb&state=%s", stateParam), nil)
		cbReq.AddCookie(stateCookie)
		h.ServeHTTP(cbRec, cbReq)

		if cbRec.Code != http.StatusFound {
			t.Fatalf("expected 302 Found on Facebook callback, got %d (%s)", cbRec.Code, cbRec.Body.String())
		}

		var count int64
		if err := dbConn.Model(&db.OAuthAccount{}).Where("provider_id = ?", "facebook").Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("expected 1 facebook link row, got count=%d, err=%v", count, err)
		}
	})

	// 5. Journey 5: Hard delete cascade
	t.Run("journey 5: hard delete cascade deletes oauth_accounts", func(t *testing.T) {
		_, dbConn, _, _ := setupOAuthE2EStack(t)

		u := db.User{
			ID:            uuid.New(),
			Email:         "cascade-test@example.com",
			EmailVerified: true,
		}
		_ = dbConn.Create(&u)
		_ = dbConn.Create(&db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         u.ID,
			ProviderID:     "microsoft",
			ProviderUserID: "ms-cascade-sub",
			Email:          u.Email,
		})

		var count int64
		_ = dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", u.ID).Count(&count)
		if count != 1 {
			t.Fatalf("expected 1 link row, got %d", count)
		}

		// Delete user
		_ = dbConn.Exec("DELETE FROM users WHERE id = ?", u.ID.String())

		_ = dbConn.Model(&db.OAuthAccount{}).Where("user_id = ?", u.ID).Count(&count)
		if count != 0 {
			t.Fatalf("expected 0 link rows after cascade delete, got %d", count)
		}
	})
}
