package oauth

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/session"
)

// stubProvider is a scriptable Provider fake for linking-engine tests.
type stubProvider struct {
	mu         sync.Mutex
	id         string
	info       *UserInfo
	infoErr    error
	exchErr    error
	gotVerifer string
	calls      int
	infoFunc   func() *UserInfo
}

func (f *stubProvider) ID() string { return f.id }

func (f *stubProvider) AuthURL(state, codeChallenge string) string {
	return "https://provider.example/auth?state=" + state + "&code_challenge=" + codeChallenge
}

func (f *stubProvider) AuthCodeURL(state, codeChallenge string, _ ...AuthCodeOption) string {
	return f.AuthURL(state, codeChallenge)
}

func (f *stubProvider) ExchangeCode(_ context.Context, code, codeVerifier string) (*TokenResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.exchErr != nil {
		return nil, f.exchErr
	}
	if code == "" {
		return nil, errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed", nil)
	}
	f.gotVerifer = codeVerifier
	return &TokenResponse{AccessToken: "stub-access"}, nil
}

func (f *stubProvider) FetchUserInfo(_ context.Context, _ *TokenResponse) (*UserInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.infoErr != nil {
		return nil, f.infoErr
	}
	if f.infoFunc != nil {
		return f.infoFunc(), nil
	}
	return f.info, nil
}

func serviceTestConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionCookieSecure = false
	cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
	return &cfg
}

func serviceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	name := fmt.Sprintf("file:mem_oauthsvc_%s?mode=memory&cache=shared", uuid.New().String())
	database, err := gorm.Open(sqlite.Open(name), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// Single connection serializes concurrent writers (shared-cache memory
	// SQLite has no busy wait); statement interleaving across goroutines
	// still occurs, so check-then-act races remain observable.
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	sqlDB.SetMaxOpenConns(1)
	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		provider_id VARCHAR(32) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_uid UNIQUE (provider_id, provider_user_id)
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
	`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return database
}

func setupServiceTest(t *testing.T, info *UserInfo) (*gorm.DB, *config.Config, *stubProvider, Service) {
	t.Helper()
	database := serviceTestDB(t)
	cfg := serviceTestConfig()
	stub := &stubProvider{id: "google", info: info}
	svc := NewService(database, session.NewService(database, cfg),
		map[string]Provider{"google": stub}, cfg)
	return database, cfg, stub, svc
}

func mustInitiate(t *testing.T, svc Service, cfg *config.Config, providerID string) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+providerID, nil)
	authURL, err := svc.InitiateFlow(rec, req, providerID)
	if err != nil {
		t.Fatalf("InitiateFlow = %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authURL: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" || u.Query().Get("code_challenge") == "" {
		t.Fatalf("authURL missing state/challenge: %q", authURL)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.OAuth.StateCookieName {
			return state, c
		}
	}
	t.Fatalf("no %q cookie issued", cfg.OAuth.StateCookieName)
	return "", nil
}

func callbackRequest(state string, cookie *http.Cookie) (*httptest.ResponseRecorder, *http.Request) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback", nil)
	req.AddCookie(cookie)
	return rec, req
}

// callbackRequestWithSession extends callbackRequest with the live session
// cookie. The callback re-resolves the signed-in user and only honours the
// state's link owner on equality, so link tests must present the session.
func callbackRequestWithSession(state string, cookie *http.Cookie, cfg *config.Config, rawSession string) (*httptest.ResponseRecorder, *http.Request) {
	rec, req := callbackRequest(state, cookie)
	req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawSession})
	return rec, req
}

// initiateLinked starts a flow for an authenticated user so the state cookie
// carries activeUserID exactly as a real account-link request does. The
// ?link=true intent is required: since the hardening gate, ambient sessions
// alone never embed a link owner.
func initiateLinked(t *testing.T, svc Service, cfg *config.Config, providerID, rawSession string) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+providerID+"?link=true", nil)
	req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawSession})
	authURL, err := svc.InitiateFlow(rec, req, providerID)
	if err != nil {
		t.Fatalf("InitiateFlow = %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse authURL: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.OAuth.StateCookieName {
			return u.Query().Get("state"), c
		}
	}
	t.Fatalf("no %q cookie issued", cfg.OAuth.StateCookieName)
	return "", nil
}

func countRows(t *testing.T, database *gorm.DB, model any) int64 {
	t.Helper()
	var n int64
	if err := database.Model(model).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func requireCode(t *testing.T, err error, want errors.Code, status int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s; got nil", want)
	}
	var appErr *errors.Error
	if !errors.As(err, &appErr) {
		t.Fatalf("error type = %T; want *errors.Error", err)
	}
	if appErr.Code() != want {
		t.Fatalf("code = %q; want %q", appErr.Code(), want)
	}
	if appErr.HTTPStatus() != status {
		t.Fatalf("status = %d; want %d", appErr.HTTPStatus(), status)
	}
}

// writeFixture writes an upstream fixture body, failing the test when the
// response can no longer be written.
func writeFixture(t *testing.T, w http.ResponseWriter, format string, args ...any) {
	t.Helper()
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		t.Errorf("write fixture: %v", err)
	}
}

func verifiedInfo() *UserInfo {
	return &UserInfo{ProviderID: "google", ProviderUserID: "sub-123", Email: "jane@example.com", EmailVerified: true}
}

// logSink is a mutex-guarded slog writer so captured audit output stays race-clean.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *logSink) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

// captureLogs installs sink as the process default logger until the test ends.
func captureLogs(t *testing.T) *logSink {
	t.Helper()
	sink := &logSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(sink, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return sink
}

// countEvents counts occurrences of msg in the captured log.
func countEvents(logs, msg string) int {
	return strings.Count(logs, `"msg":"`+msg+`"`)
}

// seedLinkedIdentity inserts a verified owner plus its oauth_accounts row.
func seedLinkedIdentity(t *testing.T, database *gorm.DB, providerID, providerUserID string) db.User {
	t.Helper()
	owner := db.User{ID: uuid.New(), Email: "linked-owner@example.com", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&owner).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	link := db.OAuthAccount{ID: uuid.New(), UserID: owner.ID, ProviderID: providerID,
		ProviderUserID: providerUserID, Email: owner.Email, Verified: true}
	if err := database.Create(&link).Error; err != nil {
		t.Fatalf("seed link: %v", err)
	}
	return owner
}

// requireIdentityRows asserts the users/links/sessions row counts.
func requireIdentityRows(t *testing.T, database *gorm.DB, users, links, sessions int) {
	t.Helper()
	if n := countRows(t, database, &db.User{}); n != int64(users) {
		t.Fatalf("users = %d; want %d", n, users)
	}
	if n := countRows(t, database, &db.OAuthAccount{}); n != int64(links) {
		t.Fatalf("oauth_accounts = %d; want %d", n, links)
	}
	if n := countRows(t, database, &db.Session{}); n != int64(sessions) {
		t.Fatalf("sessions = %d; want %d", n, sessions)
	}
}

func runCallback(t *testing.T, svc Service, cfg *config.Config) {
	t.Helper()
	state, cookie := mustInitiate(t, svc, cfg, "google")
	rec, req := callbackRequest(state, cookie)
	if _, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie); err != nil {
		t.Fatalf("HandleCallback = %v", err)
	}
}

func TestInitiateFlow(t *testing.T) {
	t.Run("sets state cookie and returns provider URL", func(t *testing.T) {
		t.Parallel()
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google", nil)
		authURL, err := svc.InitiateFlow(rec, req, "google")
		if err != nil {
			t.Fatalf("InitiateFlow = %v", err)
		}
		if got := (func() string {
			u, _ := url.Parse(authURL)
			return u.Host
		})(); got != "provider.example" {
			t.Fatalf("authURL host = %q; want provider.example (%q)", got, authURL)
		}
		found := false
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName && c.HttpOnly && c.MaxAge > 0 {
				found = true
			}
		}
		if !found {
			t.Fatal("no HttpOnly oauth_state cookie issued")
		}
	})

	t.Run("unknown provider rejects with 404", func(t *testing.T) {
		t.Parallel()
		_, _, _, svc := setupServiceTest(t, verifiedInfo())
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/discord", nil)
		_, err := svc.InitiateFlow(rec, req, "discord")
		requireCode(t, err, errors.CodeOAuthProviderNotFound, http.StatusNotFound)
	})
}

func TestHandleCallbackState(t *testing.T) {
	t.Run("tampered state rejected with 403", func(t *testing.T) {
		t.Parallel()
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state+"-tampered", cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state+"-tampered", db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthStateInvalid, http.StatusForbidden)
	})

	t.Run("missing cookie rejected with 403", func(t *testing.T) {
		t.Parallel()
		_, _, _, svc := setupServiceTest(t, verifiedInfo())
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback", nil)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", "whatever", db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthStateInvalid, http.StatusForbidden)
	})

	t.Run("empty code rejected with 400", func(t *testing.T) {
		t.Parallel()
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthCodeInvalid, http.StatusBadRequest)
	})

	t.Run("exchange failure maps to 502", func(t *testing.T) {
		t.Parallel()
		_, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
		stub.exchErr = errors.New(errors.CodeOAuthProviderError, "oauth token exchange failed", nil)
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
	})
}

func TestHandleCallbackEmailGate(t *testing.T) {
	t.Run("unverified email cannot merge into an existing account", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-9", Email: "victim@example.com"})
		owner := db.User{ID: uuid.New(), Email: "victim@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 1, 0, 0)
	})

	t.Run("existing link succeeds with email omitted", func(t *testing.T) {
		sink := captureLogs(t)
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-123", Email: "", EmailVerified: true})
		owner := seedLinkedIdentity(t, database, "google", "sub-123")
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if sess.UserID != owner.ID {
			t.Fatalf("session user = %v; want existing link owner %v", sess.UserID, owner.ID)
		}
		requireIdentityRows(t, database, 1, 1, 1)
		if n := countEvents(sink.String(), "oauth_account_linked"); n != 0 {
			t.Fatalf("oauth_account_linked = %d; want 0", n)
		}
		if n := countEvents(sink.String(), "oauth_user_created"); n != 0 {
			t.Fatalf("oauth_user_created = %d; want 0", n)
		}
	})

	t.Run("existing link succeeds with email unverified", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-123", Email: "victim@example.com"})
		owner := seedLinkedIdentity(t, database, "google", "sub-123")
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if sess.UserID != owner.ID {
			t.Fatalf("session user = %v; want existing link owner %v", sess.UserID, owner.ID)
		}
		requireIdentityRows(t, database, 1, 1, 1)
	})

	t.Run("existing link succeeds with empty email", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-123", Email: "   ", EmailVerified: true})
		owner := seedLinkedIdentity(t, database, "google", "sub-123")
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if sess.UserID != owner.ID {
			t.Fatalf("session user = %v; want existing link owner %v", sess.UserID, owner.ID)
		}
		requireIdentityRows(t, database, 1, 1, 1)
	})

	t.Run("unverified email registers a fresh unverified account", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-9", Email: "victim@example.com"})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v; want fresh registration", err)
		}
		var user db.User
		if err := database.Where("id = ?", sess.UserID).First(&user).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		if user.EmailVerified {
			t.Fatal("unverified provider email minted a verified local user")
		}
		// The link is persisted unverified: it can sign in this account and
		// nothing else.
		requireIdentityRows(t, database, 1, 1, 1)
		var link db.OAuthAccount
		if err := database.Where("provider_user_id = ?", "sub-9").First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.Verified {
			t.Fatal("unverified provider email must persist verified=false")
		}
	})

	t.Run("nil userinfo keeps the 400", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, nil)
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("padded email rejected as provider error", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-pad", Email: " jane@example.com", EmailVerified: true})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("display name email rejected as provider error", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-name", Email: "Jane<jane@example.com>", EmailVerified: true})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("quoted local part links like a bare address", func(t *testing.T) {
		t.Parallel()
		const quoted = `"jane"@example.com`
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-quoted", Email: quoted, EmailVerified: true})
		existing := db.User{ID: uuid.New(), Email: quoted, PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v; want link, not 502", err)
		}
		if sess.UserID != existing.ID {
			t.Fatalf("session user = %v; want existing %v", sess.UserID, existing.ID)
		}
		requireIdentityRows(t, database, 1, 1, 1)
	})

	t.Run("oversized email rejected as provider error", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-long",
				Email: strings.Repeat("a", 246) + "@example.com", EmailVerified: true})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("blank provider user id rejected as provider error", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "", Email: "jane@example.com", EmailVerified: true})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("oversized provider user id rejected as provider error", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: strings.Repeat("s", 256),
				Email: "jane@example.com", EmailVerified: true})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
		requireIdentityRows(t, database, 0, 0, 0)
	})
}

// TestUnverifiedSignupLinkProvenance pins what an unverified provider claim
// leaves behind: a link row marked unverified that signs in its own account, and
// keeps doing so through a password-only recovery signup, because a caller-set
// password proves nothing about the address. Only local proof (verification or
// password reset) spends it.
func TestUnverifiedSignupLinkProvenance(t *testing.T) {
	const addr = "victim@example.com"
	unverified := func() *UserInfo {
		return &UserInfo{ProviderID: "google", ProviderUserID: "sub-unverified-bind", Email: addr}
	}
	// passwordSignup runs the real recovery signup, which binds the caller's
	// password to the pending row and drops its sessions.
	passwordSignup := func(t *testing.T, database *gorm.DB, cfg *config.Config) {
		t.Helper()
		authSvc, err := auth.New(*cfg, database, email.Hooks{})
		if err != nil {
			t.Fatalf("auth.New: %v", err)
		}
		if _, _, err := authSvc.Signup(context.Background(), db.SignupRequest{
			Email: addr, Password: "CorrectHorseBattery9!",
		}); err != nil {
			t.Fatalf("password signup: %v", err)
		}
	}
	callback := func(t *testing.T, svc Service, cfg *config.Config) (*session.Session, error) {
		t.Helper()
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		return sess, err
	}

	t.Run("unverified link is purged by password-only recovery signup", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, unverified())
		first, err := callback(t, svc, cfg)
		if err != nil {
			t.Fatalf("unverified oauth signup = %v", err)
		}
		var link db.OAuthAccount
		if err := database.First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.UserID != first.UserID || link.Verified {
			t.Fatalf("link = (%v, verified=%v); want (%v, unverified)", link.UserID, link.Verified, first.UserID)
		}
		passwordSignup(t, database, cfg)
		var owner db.User
		if err := database.Where("id = ?", first.UserID).First(&owner).Error; err != nil {
			t.Fatalf("load owner: %v", err)
		}
		if owner.PasswordHash == "" {
			t.Fatal("password signup did not bind a password to the pending row")
		}
		if owner.EmailVerified {
			t.Fatal("password signup must not prove the address")
		}
		sess, err := callback(t, svc, cfg)
		if err == nil || sess != nil {
			t.Fatalf("login through unverified link should fail after password signup, got sess = %v", sess)
		}
		var linkCount int64
		database.Model(&db.OAuthAccount{}).Where("user_id = ?", first.UserID).Count(&linkCount)
		if linkCount != 0 {
			t.Fatalf("expected 0 links after password signup, got %d", linkCount)
		}
	})

	t.Run("password then oauth never binds", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, unverified())
		passwordSignup(t, database, cfg)
		sess, err := callback(t, svc, cfg)
		if sess != nil {
			t.Fatalf("session minted for %v; want none", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 1, 0, 0)
	})

	t.Run("concurrent unverified signups converge on one link", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		svc := rawSvc.(*service)
		info := unverified()
		type outcome struct {
			user db.User
			err  error
		}
		outs := make([]outcome, 2)
		var wg sync.WaitGroup
		for i := range outs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				u, _, _, err := svc.linkOrCreate(context.Background(), "google", info, "")
				outs[i] = outcome{user: u, err: err}
			}(i)
		}
		wg.Wait()
		for i, o := range outs {
			if o.err != nil {
				t.Fatalf("goroutine %d: %v; want convergence", i, o.err)
			}
		}
		if outs[0].user.ID != outs[1].user.ID {
			t.Fatalf("converged users differ: %v vs %v", outs[0].user.ID, outs[1].user.ID)
		}
		requireIdentityRows(t, database, 1, 1, 0)
	})

	// The winner's commit may become visible before the losing goroutine reads
	// the address at all; that ordering must converge exactly like the raced one.
	t.Run("visible pending row converges without a duplicate user", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		pending := db.User{ID: uuid.New(), Email: addr, PasswordHash: "", EmailVerified: false}
		if err := database.Create(&pending).Error; err != nil {
			t.Fatalf("seed pending user: %v", err)
		}
		// Winning unverified signup committed its oauth link alongside the user
		winnerLink := db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         pending.ID,
			ProviderID:     "google",
			ProviderUserID: "sub-unverified-bind",
			Email:          addr,
			Verified:       false,
		}
		if err := database.Create(&winnerLink).Error; err != nil {
			t.Fatalf("seed winner link: %v", err)
		}
		// Calling createUserAndLink exercises the losing create-race path:
		// attempting to create the user fails on email uniqueness, invoking
		// linkRacedUser and mergeOrConverge.
		got, _, created, err := rawSvc.(*service).createUserAndLink(context.Background(), "google", unverified())
		if err != nil {
			t.Fatalf("createUserAndLink over a pending row = %v; want convergence", err)
		}
		if got.ID != pending.ID || created {
			t.Fatalf("converged on %v (created=%v); want %v", got.ID, created, pending.ID)
		}
		requireIdentityRows(t, database, 1, 1, 0)
	})

	t.Run("relinkExisting invalidates unverified link on claimed account", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		claimed := db.User{ID: uuid.New(), Email: "claimed@example.com", EmailVerified: true}
		if err := database.Create(&claimed).Error; err != nil {
			t.Fatalf("seed claimed user: %v", err)
		}
		unverifiedLink := db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         claimed.ID,
			ProviderID:     "google",
			ProviderUserID: "sub-unverified-race",
			Email:          "claimed@example.com",
			Verified:       false,
		}
		if err := database.Create(&unverifiedLink).Error; err != nil {
			t.Fatalf("seed unverified link: %v", err)
		}
		_, _, _, err := rawSvc.(*service).relinkExisting(context.Background(), "google", "sub-unverified-race")
		if !errors.Is(err, errors.ErrOAuthEmailUnverified) {
			t.Fatalf("relinkExisting on unverified link for claimed account = %v; want ErrOAuthEmailUnverified", err)
		}
		var count int64
		database.Model(&db.OAuthAccount{}).Where("id = ?", unverifiedLink.ID).Count(&count)
		if count != 0 {
			t.Fatalf("expected unverified link to be deleted, got count = %d", count)
		}
	})

	t.Run("unattested email cannot take over pending unclaimed account", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, &UserInfo{
			ProviderID:     "google",
			ProviderUserID: "attacker-sub-456",
			Email:          addr,
			EmailVerified:  false,
		})
		pending := db.User{ID: uuid.New(), Email: addr, PasswordHash: "", EmailVerified: false}
		if err := database.Create(&pending).Error; err != nil {
			t.Fatalf("seed pending user: %v", err)
		}
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if sess != nil {
			t.Fatalf("session minted for %v; want none", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 1, 0, 0)
	})
}

// TestMergeGateRejectsUnstorableIdentity pins validateProviderIdentity as the
// live merge gate: no merge may attempt to store an identity the schema cannot
// hold, and an unverified claim may not pass it at all.
func TestMergeGateRejectsUnstorableIdentity(t *testing.T) {
	oversized := func(email string) *UserInfo {
		return &UserInfo{ProviderID: "google", ProviderUserID: strings.Repeat("s", providerFieldMaxLen+1),
			Email: email, EmailVerified: true}
	}

	t.Run("email merge rejects an oversized provider subject", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		existing := db.User{ID: uuid.New(), Email: "gate@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, _, _, err := rawSvc.(*service).linkOrCreate(context.Background(), "google", oversized("gate@example.com"), "")
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0", n)
		}
	})

	t.Run("raced email merge rejects an oversized provider subject", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		winner := db.User{ID: uuid.New(), Email: "raced-gate@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&winner).Error; err != nil {
			t.Fatalf("seed winner: %v", err)
		}
		_, _, _, err := rawSvc.(*service).createUserAndLink(context.Background(), "google", oversized("raced-gate@example.com"))
		requireCode(t, err, errors.CodeOAuthProviderError, http.StatusBadGateway)
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0", n)
		}
	})
}

func TestHandleCallbackLinking(t *testing.T) {
	t.Run("verified email links existing verified user without dup", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		existing := db.User{ID: uuid.New(), Email: "jane@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if sess.UserID != existing.ID {
			t.Fatalf("session user = %v; want %v", sess.UserID, existing.ID)
		}
		if n := countRows(t, database, &db.User{}); n != 1 {
			t.Fatalf("users = %d; want 1", n)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("oauth_accounts = %d; want 1", n)
		}
	})

	t.Run("verified email creates new user when absent", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		var user db.User
		if err := database.Where("id = ?", sess.UserID).First(&user).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		if !user.EmailVerified || user.PasswordHash != "" {
			t.Fatalf("new oauth user verified=%v hash=%q; want true/empty", user.EmailVerified, user.PasswordHash)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("oauth_accounts = %d; want 1", n)
		}
	})

	t.Run("repeat login reuses link with fresh session", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		var firstUser uuid.UUID
		for i := 0; i < 2; i++ {
			state, cookie := mustInitiate(t, svc, cfg, "google")
			rec, req := callbackRequest(state, cookie)
			sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
			if err != nil {
				t.Fatalf("login %d = %v", i, err)
			}
			if i == 0 {
				firstUser = sess.UserID
			} else if sess.UserID != firstUser {
				t.Fatalf("second login user = %v; want %v", sess.UserID, firstUser)
			}
		}
		if n := countRows(t, database, &db.User{}); n != 1 {
			t.Fatalf("users = %d; want 1", n)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("oauth_accounts = %d; want 1", n)
		}
		if n := countRows(t, database, &db.Session{}); n != 2 {
			t.Fatalf("sessions = %d; want 2", n)
		}
	})

	t.Run("unverified local account blocks link with 409", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		local := db.User{ID: uuid.New(), Email: "JANE@example.com", PasswordHash: "hash", EmailVerified: false}
		if err := database.Create(&local).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthAccountLinkConflict, http.StatusConflict)
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0", n)
		}
		if n := countRows(t, database, &db.User{}); n != 1 {
			t.Fatalf("users = %d; want 1", n)
		}
	})

	t.Run("session cookie set and state cleared on success", func(t *testing.T) {
		t.Parallel()
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		before := time.Now()
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		_ = before
		cookies := rec.Result().Cookies()
		var sessionSet, stateCleared bool
		for _, c := range cookies {
			if c.Name == "sid" && c.Value != "" {
				sessionSet = true
			}
			if c.Name == cfg.OAuth.StateCookieName && c.MaxAge == -1 {
				stateCleared = true
			}
		}
		if !sessionSet {
			t.Error("session cookie not set on callback success")
		}
		if !stateCleared {
			t.Error("state cookie not cleared on callback success")
		}
	})
}

func TestHandleCallbackActiveSessionLinking(t *testing.T) {
	// Provider emails in this block all differ from the active user's address:
	// a shared address would let email matching hide a broken owner lookup.
	t.Run("vanished owner fails closed instead of linking by provider email", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-orphan",
			Email: "provider-owner@personal.example", EmailVerified: true,
		})
		ctx := context.Background()
		sessSvc := session.NewService(database, cfg)
		active := db.User{ID: uuid.New(), Email: "active@work.example", PasswordHash: "hash", EmailVerified: true}
		other := db.User{ID: uuid.New(), Email: "provider-owner@personal.example", PasswordHash: "hash", EmailVerified: true}
		for _, u := range []db.User{active, other} {
			if err := database.Create(&u).Error; err != nil {
				t.Fatalf("seed user: %v", err)
			}
		}
		_, rawSession, err := sessSvc.CreateSession(ctx, active.ID, active.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		state, stateCookie := initiateLinked(t, svc, cfg, "google", rawSession)
		// Hard delete between initiate and callback: the linked owner is gone.
		if err := database.Delete(&db.User{}, "id = ?", active.ID).Error; err != nil {
			t.Fatalf("delete active user: %v", err)
		}
		rec, req := callbackRequestWithSession(state, stateCookie, cfg, rawSession)
		sess, _, _, err := svc.HandleCallback(ctx, rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if sess != nil {
			t.Fatalf("session issued for %v; want none", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthAccountNotLinked, http.StatusNotFound)
		// Merge premise (oauth sync): the callback's live-session re-resolution
		// prunes the dangling pre-created session (missing_user_at_read), so no
		// session row survives; no session was minted and the provider identity
		// stayed unlinked.
		requireIdentityRows(t, database, 1, 0, 0)
	})

	t.Run("non-uuid active user id fails closed", func(t *testing.T) {
		database, _, _, rawSvc := setupServiceTest(t, nil)
		info := &UserInfo{ProviderID: "google", ProviderUserID: "sub-bad-id",
			Email: "provider-owner@personal.example", EmailVerified: true}
		_, _, _, err := rawSvc.(*service).linkOrCreate(context.Background(), "google", info, "not-a-uuid")
		requireCode(t, err, errors.CodeOAuthAccountNotLinked, http.StatusNotFound)
		requireIdentityRows(t, database, 0, 0, 0)
	})

	t.Run("store failure stays a domain error", func(t *testing.T) {
		_, _, _, rawSvc := setupServiceTest(t, nil)
		base := rawSvc.(*service).store
		broken := &failingGetByIDStore{
			Store: base,
			users: &failingGetByIDUserStore{UserStore: base.Users(), err: stderrors.New("dial tcp: connection refused")},
		}
		svc := NewServiceWithStore(broken, nil, nil, serviceTestConfig()).(*service)
		_, _, _, err := svc.linkOrCreate(context.Background(), "google", verifiedInfo(), uuid.New().String())
		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
	})

	t.Run("nil user from store fails closed", func(t *testing.T) {
		_, _, _, rawSvc := setupServiceTest(t, nil)
		base := rawSvc.(*service).store
		svc := NewServiceWithStore(&wrappedTxStore{
			Store: base,
			users: nilUserStore{UserStore: base.Users()},
		}, nil, nil, serviceTestConfig()).(*service)
		_, _, _, err := svc.linkOrCreate(context.Background(), "google", verifiedInfo(), uuid.New().String())
		requireCode(t, err, errors.CodeOAuthAccountNotLinked, http.StatusNotFound)
	})

	t.Run("provider email differing from the active user links to the active user", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-active",
			Email: "provider-owner@personal.example", EmailVerified: true,
		})
		ctx := context.Background()
		sessSvc := session.NewService(database, cfg)
		active := db.User{ID: uuid.New(), Email: "active@work.example", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&active).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, rawSession, err := sessSvc.CreateSession(ctx, active.ID, active.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		state, stateCookie := initiateLinked(t, svc, cfg, "google", rawSession)
		rec, req := callbackRequestWithSession(state, stateCookie, cfg, rawSession)
		sess, _, _, err := svc.HandleCallback(ctx, rec, req, "google", "code-1", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v", err)
		}
		if sess.UserID != active.ID {
			t.Fatalf("session user = %v; want active user %v", sess.UserID, active.ID)
		}
		var link db.OAuthAccount
		if err := database.Where("provider_id = ? AND provider_user_id = ?", "google", "sub-active").First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.UserID != active.ID {
			t.Fatalf("link owner = %v; want %v", link.UserID, active.ID)
		}
	})
}

// TestExplicitLinkRequiresClaimedOwner pins the pre-hijack gate on the explicit
// ?link=true path: anyone who registered an address can hold a session on its
// still-unclaimed row, so a verified provider identity may attach only after the
// user has proved the address locally with an email verification or a password
// reset. A password is caller-set and therefore never proof.
func TestExplicitLinkRequiresClaimedOwner(t *testing.T) {
	linkInfo := func() *UserInfo {
		return &UserInfo{ProviderID: "google", ProviderUserID: "sub-link-gate",
			Email: "provider-owner@personal.example", EmailVerified: true}
	}
	linkAttempt := func(t *testing.T, svc Service, cfg *config.Config, rawSession string) (*session.Session, error) {
		t.Helper()
		state, cookie := initiateLinked(t, svc, cfg, "google", rawSession)
		rec, req := callbackRequestWithSession(state, cookie, cfg, rawSession)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		return sess, err
	}
	seedUnclaimed := func(t *testing.T, database *gorm.DB, cfg *config.Config) (db.User, string) {
		t.Helper()
		owner := db.User{ID: uuid.New(), Email: "unclaimed@work.example"}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed owner: %v", err)
		}
		_, rawSession, err := session.NewService(database, cfg).
			CreateSession(context.Background(), owner.ID, owner.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		return owner, rawSession
	}

	t.Run("unclaimed owner rejects the link", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, linkInfo())
		_, rawSession := seedUnclaimed(t, database, cfg)

		sess, err := linkAttempt(t, svc, cfg, rawSession)
		if sess != nil {
			t.Fatalf("session minted for %v; want the link rejected", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthAccountLinkConflict, http.StatusConflict)
		requireIdentityRows(t, database, 1, 0, 1)
	})

	t.Run("password alone does not authorize the link", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, linkInfo())
		owner, _ := seedUnclaimed(t, database, cfg)
		signupPassword(t, database, cfg, owner.Email, "CorrectHorseBattery9!")

		var claimed db.User
		if err := database.Where("id = ?", owner.ID).First(&claimed).Error; err != nil {
			t.Fatalf("load claimed owner: %v", err)
		}
		if claimed.PasswordHash == "" {
			t.Fatal("password signup did not bind a password")
		}
		if claimed.EmailVerified {
			t.Fatal("password signup must not mark the address verified")
		}
		_, rawSession, err := session.NewService(database, cfg).
			CreateSession(context.Background(), claimed.ID, claimed.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		sess, err := linkAttempt(t, svc, cfg, rawSession)
		if sess != nil {
			t.Fatalf("session minted for %v; a caller-set password must not authorize the link", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthAccountLinkConflict, http.StatusConflict)
		requireIdentityRows(t, database, 1, 0, 1)
	})

	t.Run("locally verified owner links", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t, linkInfo())
		owner := db.User{ID: uuid.New(), Email: "verified-owner@example.com", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed owner: %v", err)
		}
		_, rawSession, err := session.NewService(database, cfg).
			CreateSession(context.Background(), owner.ID, owner.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		sess, err := linkAttempt(t, svc, cfg, rawSession)
		if err != nil {
			t.Fatalf("link for a verified owner = %v; want success", err)
		}
		if sess.UserID != owner.ID {
			t.Fatalf("session user = %v; want %v", sess.UserID, owner.ID)
		}
		var link db.OAuthAccount
		if err := database.Where("provider_id = ? AND provider_user_id = ?", "google", "sub-link-gate").First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.UserID != owner.ID || !link.Verified {
			t.Fatalf("link = (%v, verified=%v); want (%v, verified)", link.UserID, link.Verified, owner.ID)
		}
	})

	// The full pre-hijack chain: an unverified provider signup mints a session on
	// the victim's unclaimed row, and the explicit link that would have survived
	// the later claim is refused, so the refused identity never gets a row. The
	// owner's own unverified link then dies at the address proof (covered by
	// TestUnverifiedLinkTakeoverDefense).
	t.Run("rejected pre-claim link persists nothing for the refused identity", func(t *testing.T) {
		database := serviceTestDB(t)
		cfg := serviceTestConfig()
		const addr = "victim@example.test"
		google := &stubProvider{id: "google", info: &UserInfo{
			ProviderID: "google", ProviderUserID: "sub-victim-unverified", Email: addr,
		}}
		github := &stubProvider{id: "github", info: &UserInfo{
			ProviderID: "github", ProviderUserID: "sub-attacker-verified",
			Email: "attacker@example.test", EmailVerified: true,
		}}
		sessSvc := session.NewService(database, cfg)
		svc := NewService(database, sessSvc, map[string]Provider{"google": google, "github": github}, cfg)

		attacker, err := loginViaGoogle(t, svc, cfg)
		if err != nil {
			t.Fatalf("unverified signup = %v", err)
		}
		var pending db.User
		if err := database.Where("id = ?", attacker.UserID).First(&pending).Error; err != nil {
			t.Fatalf("load pending owner: %v", err)
		}
		_, rawSession, err := sessSvc.CreateSession(context.Background(), pending.ID,
			pending.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		state, cookie := initiateLinked(t, svc, cfg, "github", rawSession)
		rec, req := callbackRequestWithSession(state, cookie, cfg, rawSession)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "github", "code-1", state, db.SessionTypeCookie)
		if sess != nil {
			t.Fatalf("session minted for %v through the explicit link", sess.UserID)
		}
		requireCode(t, err, errors.CodeOAuthAccountLinkConflict, http.StatusConflict)
		requireIdentityRows(t, database, 1, 1, 2)
		var link db.OAuthAccount
		if err := database.First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.ProviderUserID != "sub-victim-unverified" || link.Verified {
			t.Fatalf("surviving link = (%q, verified=%v); want the owner's own unverified google link",
				link.ProviderUserID, link.Verified)
		}
		var refused int64
		if err := database.Model(&db.OAuthAccount{}).
			Where("provider_id = ? AND provider_user_id = ?", "github", "sub-attacker-verified").
			Count(&refused).Error; err != nil {
			t.Fatalf("count refused link: %v", err)
		}
		if refused != 0 {
			t.Fatalf("refused identity rows = %d; want 0", refused)
		}
	})
}

// TestInitiateFlowSkipsNonceForNonOIDC pins that a nonce is minted only for
// providers that can verify an ID token: a plain Provider has no nonce channel
// and never checks one at callback.
func TestInitiateFlowSkipsNonceForNonOIDC(t *testing.T) {
	database := serviceTestDB(t)
	cfg := serviceTestConfig()
	stub := &stubProvider{id: "google", info: verifiedInfo()}
	svc := NewService(database, session.NewService(database, cfg), map[string]Provider{"google": stub}, cfg)

	state, cookie := mustInitiate(t, svc, cfg, "google")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback", nil)
	req.AddCookie(cookie)
	payload, err := ValidateState(rec, req, cfg, "google", state)
	if err != nil {
		t.Fatalf("ValidateState = %v", err)
	}
	if payload.Nonce != "" {
		t.Fatalf("state nonce = %q for a non-OIDC provider; want empty", payload.Nonce)
	}
}

// failingGetByIDStore swaps the user store so GetByID can fail like a dead DB link.
type failingGetByIDStore struct {
	db.Store
	users db.UserStore
}

func (f *failingGetByIDStore) Users() db.UserStore { return f.users }

type failingGetByIDUserStore struct {
	db.UserStore
	err error
}

func (f *failingGetByIDUserStore) GetByID(context.Context, uuid.UUID) (*db.User, error) {
	return nil, f.err
}

// nilUserStore returns (nil, nil) for GetByID: Store is a pluggable interface,
// so a third-party implementation may violate the miss contract.
type nilUserStore struct{ db.UserStore }

func (nilUserStore) GetByID(context.Context, uuid.UUID) (*db.User, error) { return nil, nil }

// linkGate is the state shared by every gated store view: the service reads
// through the root store and through the transaction it opens, and both must
// agree on the rendezvous and on which probes report a miss.
type linkGate struct {
	remaining atomic.Int32
	conflicts atomic.Int32
	arrived   chan struct{}
	release   chan struct{}
}

// gatedStore rebinds the gate to whichever store view is current, so the
// transaction-scoped insert is the one that observes the unique violation.
type gatedStore struct {
	db.Store
	gate *linkGate
}

func (s *gatedStore) OAuthAccounts() db.OAuthAccountStore {
	return &gatedMissLinkStore{OAuthAccountStore: s.Store.OAuthAccounts(), gate: s.gate}
}

func (s *gatedStore) Transaction(ctx context.Context, fn func(db.Store) error) error {
	return s.Store.Transaction(ctx, func(tx db.Store) error {
		return fn(&gatedStore{Store: tx, gate: s.gate})
	})
}

// gatedMissLinkStore reports a miss for its first `remaining` GetByProvider
// probes, holding each caller until release closes. Both concurrent callbacks
// therefore clear the already-linked branch before either can insert.
type gatedMissLinkStore struct {
	db.OAuthAccountStore
	gate *linkGate
}

func (g *gatedMissLinkStore) GetByProvider(ctx context.Context, providerID, providerUserID string) (*db.OAuthAccount, error) {
	if g.gate.remaining.Add(-1) < 0 {
		return g.OAuthAccountStore.GetByProvider(ctx, providerID, providerUserID)
	}
	g.gate.arrived <- struct{}{}
	<-g.gate.release
	return nil, gorm.ErrRecordNotFound
}

func (g *gatedMissLinkStore) Create(ctx context.Context, a *db.OAuthAccount) error {
	err := g.OAuthAccountStore.Create(ctx, a)
	if isUniqueViolation(err) {
		g.gate.conflicts.Add(1)
	}
	return err
}

// hideFirstLinkStore hides an existing link from the first GetByProvider probe,
// so the callback skips the already-linked branch and loses the insert race.
type hideFirstLinkStore struct {
	db.OAuthAccountStore
	hidden bool
}

func (h *hideFirstLinkStore) GetByProvider(ctx context.Context, providerID, providerUserID string) (*db.OAuthAccount, error) {
	if h.hidden {
		h.hidden = false
		return nil, gorm.ErrRecordNotFound
	}
	return h.OAuthAccountStore.GetByProvider(ctx, providerID, providerUserID)
}

func TestHandleCallbackLinkConflictForeignOwner(t *testing.T) {
	database, cfg, stub, rawSvc := setupServiceTest(t, &UserInfo{
		ProviderID: "google", ProviderUserID: "sub-conflict",
		Email: "provider-owner@personal.example", EmailVerified: true,
	})
	ctx := context.Background()
	sessSvc := session.NewService(database, cfg)
	active := db.User{ID: uuid.New(), Email: "active@work.example", PasswordHash: "hash", EmailVerified: true}
	foreign := db.User{ID: uuid.New(), Email: "foreign@personal.example", PasswordHash: "hash", EmailVerified: true}
	for _, u := range []db.User{active, foreign} {
		if err := database.Create(&u).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	won := db.OAuthAccount{ID: uuid.New(), UserID: foreign.ID, ProviderID: "google",
		ProviderUserID: "sub-conflict", Email: foreign.Email, Verified: true}
	if err := database.Create(&won).Error; err != nil {
		t.Fatalf("seed link: %v", err)
	}
	_, rawSession, err := sessSvc.CreateSession(ctx, active.ID, active.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	base := rawSvc.(*service).store
	svc := NewServiceWithStore(&wrappedTxStore{
		Store: base,
		oauth: &hideFirstLinkStore{OAuthAccountStore: base.OAuthAccounts(), hidden: true},
	}, sessSvc, map[string]Provider{"google": stub}, cfg)

	state, stateCookie := initiateLinked(t, svc, cfg, "google", rawSession)
	rec, req := callbackRequestWithSession(state, stateCookie, cfg, rawSession)
	sess, _, _, err := svc.HandleCallback(ctx, rec, req, "google", "code-1", state, db.SessionTypeCookie)
	if sess != nil {
		t.Fatalf("session issued for %v; want none for the foreign owner", sess.UserID)
	}
	requireCode(t, err, errors.CodeOAuthAccountAlreadyLinked, http.StatusConflict)
	requireIdentityRows(t, database, 2, 1, 1)
	var link db.OAuthAccount
	if err := database.Where("provider_id = ? AND provider_user_id = ?", "google", "sub-conflict").First(&link).Error; err != nil {
		t.Fatalf("load link: %v", err)
	}
	if link.UserID != foreign.ID {
		t.Fatalf("link owner = %v; want untouched %v", link.UserID, foreign.ID)
	}
}

func TestHandleCallbackLinkConflictSameOwnerConverges(t *testing.T) {
	database, cfg, stub, rawSvc := setupServiceTest(t, &UserInfo{
		ProviderID: "google", ProviderUserID: "sub-same-owner",
		Email: "provider-owner@personal.example", EmailVerified: true,
	})
	ctx := context.Background()
	sessSvc := session.NewService(database, cfg)
	active := db.User{ID: uuid.New(), Email: "active@work.example", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&active).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	_, rawSession, err := sessSvc.CreateSession(ctx, active.ID, active.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	base := rawSvc.(*service).store
	gate := &linkGate{
		arrived: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	gate.remaining.Store(2)
	svc := NewServiceWithStore(&gatedStore{Store: base, gate: gate},
		sessSvc, map[string]Provider{"google": stub}, cfg)

	states := make([]string, 2)
	cookies := make([]*http.Cookie, 2)
	for i := range states {
		states[i], cookies[i] = initiateLinked(t, svc, cfg, "google", rawSession)
	}
	type outcome struct {
		userID uuid.UUID
		err    error
	}
	results := make([]outcome, len(states))
	var wg sync.WaitGroup
	for i := range states {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, req := callbackRequestWithSession(states[i], cookies[i], cfg, rawSession)
			sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", states[i], db.SessionTypeCookie)
			if sess != nil {
				results[i].userID = sess.UserID
			}
			results[i].err = err
		}(i)
	}
	// Hold both callbacks at their first link probe until both have arrived, so
	// one insert wins and the other takes the conflict-recovery path.
	<-gate.arrived
	<-gate.arrived
	close(gate.release)
	wg.Wait()
	if n := gate.conflicts.Load(); n != 1 {
		t.Fatalf("unique conflicts = %d; want 1 (loser must take the relink path)", n)
	}

	for i, r := range results {
		if r.err != nil {
			t.Fatalf("callback %d: %v; want same-owner convergence", i, r.err)
		}
		if r.userID != active.ID {
			t.Fatalf("callback %d session user = %v; want %v", i, r.userID, active.ID)
		}
	}
	// One active-user session plus one per callback; both linked to the owner.
	requireIdentityRows(t, database, 1, 1, 3)
}

// staleOwnerStore hides a revocation that lands after the caller's first read:
// Users().GetByID returns the verified snapshot the gate would have used, while
// the locking read observes the current (unverified) row. Transaction rebinds
// the snapshot to the tx store, so only GetByID is overridden and every other
// user read, GetByIDForUpdate included, stays on the transaction's connection.
type staleOwnerStore struct {
	db.Store
	stale *db.User
}

func (s *staleOwnerStore) Users() db.UserStore {
	return &staleOwnerUserStore{UserStore: s.Store.Users(), stale: s.stale}
}

func (s *staleOwnerStore) Transaction(ctx context.Context, fn func(db.Store) error) error {
	return s.Store.Transaction(ctx, func(tx db.Store) error {
		return fn(&wrappedTxStore{Store: tx, users: &staleOwnerUserStore{UserStore: tx.Users(), stale: s.stale}})
	})
}

type staleOwnerUserStore struct {
	db.UserStore
	stale *db.User
}

func (s *staleOwnerUserStore) GetByID(ctx context.Context, id uuid.UUID) (*db.User, error) {
	if s.stale != nil && s.stale.ID == id {
		return s.stale, nil
	}
	return s.UserStore.GetByID(ctx, id)
}

// TestExplicitLinkGateReadsLockedOwnerState pins that the claim decision is made
// on the row-locked owner, not on an earlier read: a revocation that lands
// between the callback's owner load and the insert must be observed, so the
// link cannot be committed onto an account that is no longer claimed.
func TestExplicitLinkGateReadsLockedOwnerState(t *testing.T) {
	database, cfg, stub, rawSvc := setupServiceTest(t, &UserInfo{
		ProviderID: "google", ProviderUserID: "sub-locked-gate",
		Email: "provider-owner@personal.example", EmailVerified: true,
	})
	owner := db.User{ID: uuid.New(), Email: "owner@work.example", EmailVerified: true}
	if err := database.Create(&owner).Error; err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	_, rawSession, err := session.NewService(database, cfg).
		CreateSession(context.Background(), owner.ID, owner.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// The verified snapshot the callback would have gated on, and the revoked row
	// a concurrent writer commits before the insert.
	stale := owner
	if err := database.Model(&db.User{}).Where("id = ?", owner.ID).Update("email_verified", false).Error; err != nil {
		t.Fatalf("revoke verification: %v", err)
	}

	base := rawSvc.(*service).store
	svc := NewServiceWithStore(&staleOwnerStore{Store: base, stale: &stale},
		session.NewService(database, cfg), map[string]Provider{"google": stub}, cfg)

	state, cookie := initiateLinked(t, svc, cfg, "google", rawSession)
	rec, req := callbackRequestWithSession(state, cookie, cfg, rawSession)
	sess, _, _, err := svc.HandleCallback(context.Background(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
	if sess != nil {
		t.Fatalf("session minted for %v; the revoked claim must reject the link", sess.UserID)
	}
	requireCode(t, err, errors.CodeOAuthAccountLinkConflict, http.StatusConflict)
	requireIdentityRows(t, database, 1, 0, 1)
}

func TestHandleCallbackNilGuards(t *testing.T) {
	t.Run("nil request tolerated on initiate", func(t *testing.T) {
		t.Parallel()
		_, _, _, svc := setupServiceTest(t, verifiedInfo())
		rec := httptest.NewRecorder()
		if _, err := svc.InitiateFlow(rec, nil, "google"); err != nil {
			t.Fatalf("InitiateFlow(nil r) = %v; want nil error", err)
		}
	})

	t.Run("nil request rejected without panic", func(t *testing.T) {
		t.Parallel()
		_, _, _, svc := setupServiceTest(t, verifiedInfo())
		_, _, _, err := svc.HandleCallback(context.Background(), httptest.NewRecorder(), nil, "google", "c", "s", db.SessionTypeCookie)
		requireCode(t, err, errors.CodeValidationError, http.StatusBadRequest)
	})

	t.Run("nil writer rejected without panic", func(t *testing.T) {
		t.Parallel()
		_, _, _, svc := setupServiceTest(t, verifiedInfo())
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google/callback", nil)
		_, _, _, err := svc.HandleCallback(req.Context(), nil, req, "google", "c", "s", db.SessionTypeCookie)
		requireCode(t, err, errors.CodeValidationError, http.StatusBadRequest)
	})
}

func TestLinkOrCreateConcurrent(t *testing.T) {
	raceService := func(t *testing.T) (*gorm.DB, *service) {
		t.Helper()
		database := serviceTestDB(t)
		sqlDB, err := database.DB()
		if err != nil {
			t.Fatalf("sql DB: %v", err)
		}
		// Single connection serializes sqlite writers so the loser sees a
		// UNIQUE violation (the race path) instead of SQLITE_BUSY.
		sqlDB.SetMaxOpenConns(1)
		cfg := serviceTestConfig()
		stub := &stubProvider{id: "google", info: verifiedInfo()}
		svc, ok := NewService(database, session.NewService(database, cfg),
			map[string]Provider{"google": stub}, cfg).(*service)
		if !ok {
			t.Fatal("NewService did not return *service")
		}
		return database, svc
	}
	race := func(t *testing.T, svc *service, info *UserInfo) []db.User {
		t.Helper()
		type outcome struct {
			user db.User
			err  error
		}
		outs := make([]outcome, 2)
		var wg sync.WaitGroup
		for i := range outs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				u, _, _, err := svc.linkOrCreate(context.Background(), "google", info, "")
				outs[i] = outcome{u, err}
			}(i)
		}
		wg.Wait()
		for i, o := range outs {
			if o.err != nil {
				t.Fatalf("goroutine %d: %v; want convergence", i, o.err)
			}
		}
		return []db.User{outs[0].user, outs[1].user}
	}

	t.Run("concurrent first login converges on one user", func(t *testing.T) {
		t.Parallel()
		database, svc := raceService(t)
		users := race(t, svc, verifiedInfo())
		if users[0].ID != users[1].ID {
			t.Fatalf("converged users differ: %v vs %v", users[0].ID, users[1].ID)
		}
		if n := countRows(t, database, &db.User{}); n != 1 {
			t.Fatalf("users = %d; want 1", n)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("oauth_accounts = %d; want 1", n)
		}
	})

	t.Run("concurrent link converges without dup", func(t *testing.T) {
		t.Parallel()
		database, svc := raceService(t)
		existing := db.User{ID: uuid.New(), Email: "jane@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		users := race(t, svc, verifiedInfo())
		if users[0].ID != existing.ID || users[1].ID != existing.ID {
			t.Fatalf("linked users = %v, %v; want %v", users[0].ID, users[1].ID, existing.ID)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("oauth_accounts = %d; want 1", n)
		}
	})
}

func TestHandleCallbackConcurrentSameIdentityConverges(t *testing.T) {
	database, cfg, stub, svc := setupServiceTest(t, verifiedInfo())
	var n int64
	stub.infoFunc = func() *UserInfo {
		i := atomic.AddInt64(&n, 1)
		return &UserInfo{ProviderID: "google", ProviderUserID: "sub-race",
			Email: fmt.Sprintf("race-%d@example.com", i), EmailVerified: true}
	}
	const workers = 8
	states := make([]string, workers)
	cookies := make([]*http.Cookie, workers)
	for i := 0; i < workers; i++ {
		states[i], cookies[i] = mustInitiate(t, svc, cfg, "google")
	}
	type outcome struct {
		userID uuid.UUID
		err    error
	}
	results := make([]outcome, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, req := callbackRequest(states[i], cookies[i])
			sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", states[i], db.SessionTypeCookie)
			if err == nil && sess != nil {
				results[i].userID = sess.UserID
			}
			results[i].err = err
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("callback %d: %v", i, r.err)
		}
		if i > 0 && r.userID != results[0].userID {
			t.Fatalf("callback %d user %v; want %v", i, r.userID, results[0].userID)
		}
	}
	if n := countRows(t, database, &db.User{}); n != 1 {
		t.Fatalf("users = %d; want 1 (orphan user committed)", n)
	}
	if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
		t.Fatalf("links = %d; want 1", n)
	}
}

func TestHandleCallbackAuditFlags(t *testing.T) {
	t.Run("new identity emits linked and created once", func(t *testing.T) {
		sink := captureLogs(t)
		database, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		runCallback(t, svc, cfg)
		if n := countEvents(sink.String(), "oauth_account_linked"); n != 1 {
			t.Fatalf("oauth_account_linked = %d; want 1", n)
		}
		if n := countEvents(sink.String(), "oauth_user_created"); n != 1 {
			t.Fatalf("oauth_user_created = %d; want 1", n)
		}
		if n := countRows(t, database, &db.User{}); n != 1 {
			t.Fatalf("users = %d; want 1", n)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("links = %d; want 1", n)
		}
	})

	t.Run("email link emits linked only", func(t *testing.T) {
		sink := captureLogs(t)
		database, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		existing := db.User{ID: uuid.New(), Email: "jane@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&existing).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		runCallback(t, svc, cfg)
		if n := countEvents(sink.String(), "oauth_account_linked"); n != 1 {
			t.Fatalf("oauth_account_linked = %d; want 1", n)
		}
		if n := countEvents(sink.String(), "oauth_user_created"); n != 0 {
			t.Fatalf("oauth_user_created = %d; want 0", n)
		}
	})

	t.Run("repeat link emits neither", func(t *testing.T) {
		_, cfg, _, svc := setupServiceTest(t, verifiedInfo())
		runCallback(t, svc, cfg)
		sink := captureLogs(t)
		runCallback(t, svc, cfg)
		if n := countEvents(sink.String(), "oauth_account_linked"); n != 0 {
			t.Fatalf("oauth_account_linked = %d; want 0", n)
		}
		if n := countEvents(sink.String(), "oauth_user_created"); n != 0 {
			t.Fatalf("oauth_user_created = %d; want 0", n)
		}
	})

	t.Run("race loser emits neither", func(t *testing.T) {
		sink := captureLogs(t)
		database, _, _, svc := setupServiceTest(t, verifiedInfo())
		owner := db.User{ID: uuid.New(), Email: "owner@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&owner).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		link := db.OAuthAccount{ID: uuid.New(), UserID: owner.ID, ProviderID: "google",
			ProviderUserID: "sub-123", Email: owner.Email, Verified: true}
		if err := database.Create(&link).Error; err != nil {
			t.Fatalf("seed link: %v", err)
		}
		// Enter the create step directly: the seeded link is exactly what a
		// concurrent winner leaves behind, so the insert must lose to it.
		user, linked, created, err := svc.(*service).createUserAndLink(context.Background(), "google", verifiedInfo())
		if err != nil {
			t.Fatalf("createUserAndLink = %v", err)
		}
		if user.ID != owner.ID || linked || created {
			t.Fatalf("tuple = (%v,%v,%v); want (%v,false,false)", user.ID, linked, created, owner.ID)
		}
		logLinkAudit(context.Background(), "google", user, linked, created)
		if n := countEvents(sink.String(), "oauth_account_linked"); n != 0 {
			t.Fatalf("oauth_account_linked = %d; want 0", n)
		}
		if n := countEvents(sink.String(), "oauth_user_created"); n != 0 {
			t.Fatalf("oauth_user_created = %d; want 0", n)
		}
		if n := countRows(t, database, &db.User{}); n != 1 {
			t.Fatalf("users = %d; want 1 (loser's user must roll back)", n)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("links = %d; want 1", n)
		}
	})
}

func TestService_CreateUserEmailRaceRecovery(t *testing.T) {
	t.Run("race loser links onto verified winner", func(t *testing.T) {
		database, _, _, svc := setupServiceTest(t, nil)
		ctx := context.Background()

		// Seed the winning user that won the race
		winner := db.User{
			ID:            uuid.New(),
			Email:         "raced@example.com",
			PasswordHash:  "hash",
			EmailVerified: true,
		}
		if err := database.Create(&winner).Error; err != nil {
			t.Fatalf("seed winner: %v", err)
		}

		// Raced user tries to create user and link
		info := &UserInfo{
			ProviderUserID: "raced-subject-123",
			Email:          "raced@example.com",
			EmailVerified:  true,
		}
		user, linked, created, err := svc.(*service).createUserAndLink(ctx, "google", info)
		if err != nil {
			t.Fatalf("expected successful race recovery, got err: %v", err)
		}
		if user.ID != winner.ID {
			t.Fatalf("expected linked user ID %v, got %v", winner.ID, user.ID)
		}
		if !linked {
			t.Fatal("expected linked to be true")
		}
		if created {
			t.Fatal("expected created to be false (reused winning user)")
		}

		// Verify oauth_accounts has the link
		var link db.OAuthAccount
		if err := database.Where("provider_id = ? AND provider_user_id = ?", "google", "raced-subject-123").First(&link).Error; err != nil {
			t.Fatalf("failed to query recovered link: %v", err)
		}
		if link.UserID != winner.ID {
			t.Fatalf("expected link user_id %v, got %v", winner.ID, link.UserID)
		}
	})

	t.Run("race loser rejected if winner email unverified", func(t *testing.T) {
		database, _, _, svc := setupServiceTest(t, nil)
		ctx := context.Background()

		unverifiedWinner := db.User{
			ID:            uuid.New(),
			Email:         "unverified@example.com",
			PasswordHash:  "hash",
			EmailVerified: false,
		}
		if err := database.Create(&unverifiedWinner).Error; err != nil {
			t.Fatalf("seed unverified: %v", err)
		}

		info := &UserInfo{
			ProviderUserID: "raced-subject-unverified",
			Email:          "unverified@example.com",
			EmailVerified:  true,
		}
		_, _, _, err := svc.(*service).createUserAndLink(ctx, "google", info)
		if !errors.Is(err, errors.ErrOAuthAccountLinkConflict) {
			t.Fatalf("expected ErrOAuthAccountLinkConflict, got %v", err)
		}
	})

	t.Run("race loser with unverified provider email never merges", func(t *testing.T) {
		database, _, _, svc := setupServiceTest(t, nil)
		ctx := context.Background()

		winner := db.User{
			ID:            uuid.New(),
			Email:         "raced-unverified@example.com",
			PasswordHash:  "hash",
			EmailVerified: true,
		}
		if err := database.Create(&winner).Error; err != nil {
			t.Fatalf("seed winner: %v", err)
		}

		info := &UserInfo{
			ProviderUserID: "raced-unverified-subject",
			Email:          "raced-unverified@example.com",
			EmailVerified:  false,
		}
		_, _, _, err := svc.(*service).createUserAndLink(ctx, "facebook", info)
		if !errors.Is(err, errors.ErrOAuthEmailUnverified) {
			t.Fatalf("expected ErrOAuthEmailUnverified, got %v", err)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0 (no merge on an unverified claim)", n)
		}
	})
}

func TestService_SubjectCaseSensitivity(t *testing.T) {
	_, _, _, svc := setupServiceTest(t, nil)
	ctx := context.Background()

	upperInfo := &UserInfo{
		ProviderUserID: "Subject_CASE_123",
		Email:          "upper@example.com",
		EmailVerified:  true,
	}
	lowerInfo := &UserInfo{
		ProviderUserID: "subject_case_123",
		Email:          "lower@example.com",
		EmailVerified:  true,
	}

	u1, linked1, created1, err1 := svc.(*service).createUserAndLink(ctx, "google", upperInfo)
	if err1 != nil || !linked1 || !created1 {
		t.Fatalf("create upper failed: %v", err1)
	}

	u2, linked2, created2, err2 := svc.(*service).createUserAndLink(ctx, "google", lowerInfo)
	if err2 != nil || !linked2 || !created2 {
		t.Fatalf("create lower failed: %v", err2)
	}

	if u1.ID == u2.ID {
		t.Fatalf("expected distinct users for case-variant provider subjects, got identical ID: %v", u1.ID)
	}

	// Verify lookups resolve distinct accounts
	l1, found1, err := svc.(*service).findLink(ctx, "google", "Subject_CASE_123")
	if err != nil || !found1 || l1.UserID != u1.ID {
		t.Fatalf("upper lookup mismatch: found=%v, err=%v, link=%+v", found1, err, l1)
	}

	l2, found2, err := svc.(*service).findLink(ctx, "google", "subject_case_123")
	if err != nil || !found2 || l2.UserID != u2.ID {
		t.Fatalf("lower lookup mismatch: found=%v, err=%v, link=%+v", found2, err, l2)
	}
}

type retryProxyStore struct {
	db.Store
	attempt   int
	onAttempt func(attempt int, base db.Store) db.Store
}

func (r *retryProxyStore) Transaction(ctx context.Context, fn func(txStore db.Store) error) error {
	var err error
	for i := 1; i <= 2; i++ {
		r.attempt = i
		txStore := r.onAttempt(i, r.Store)
		err = fn(txStore)
		if err == nil {
			return nil
		}
	}
	return err
}

type wrappedTxStore struct {
	db.Store
	users db.UserStore
	oauth db.OAuthAccountStore
}

func (w *wrappedTxStore) Users() db.UserStore {
	if w.users != nil {
		return w.users
	}
	return w.Store.Users()
}

func (w *wrappedTxStore) OAuthAccounts() db.OAuthAccountStore {
	if w.oauth != nil {
		return w.oauth
	}
	return w.Store.OAuthAccounts()
}

type interceptUserStore struct {
	db.UserStore
	createFunc func(ctx context.Context, u *db.User) error
}

func (i *interceptUserStore) Create(ctx context.Context, u *db.User) error {
	if i.createFunc != nil {
		return i.createFunc(ctx, u)
	}
	return i.UserStore.Create(ctx, u)
}

type interceptOAuthStore struct {
	db.OAuthAccountStore
	createFunc func(ctx context.Context, a *db.OAuthAccount) error
}

func (i *interceptOAuthStore) Create(ctx context.Context, a *db.OAuthAccount) error {
	if i.createFunc != nil {
		return i.createFunc(ctx, a)
	}
	return i.OAuthAccountStore.Create(ctx, a)
}

func TestService_CreateUserAndLink_RetryIsolation(t *testing.T) {
	t.Run("linkConflict on attempt 1 does not leak into attempt 2 failure", func(t *testing.T) {
		_, _, _, rawSvc := setupServiceTest(t, nil)
		svc := rawSvc.(*service)
		ctx := context.Background()

		networkErr := fmt.Errorf("fatal network timeout on attempt 2")
		proxyStore := &retryProxyStore{
			Store: svc.store,
			onAttempt: func(attempt int, base db.Store) db.Store {
				if attempt == 1 {
					// Attempt 1: Users().Create succeeds, OAuthAccounts().Create returns unique conflict
					return &wrappedTxStore{
						Store: base,
						oauth: &interceptOAuthStore{
							OAuthAccountStore: base.OAuthAccounts(),
							createFunc: func(ctx context.Context, a *db.OAuthAccount) error {
								return errors.ErrOAuthAccountAlreadyLinked
							},
						},
					}
				}
				// Attempt 2: Users().Create fails with unexpected non-conflict network error
				return &wrappedTxStore{
					Store: base,
					users: &interceptUserStore{
						UserStore: base.Users(),
						createFunc: func(ctx context.Context, u *db.User) error {
							return networkErr
						},
					},
				}
			},
		}

		testSvc := &service{
			store:      proxyStore,
			sessionSvc: svc.sessionSvc,
			providers:  svc.providers,
			cfg:        svc.cfg,
		}

		info := &UserInfo{
			ProviderUserID: "retry-sub-link-conflict",
			Email:          "retry-link@example.com",
			EmailVerified:  true,
		}

		_, _, _, err := testSvc.createUserAndLink(ctx, "google", info)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) {
			t.Fatalf("expected *errors.Error, got %T: %v", err, err)
		}
		if appErr.Code() != errors.CodeInternalError {
			t.Fatalf("expected CodeInternalError, got: %v", appErr.Code())
		}
		if !strings.Contains(appErr.Message(), "failed to create oauth user") {
			t.Fatalf("expected op 'failed to create oauth user', got: %v", appErr.Message())
		}
		if !strings.Contains(err.Error(), "fatal network timeout") {
			t.Fatalf("expected underlying error 'fatal network timeout', got: %v", err)
		}
	})

	t.Run("userConflict on attempt 1 does not leak into attempt 2 failure", func(t *testing.T) {
		_, _, _, rawSvc := setupServiceTest(t, nil)
		svc := rawSvc.(*service)
		ctx := context.Background()

		diskErr := fmt.Errorf("disk full during oauth link on attempt 2")
		proxyStore := &retryProxyStore{
			Store: svc.store,
			onAttempt: func(attempt int, base db.Store) db.Store {
				if attempt == 1 {
					// Attempt 1: Users().Create returns user conflict
					return &wrappedTxStore{
						Store: base,
						users: &interceptUserStore{
							UserStore: base.Users(),
							createFunc: func(ctx context.Context, u *db.User) error {
								return errors.ErrEmailAlreadyExists
							},
						},
					}
				}
				// Attempt 2: Users().Create succeeds, OAuthAccounts().Create fails with non-conflict error
				return &wrappedTxStore{
					Store: base,
					oauth: &interceptOAuthStore{
						OAuthAccountStore: base.OAuthAccounts(),
						createFunc: func(ctx context.Context, a *db.OAuthAccount) error {
							return diskErr
						},
					},
				}
			},
		}

		testSvc := &service{
			store:      proxyStore,
			sessionSvc: svc.sessionSvc,
			providers:  svc.providers,
			cfg:        svc.cfg,
		}

		info := &UserInfo{
			ProviderUserID: "retry-sub-user-conflict",
			Email:          "retry-user@example.com",
			EmailVerified:  true,
		}

		_, _, _, err := testSvc.createUserAndLink(ctx, "google", info)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) {
			t.Fatalf("expected *errors.Error, got %T: %v", err, err)
		}
		if appErr.Code() != errors.CodeInternalError {
			t.Fatalf("expected CodeInternalError, got: %v", appErr.Code())
		}
		if !strings.Contains(appErr.Message(), "failed to link oauth account") {
			t.Fatalf("expected op 'failed to link oauth account', got: %v", appErr.Message())
		}
		if !strings.Contains(err.Error(), "disk full during oauth link") {
			t.Fatalf("expected underlying error 'disk full during oauth link', got: %v", err)
		}
	})
}

func TestOAuthService_X_MissingEmail(t *testing.T) {
	database := serviceTestDB(t)
	cfg := serviceTestConfig()

	xInfo := &UserInfo{
		ProviderID:     "x",
		ProviderUserID: "x-user-999",
		Email:          "",
		EmailVerified:  false,
		Name:           "X User",
		AvatarURL:      "https://example.com/avatar.png",
	}

	stub := &stubProvider{id: "x", info: xInfo}
	svc := NewService(database, session.NewService(database, cfg),
		map[string]Provider{"x": stub}, cfg)

	t.Run("unauthenticated registration with missing email fails closed", func(t *testing.T) {
		state, cookie := mustInitiate(t, svc, cfg, "x")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/x/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		_, _, _, err := svc.HandleCallback(context.Background(), rec, req, "x", "test-code", state, db.SessionTypeCookie)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthEmailRequired) {
			t.Fatalf("expected ErrOAuthEmailRequired, got %v", err)
		}

		// Invariant: zero synthetic users or link rows created in database
		var userCount, linkCount int64
		if err := database.Model(&db.User{}).Count(&userCount).Error; err != nil {
			t.Fatalf("count users: %v", err)
		}
		if err := database.Model(&db.OAuthAccount{}).Count(&linkCount).Error; err != nil {
			t.Fatalf("count links: %v", err)
		}
		if userCount != 0 {
			t.Fatalf("expected 0 users created, got %d", userCount)
		}
		if linkCount != 0 {
			t.Fatalf("expected 0 links created, got %d", linkCount)
		}
	})

	t.Run("returning user with pre-linked account succeeds without email", func(t *testing.T) {
		owner := seedLinkedIdentity(t, database, "x", "x-user-999")

		state, cookie := mustInitiate(t, svc, cfg, "x")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/x/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		sess, rawID, _, err := svc.HandleCallback(context.Background(), rec, req, "x", "test-code", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("unexpected callback error: %v", err)
		}
		if sess == nil || rawID == "" {
			t.Fatal("expected valid session and token")
		}
		if sess.UserID != owner.ID {
			t.Fatalf("sess.UserID = %v; want %v", sess.UserID, owner.ID)
		}
	})

	t.Run("active session links provider account without email", func(t *testing.T) {
		sessSvc := session.NewService(database, cfg)
		user := db.User{
			ID:            uuid.New(),
			Email:         "active-session-user@example.com",
			EmailVerified: true,
		}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}

		sess, rawToken, err := sessSvc.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		if sess == nil || rawToken == "" {
			t.Fatal("session required")
		}

		initReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/x?link=true", nil)
		initReq.AddCookie(&http.Cookie{
			Name:  cfg.SessionCookieName,
			Value: rawToken,
		})
		initRec := httptest.NewRecorder()

		activeStub := &stubProvider{id: "x", info: &UserInfo{ProviderID: "x", ProviderUserID: "x-active-user-123", Email: ""}}
		activeSvc := NewService(database, sessSvc, map[string]Provider{"x": activeStub}, cfg)

		authURL, err := activeSvc.InitiateFlow(initRec, initReq, "x")
		if err != nil {
			t.Fatalf("initiate flow failed: %v", err)
		}
		if authURL == "" {
			t.Fatal("expected non-empty auth url")
		}

		var stateCookie *http.Cookie
		for _, c := range initRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				stateCookie = c
				break
			}
		}
		if stateCookie == nil {
			t.Fatal("state cookie required")
		}

		// Extract state query param from authURL
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse auth url: %v", err)
		}
		state := u.Query().Get("state")

		cbReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/x/callback?code=valid-code&state="+state, nil)
		cbReq.AddCookie(stateCookie)
		cbReq.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawToken})
		cbRec := httptest.NewRecorder()

		cbSess, _, _, err := activeSvc.HandleCallback(context.Background(), cbRec, cbReq, "x", "valid-code", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("callback failed for active user link: %v", err)
		}
		if cbSess.UserID != user.ID {
			t.Fatalf("expected session user %v, got %v", user.ID, cbSess.UserID)
		}

		// Verify oauth_accounts link was created
		var count int64
		if err := database.Model(&db.OAuthAccount{}).Where("provider_id = ? AND user_id = ?", "x", user.ID).Count(&count).Error; err != nil {
			t.Fatalf("count links: %v", err)
		}
		if count != 1 {
			t.Fatalf("expected 1 link for user, got %d", count)
		}
	})

	t.Run("subsequent login with linked subject-only identity succeeds and preserves link", func(t *testing.T) {
		sessSvc := session.NewService(database, cfg)
		user := db.User{
			ID:            uuid.New(),
			Email:         "active-subseq-user@example.com",
			EmailVerified: true,
		}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}

		_, rawToken, err := sessSvc.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		initReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/x?link=true", nil)
		initReq.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawToken})
		initRec := httptest.NewRecorder()

		stub := &stubProvider{id: "x", info: &UserInfo{ProviderID: "x", ProviderUserID: "x-subseq-user-456", Email: "", EmailVerified: false}}
		xSvc := NewService(database, sessSvc, map[string]Provider{"x": stub}, cfg)

		authURL, err := xSvc.InitiateFlow(initRec, initReq, "x")
		if err != nil {
			t.Fatalf("initiate flow failed: %v", err)
		}
		u, _ := url.Parse(authURL)
		state := u.Query().Get("state")

		var stateCookie *http.Cookie
		for _, c := range initRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				stateCookie = c
				break
			}
		}

		// Explicit link
		cbReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/x/callback?code=valid-code&state="+state, nil)
		cbReq.AddCookie(stateCookie)
		cbReq.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawToken})
		cbRec := httptest.NewRecorder()

		cbSess, _, _, err := xSvc.HandleCallback(context.Background(), cbRec, cbReq, "x", "valid-code", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("callback failed for active user link: %v", err)
		}
		if cbSess.UserID != user.ID {
			t.Fatalf("expected session user %v, got %v", user.ID, cbSess.UserID)
		}

		// Subsequent login (unauthenticated, returning user)
		loginState, loginCookie := mustInitiate(t, xSvc, cfg, "x")
		loginReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/x/callback", nil)
		loginReq.AddCookie(loginCookie)
		loginRec := httptest.NewRecorder()

		loginSess, _, _, err := xSvc.HandleCallback(context.Background(), loginRec, loginReq, "x", "login-code", loginState, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("subsequent login failed: %v; want successful login", err)
		}
		if loginSess.UserID != user.ID {
			t.Fatalf("expected session user %v, got %v", user.ID, loginSess.UserID)
		}

		// Verify link was not deleted by the unverified-link invalidation rule
		var link db.OAuthAccount
		if err := database.Where("provider_id = ? AND provider_user_id = ?", "x", "x-subseq-user-456").First(&link).Error; err != nil {
			t.Fatalf("expected link to persist, got err: %v", err)
		}
		if link.UserID != user.ID {
			t.Fatalf("expected link user %v, got %v", user.ID, link.UserID)
		}
	})

	t.Run("untrusted tenant token is rejected with ErrOAuthTenantInvalid", func(t *testing.T) {
		sessSvc := session.NewService(database, cfg)
		// Mock profile carrying untrusted_tenant claim
		untrustedInfo := &UserInfo{
			ProviderID:     "microsoft",
			ProviderUserID: "ms-untrusted-sub",
			Email:          "victim@example.com",
			EmailVerified:  false,
			Name:           "Untrusted Tenant User",
			RawClaims: map[string]any{
				"untrusted_tenant": true,
			},
		}
		mockMS := &stubProvider{
			id:   "microsoft",
			info: untrustedInfo,
		}
		msSvc := NewService(database, sessSvc, map[string]Provider{"microsoft": mockMS}, cfg)

		state, cookie := mustInitiate(t, msSvc, cfg, "microsoft")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		_, _, _, err := msSvc.HandleCallback(context.Background(), rec, req, "microsoft", "code", state, db.SessionTypeCookie)
		if !errors.Is(err, errors.ErrOAuthTenantInvalid) {
			t.Fatalf("expected ErrOAuthTenantInvalid, got %v", err)
		}
	})
}

func TestHandleCallbackActiveSessionUntrustedTenant(t *testing.T) {
	t.Run("signed-in link with untrusted tenant fails closed", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, _ := setupServiceTest(t, verifiedInfo())
		sessSvc := session.NewService(database, cfg)
		user := db.User{ID: uuid.New(), Email: "victim@example.com", PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		_, rawToken, err := sessSvc.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		untrusted := &stubProvider{id: "microsoft", info: &UserInfo{
			ProviderID: "microsoft", ProviderUserID: "ms-attacker-sub",
			Email: "victim@example.com", EmailVerified: true, Name: "Attacker",
			RawClaims: map[string]any{"untrusted_tenant": true},
		}}
		svc := NewService(database, sessSvc, map[string]Provider{"microsoft": untrusted}, cfg)

		initReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft?link=true", nil)
		initReq.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawToken})
		initRec := httptest.NewRecorder()
		authURL, err := svc.InitiateFlow(initRec, initReq, "microsoft")
		if err != nil {
			t.Fatalf("initiate flow failed: %v", err)
		}
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse auth url: %v", err)
		}
		state := u.Query().Get("state")
		var stateCookie *http.Cookie
		for _, c := range initRec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				stateCookie = c
			}
		}
		if stateCookie == nil {
			t.Fatal("state cookie required")
		}
		cbReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
		cbReq.AddCookie(stateCookie)
		cbReq.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawToken})
		_, _, _, err = svc.HandleCallback(context.Background(), httptest.NewRecorder(), cbReq, "microsoft", "code-1", state, db.SessionTypeCookie)
		if !errors.Is(err, errors.ErrOAuthTenantInvalid) {
			t.Fatalf("expected ErrOAuthTenantInvalid, got %v", err)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0", n)
		}
	})
}

func TestHandleCallback_MicrosoftLegacyOIDFallback(t *testing.T) {
	t.Run("resolves legacy oid link on unattested email and migrates to sub", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, _ := setupServiceTest(t, verifiedInfo())
		sessSvc := session.NewService(database, cfg)

		user := db.User{
			ID:            uuid.New(),
			Email:         "ms-user@example.com",
			EmailVerified: true,
		}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		legacyLink := db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         user.ID,
			ProviderID:     "microsoft",
			ProviderUserID: "legacy-oid-guid-123",
			Email:          user.Email,
			Verified:       true,
		}
		if err := database.Create(&legacyLink).Error; err != nil {
			t.Fatalf("create legacy link: %v", err)
		}

		msInfo := &UserInfo{
			ProviderID:     "microsoft",
			ProviderUserID: "new-pairwise-sub-456",
			Email:          "ms-user@example.com",
			EmailVerified:  false,
			Name:           "MS User",
			RawClaims: map[string]any{
				"sub": "new-pairwise-sub-456",
				"oid": "legacy-oid-guid-123",
			},
		}
		mockMS := &stubProvider{id: "microsoft", info: msInfo}
		svc := NewService(database, sessSvc, map[string]Provider{"microsoft": mockMS}, cfg)

		state, cookie := mustInitiate(t, svc, cfg, "microsoft")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		sess, _, _, err := svc.HandleCallback(context.Background(), rec, req, "microsoft", "code", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback failed: %v", err)
		}
		if sess == nil || sess.UserID != user.ID {
			t.Fatalf("expected session for user %s, got %v", user.ID, sess)
		}

		var updatedLink db.OAuthAccount
		if err := database.Where("id = ?", legacyLink.ID).First(&updatedLink).Error; err != nil {
			t.Fatalf("failed to query updated link: %v", err)
		}
		if updatedLink.ProviderUserID != "new-pairwise-sub-456" {
			t.Fatalf("expected link to be migrated to new-pairwise-sub-456, got %s", updatedLink.ProviderUserID)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("expected exactly 1 oauth_accounts row, found %d", n)
		}
	})

	t.Run("resolves link directly by sub when already migrated", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, _ := setupServiceTest(t, verifiedInfo())
		sessSvc := session.NewService(database, cfg)

		user := db.User{
			ID:            uuid.New(),
			Email:         "ms-sub@example.com",
			EmailVerified: true,
		}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		link := db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         user.ID,
			ProviderID:     "microsoft",
			ProviderUserID: "direct-sub-789",
			Email:          user.Email,
			Verified:       true,
		}
		if err := database.Create(&link).Error; err != nil {
			t.Fatalf("create link: %v", err)
		}

		msInfo := &UserInfo{
			ProviderID:     "microsoft",
			ProviderUserID: "direct-sub-789",
			Email:          "ms-sub@example.com",
			EmailVerified:  true,
			Name:           "MS Sub User",
			RawClaims: map[string]any{
				"sub": "direct-sub-789",
				"oid": "directory-oid-999",
			},
		}
		mockMS := &stubProvider{id: "microsoft", info: msInfo}
		svc := NewService(database, sessSvc, map[string]Provider{"microsoft": mockMS}, cfg)

		state, cookie := mustInitiate(t, svc, cfg, "microsoft")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		sess, _, _, err := svc.HandleCallback(context.Background(), rec, req, "microsoft", "code", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback failed: %v", err)
		}
		if sess == nil || sess.UserID != user.ID {
			t.Fatalf("expected session for user %s, got %v", user.ID, sess)
		}
	})

	t.Run("legacy oid fallback does not insert duplicate when email is attested", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, _ := setupServiceTest(t, verifiedInfo())
		sessSvc := session.NewService(database, cfg)

		user := db.User{
			ID:            uuid.New(),
			Email:         "ms-attested@example.com",
			EmailVerified: true,
		}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
		legacyLink := db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         user.ID,
			ProviderID:     "microsoft",
			ProviderUserID: "legacy-oid-attested",
			Email:          user.Email,
			Verified:       true,
		}
		if err := database.Create(&legacyLink).Error; err != nil {
			t.Fatalf("create legacy link: %v", err)
		}

		msInfo := &UserInfo{
			ProviderID:     "microsoft",
			ProviderUserID: "sub-attested-new",
			Email:          "ms-attested@example.com",
			EmailVerified:  true,
			Name:           "MS Attested User",
			RawClaims: map[string]any{
				"sub": "sub-attested-new",
				"oid": "legacy-oid-attested",
			},
		}
		mockMS := &stubProvider{id: "microsoft", info: msInfo}
		svc := NewService(database, sessSvc, map[string]Provider{"microsoft": mockMS}, cfg)

		state, cookie := mustInitiate(t, svc, cfg, "microsoft")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		sess, _, _, err := svc.HandleCallback(context.Background(), rec, req, "microsoft", "code", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback failed: %v", err)
		}
		if sess == nil || sess.UserID != user.ID {
			t.Fatalf("expected session for user %s, got %v", user.ID, sess)
		}

		if n := countRows(t, database, &db.OAuthAccount{}); n != 1 {
			t.Fatalf("expected 1 row (migrated, not duplicated), got %d", n)
		}
	})

	t.Run("propagates 500 when legacy oid lookup fails with database error", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, _ := setupServiceTest(t, verifiedInfo())
		sessSvc := session.NewService(database, cfg)

		user := db.User{
			ID:            uuid.New(),
			Email:         "ms-err@example.com",
			EmailVerified: false,
		}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}

		msInfo := &UserInfo{
			ProviderID:     "microsoft",
			ProviderUserID: "new-sub-err",
			Email:          "ms-err@example.com",
			EmailVerified:  false,
			Name:           "MS Error User",
			RawClaims: map[string]any{
				"sub": "new-sub-err",
				"oid": "faulty-oid-123",
			},
		}
		mockMS := &stubProvider{id: "microsoft", info: msInfo}

		baseStore := gormstore.New(database)
		faultyAccounts := &faultyOAuthAccountStore{
			OAuthAccountStore: baseStore.OAuthAccounts(),
			errOnUID:          "faulty-oid-123",
		}
		faultyStore := &faultyStoreWrapper{
			Store:    baseStore,
			accounts: faultyAccounts,
		}

		svc := NewServiceWithStore(faultyStore, sessSvc, map[string]Provider{"microsoft": mockMS}, cfg)

		state, cookie := mustInitiate(t, svc, cfg, "microsoft")
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		_, _, _, err := svc.HandleCallback(context.Background(), rec, req, "microsoft", "code", state, db.SessionTypeCookie)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !stderrors.As(err, &appErr) {
			t.Fatalf("expected *errors.Error, got %T: %v", err, err)
		}
		if appErr.Code() != errors.CodeInternalError {
			t.Fatalf("expected CodeInternalError (500), got %s", appErr.Code())
		}
	})
}

type faultyOAuthAccountStore struct {
	db.OAuthAccountStore
	errOnUID string
}

func (s *faultyOAuthAccountStore) GetByProvider(ctx context.Context, providerID, providerUserID string) (*db.OAuthAccount, error) {
	if providerUserID == s.errOnUID {
		return nil, stderrors.New("simulated database failure")
	}
	return s.OAuthAccountStore.GetByProvider(ctx, providerID, providerUserID)
}

type faultyStoreWrapper struct {
	db.Store
	accounts db.OAuthAccountStore
}

func (w *faultyStoreWrapper) OAuthAccounts() db.OAuthAccountStore {
	return w.accounts
}

// TestFacebookFirstSignup drives the real Facebook adapter through the linking
// engine: the Graph email decides whether a first-time signup can complete.
func TestFacebookFirstSignup(t *testing.T) {
	const appID = "fb-test-app"

	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/access_token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			writeFixture(t, w, `{"access_token":%q,"token_type":"bearer"}`, "token-"+r.PostFormValue("code"))
		case "/debug_token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.PostFormValue("input_token") == "" {
				http.Error(w, "missing input_token", http.StatusBadRequest)
				return
			}
			writeFixture(t, w, `{"data":{"app_id":%q,"is_valid":true}}`, appID)
		case "/me":
			switch strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") {
			case "token-code-with-email":
				writeFixture(t, w, `{"id":"fb-1001","name":"Alice","email":"alice@fb-test.com"}`)
			case "token-code-without-email":
				writeFixture(t, w, `{"id":"fb-1002","name":"Bob"}`)
			default:
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(graph.Close)

	newService := func(t *testing.T) (*gorm.DB, *config.Config, Service) {
		t.Helper()
		database := serviceTestDB(t)
		cfg := serviceTestConfig()
		p := NewFacebookProvider(config.FacebookConfig{
			AppID:        appID,
			AppSecret:    "fb-test-secret",
			RedirectURI:  "https://example.com/callback",
			GraphVersion: "v19.0",
		})
		p.tokenURL = graph.URL + "/oauth/access_token"
		p.debugURL = graph.URL + "/debug_token"
		p.userInfoURL = graph.URL + "/me"
		return database, cfg, NewService(database, session.NewService(database, cfg),
			map[string]Provider{"facebook": p}, cfg)
	}

	t.Run("first signup with an unverified Graph email registers an unverified user", func(t *testing.T) {
		database, cfg, svc := newService(t)
		state, cookie := mustInitiate(t, svc, cfg, "facebook")
		rec, req := callbackRequest(state, cookie)
		sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "facebook", "code-with-email", state, db.SessionTypeCookie)
		if err != nil {
			t.Fatalf("HandleCallback = %v; want first-time facebook signup", err)
		}
		var user db.User
		if err := database.Where("id = ?", sess.UserID).First(&user).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		if user.Email != "alice@fb-test.com" || user.EmailVerified {
			t.Fatalf("user email=%q verified=%v; want alice@fb-test.com/false", user.Email, user.EmailVerified)
		}
		// The row records that Meta did not attest the address, which is what
		// keeps it out of merge, recovery, and email resolution.
		requireIdentityRows(t, database, 1, 1, 1)
		var link db.OAuthAccount
		if err := database.Where("provider_id = ?", "facebook").First(&link).Error; err != nil {
			t.Fatalf("load link: %v", err)
		}
		if link.Verified {
			t.Fatal("facebook graph email must persist verified=false")
		}
	})

	t.Run("first signup without a Graph email is rejected", func(t *testing.T) {
		database, cfg, svc := newService(t)
		state, cookie := mustInitiate(t, svc, cfg, "facebook")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "facebook", "code-without-email", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthEmailRequired, http.StatusBadRequest)
		requireIdentityRows(t, database, 0, 0, 0)
	})
}

// TestProviderLookupCanonicalSlug pins the dynamic registry path: a registered
// provider must resolve under any casing, and the canonical slug is what reaches
// the store.
func TestProviderLookupCanonicalSlug(t *testing.T) {
	database := serviceTestDB(t)
	cfg := serviceTestConfig()
	info := &UserInfo{ProviderID: "custom-idp", ProviderUserID: "custom-sub-1",
		Email: "custom@example.com", EmailVerified: true}
	reg := NewRegistry()
	if err := reg.Register(&stubProvider{id: "custom-idp", info: info}); err != nil {
		t.Fatalf("register dynamic provider: %v", err)
	}
	svc := NewServiceWithRegistry(gormstore.New(database), session.NewService(database, cfg), reg, cfg)
	inner := svc.(*service)

	p, err := inner.providerFor("  Custom-IDP ")
	if err != nil || p == nil || p.ID() != "custom-idp" {
		t.Fatalf("providerFor(non-canonical) = %v, err = %v; want custom-idp", p, err)
	}

	_, err = inner.providerFor("missing")
	requireCode(t, err, errors.CodeOAuthProviderNotFound, http.StatusNotFound)

	state, cookie := mustInitiate(t, svc, cfg, "Custom-IDP")
	rec, req := callbackRequest(state, cookie)
	sess, _, _, err := svc.HandleCallback(req.Context(), rec, req, "Custom-IDP", "code-1", state, db.SessionTypeCookie)
	if err != nil {
		t.Fatalf("HandleCallback(non-canonical) = %v", err)
	}

	var link db.OAuthAccount
	if err := database.Where("provider_user_id = ?", "custom-sub-1").First(&link).Error; err != nil {
		t.Fatalf("load link: %v", err)
	}
	if link.ProviderID != "custom-idp" {
		t.Fatalf("stored provider_id = %q; want canonical custom-idp", link.ProviderID)
	}

	// A later login through the canonical slug must resolve the same identity.
	state, cookie = mustInitiate(t, svc, cfg, "custom-idp")
	rec, req = callbackRequest(state, cookie)
	again, _, _, err := svc.HandleCallback(req.Context(), rec, req, "custom-idp", "code-1", state, db.SessionTypeCookie)
	if err != nil {
		t.Fatalf("HandleCallback(canonical) = %v", err)
	}
	if again.UserID != sess.UserID || link.UserID != sess.UserID {
		t.Fatalf("second login user = %v; want %v", again.UserID, sess.UserID)
	}
	requireIdentityRows(t, database, 1, 1, 2)
}

// TestCallbackStateReplayAcrossSessions pins the state-to-session binding: a
// completed state value can never be replayed against another live session.
func TestCallbackStateReplayAcrossSessions(t *testing.T) {
	database, cfg, _, svc := setupServiceTest(t, &UserInfo{
		ProviderID: "google", ProviderUserID: "sub-replay-state",
		Email: "replay-state@example.com", EmailVerified: true,
	})
	sessSvc := session.NewService(database, cfg)
	seedSession := func(t *testing.T, email string) string {
		t.Helper()
		user := db.User{ID: uuid.New(), Email: email, PasswordHash: "hash", EmailVerified: true}
		if err := database.Create(&user).Error; err != nil {
			t.Fatalf("seed user: %v", err)
		}
		_, raw, err := sessSvc.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "ua")
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		return raw
	}
	tokA := seedSession(t, "replay-a@example.com")
	tokB := seedSession(t, "replay-b@example.com")

	state, cookie := initiateLinked(t, svc, cfg, "google", tokA)
	rec, req := callbackRequestWithSession(state, cookie, cfg, tokA)
	if _, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie); err != nil {
		t.Fatalf("first callback = %v", err)
	}

	rec, req = callbackRequestWithSession(state, cookie, cfg, tokB)
	_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
	requireCode(t, err, errors.CodeOAuthStateInvalid, http.StatusForbidden)
	requireIdentityRows(t, database, 2, 1, 3)
}

// TestResolveLinkUserID pins the guards that keep a broken session store loud
// and an absent context owner from becoming a link target.
func TestResolveLinkUserID(t *testing.T) {
	cfg := serviceTestConfig()
	newSvc := func(sessSvc session.Service) *service {
		return NewServiceWithStore(nil, sessSvc, nil, cfg).(*service)
	}
	sessionRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google?link=true", nil)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: "0123456789abcdef0123456789abcdef"})
		return req
	}
	contextRequest := func(v any) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth/google?link=true", nil)
		return req.WithContext(context.WithValue(context.Background(), ctxUserIDKey{}, v))
	}

	t.Run("store failure stays a 500", func(t *testing.T) {
		svc := newSvc(&failGetSessionSvc{err: errors.New(errors.CodeInternalError, "db down", nil)})
		_, err := svc.resolveLinkUserID(sessionRequest())
		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
	})

	t.Run("lapsed session degrades to login", func(t *testing.T) {
		svc := newSvc(&failGetSessionSvc{err: errors.ErrSessionInvalid})
		uid, err := svc.resolveLinkUserID(sessionRequest())
		if err != nil || uid != "" {
			t.Fatalf("resolveLinkUserID = %q, %v; want empty owner and nil error", uid, err)
		}
	})

	t.Run("missing session service fails closed", func(t *testing.T) {
		_, err := newSvc(nil).resolveLinkUserID(sessionRequest())
		requireCode(t, err, errors.CodeInternalError, http.StatusInternalServerError)
	})

	t.Run("nil uuid context owner degrades to login", func(t *testing.T) {
		svc := newSvc(&failGetSessionSvc{err: errors.ErrSessionInvalid})
		uid, err := svc.resolveLinkUserID(contextRequest(uuid.Nil))
		if err != nil || uid != "" {
			t.Fatalf("resolveLinkUserID(nil uuid) = %q, %v; want empty owner and nil error", uid, err)
		}
	})

	t.Run("valid uuid context owner resolves", func(t *testing.T) {
		want := uuid.New()
		svc := newSvc(&failGetSessionSvc{err: errors.ErrSessionInvalid})
		uid, err := svc.resolveLinkUserID(contextRequest(want))
		if err != nil || uid != want.String() {
			t.Fatalf("resolveLinkUserID = %q, %v; want %q", uid, err, want)
		}
	})

	t.Run("empty context owner degrades to login", func(t *testing.T) {
		svc := newSvc(&failGetSessionSvc{err: errors.ErrSessionInvalid})
		uid, err := svc.resolveLinkUserID(contextRequest(""))
		if err != nil || uid != "" {
			t.Fatalf("resolveLinkUserID(empty) = %q, %v; want empty owner and nil error", uid, err)
		}
	})
}
