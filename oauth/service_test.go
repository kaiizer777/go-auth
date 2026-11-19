package oauth

import (
	"bytes"
	"context"
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

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
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
		ProviderUserID: providerUserID, Email: owner.Email}
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
	t.Run("unverified email rejected before any DB write", func(t *testing.T) {
		t.Parallel()
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-9", Email: "victim@example.com"})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		if n := countRows(t, database, &db.User{}); n != 0 {
			t.Fatalf("users = %d; want 0", n)
		}
		if n := countRows(t, database, &db.OAuthAccount{}); n != 0 {
			t.Fatalf("oauth_accounts = %d; want 0", n)
		}
		if n := countRows(t, database, &db.Session{}); n != 0 {
			t.Fatalf("sessions = %d; want 0", n)
		}
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

	t.Run("no link unverified email writes zero rows", func(t *testing.T) {
		database, cfg, _, svc := setupServiceTest(t,
			&UserInfo{ProviderID: "google", ProviderUserID: "sub-9", Email: "victim@example.com"})
		state, cookie := mustInitiate(t, svc, cfg, "google")
		rec, req := callbackRequest(state, cookie)
		_, _, _, err := svc.HandleCallback(req.Context(), rec, req, "google", "code-1", state, db.SessionTypeCookie)
		requireCode(t, err, errors.CodeOAuthEmailUnverified, http.StatusBadRequest)
		requireIdentityRows(t, database, 0, 0, 0)
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
				u, _, _, err := svc.linkOrCreate(context.Background(), "google", info)
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
			ProviderUserID: "sub-123", Email: owner.Email}
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
