package security_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
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
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

func pkceChal(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func setupAntiHijackingDB(t *testing.T) (*gorm.DB, db.Store) {
	t.Helper()
	name := fmt.Sprintf("file:anti_hijack_%s?mode=memory&cache=shared", uuid.New().String())
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
		t.Fatalf("schema error: %v", err)
	}
	return database, gormstore.New(database)
}

func TestSecurity_PreHijackingAccountLinkConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupAntiHijackingDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-anti-hijack-test-state-key-32b"
	cfg.OAuth.TokenKEK = secTokenKEK
	sessSvc := session.NewService(database, &cfg)

	// 1. Attacker pre-creates local account with victim's email (email_verified = false)
	victimEmail := "victim@target-corporation.com"
	attackerUser := &db.User{
		ID:            uuid.New(),
		Email:         victimEmail,
		PasswordHash:  "attacker-password-hash",
		EmailVerified: false, // NOT verified
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := store.Users().Create(ctx, attackerUser); err != nil {
		t.Fatalf("create pre-created user failed: %v", err)
	}

	// 2. Legitimate victim logs in via Microsoft OAuth with verified email
	mockMS := oauthmock.New("microsoft", "victim-ms-oid-999", victimEmail, true)
	defer mockMS.Close()

	reg := oauth.NewRegistry()
	_ = reg.Register(mockMS)

	svc := oauth.NewServiceWithRegistry(store, sessSvc, reg, &cfg)

	rec := httptest.NewRecorder()
	state, err := oauth.SetStateCookie(rec, &cfg, "microsoft", "v-pkce-123", "")
	if err != nil {
		t.Fatalf("SetStateCookie failed: %v", err)
	}
	mockMS.AuthURL(state, pkceChal("v-pkce-123"))

	cbReq := httptest.NewRequest("GET", "/auth/oauth/microsoft/callback?state="+state, nil)
	for _, c := range rec.Result().Cookies() {
		cbReq.AddCookie(c)
	}

	cbRec := httptest.NewRecorder()
	_, _, _, err = svc.HandleCallback(ctx, cbRec, cbReq, "microsoft", "code-1", state, db.SessionTypeCookie)

	// Invariant: Flow MUST be rejected with 409 Conflict (ErrOAuthAccountLinkConflict)
	if err == nil {
		t.Fatal("expected pre-hijacking attempt to fail with 409 Conflict, but succeeded")
	}
	if !errors.Is(err, errors.ErrOAuthAccountLinkConflict) {
		t.Fatalf("expected ErrOAuthAccountLinkConflict, got %v", err)
	}

	// Invariant: Local account remains untouched and no oauth_accounts row is linked
	var count int64
	if err := database.Model(&db.OAuthAccount{}).Count(&count).Error; err != nil {
		t.Fatalf("count links: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 oauth links created, got %d", count)
	}
}

func TestSecurity_Microsoft_nOauth_UntrustedTenantTakeover(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupAntiHijackingDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-anti-hijack-test-state-key-32b"
	cfg.OAuth.TokenKEK = secTokenKEK
	sessSvc := session.NewService(database, &cfg)

	// External untrusted tenant ID attempting to claim victim@company.com without domain verification.
	// Verified email pins the test to the tenant gate: the email gate must
	// NOT be able to satisfy this assertion on its own.
	mockMS := oauthmock.New("microsoft", "ms-attacker-controlled-sub", "victim@company.com", true)
	mockMS.SetRawClaims(map[string]any{"untrusted_tenant": true})
	defer mockMS.Close()

	reg := oauth.NewRegistry()
	_ = reg.Register(mockMS)

	svc := oauth.NewServiceWithRegistry(store, sessSvc, reg, &cfg)

	rec := httptest.NewRecorder()
	state, err := oauth.SetStateCookie(rec, &cfg, "microsoft", "v-verifier", "")
	if err != nil {
		t.Fatalf("SetStateCookie failed: %v", err)
	}
	mockMS.AuthURL(state, pkceChal("v-verifier"))

	cbReq := httptest.NewRequest("GET", "/auth/oauth/microsoft/callback?state="+state, nil)
	for _, c := range rec.Result().Cookies() {
		cbReq.AddCookie(c)
	}

	// The profile is verified, so only the untrusted-tenant gate can fail
	// this closed: assert its exact sentinel, not either-or.
	cbRec := httptest.NewRecorder()
	_, _, _, err = svc.HandleCallback(ctx, cbRec, cbReq, "microsoft", "code-ms", state, db.SessionTypeCookie)

	if err == nil {
		t.Fatal("expected untrusted tenant to fail, got nil")
	}
	if !errors.Is(err, errors.ErrOAuthTenantInvalid) {
		t.Fatalf("expected ErrOAuthTenantInvalid, got: %v", err)
	}

	var count int64
	if err := database.Model(&db.OAuthAccount{}).Count(&count).Error; err != nil {
		t.Fatalf("count links: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 oauth links created, got %d", count)
	}
}

// initiateState starts a flow, optionally authenticated as rawSession, and
// returns the state plus the signed state cookie carrying the selected user.
func initiateState(t *testing.T, svc oauth.Service, cfg *config.Config, providerID, rawSession string) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+providerID, nil)
	if rawSession != "" {
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawSession})
	}
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

func TestSecurity_UntrustedTenantNotLinkedForActiveSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupAntiHijackingDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-anti-hijack-test-state-key-32b"
	cfg.OAuth.TokenKEK = secTokenKEK
	sessSvc := session.NewService(database, &cfg)

	active := db.User{ID: uuid.New(), Email: "active@company.com", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&active).Error; err != nil {
		t.Fatalf("create active user: %v", err)
	}
	_, rawSession, err := sessSvc.CreateSession(ctx, active.ID, active.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Verified email, differing from the active user's: only the tenant marker
	// may reject this flow, and email matching must not bind it either.
	info := &oauth.UserInfo{
		ProviderID:       "microsoft",
		ProviderTenantID: oauthmock.MicrosoftTenantID,
		ProviderUserID:   "ms-untrusted-active-sub",
		Email:            "untrusted@external-tenant.example",
		EmailVerified:    true,
		RawClaims:        map[string]any{"untrusted_tenant": true},
	}
	reg := oauth.NewRegistry()
	_ = reg.Register(&untrustedTenantProvider{info: info})
	svc := oauth.NewServiceWithRegistry(store, sessSvc, reg, &cfg)

	state, stateCookie := initiateState(t, svc, &cfg, "microsoft", rawSession)
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback?state="+state, nil)
	cbReq.AddCookie(stateCookie)
	sess, _, _, err := svc.HandleCallback(ctx, httptest.NewRecorder(), cbReq, "microsoft", "code-ms", state, db.SessionTypeCookie)

	if sess != nil {
		t.Fatalf("session issued for %v; want none", sess.UserID)
	}
	if !errors.Is(err, errors.ErrOAuthTenantInvalid) {
		t.Fatalf("expected ErrOAuthTenantInvalid (403), got %v", err)
	}
	var links int64
	if err := database.Model(&db.OAuthAccount{}).Count(&links).Error; err != nil {
		t.Fatalf("count links: %v", err)
	}
	if links != 0 {
		t.Fatalf("expected 0 oauth links for an untrusted tenant, got %d", links)
	}
}

func TestSecurity_UntrustedTenantEvictsAndGatesExistingLink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupAntiHijackingDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-anti-hijack-test-state-key-32b"
	cfg.OAuth.TokenKEK = secTokenKEK
	sessSvc := session.NewService(database, &cfg)

	owner := db.User{ID: uuid.New(), Email: "linked@company.com", PasswordHash: "hash", EmailVerified: true}
	if err := database.Create(&owner).Error; err != nil {
		t.Fatalf("create owner: %v", err)
	}
	link := db.OAuthAccount{ID: uuid.New(), UserID: owner.ID, ProviderID: "microsoft",
		ProviderTenantID: oauthmock.MicrosoftTenantID,
		ProviderUserID:   "ms-untrusted-linked-sub", Email: owner.Email, Verified: true}
	if err := database.Create(&link).Error; err != nil {
		t.Fatalf("create link: %v", err)
	}

	info := &oauth.UserInfo{
		ProviderID:       "microsoft",
		ProviderTenantID: oauthmock.MicrosoftTenantID,
		ProviderUserID:   "ms-untrusted-linked-sub",
		Email:            "untrusted@external-tenant.example",
		EmailVerified:    true,
		RawClaims:        map[string]any{"untrusted_tenant": true},
	}
	reg := oauth.NewRegistry()
	_ = reg.Register(&untrustedTenantProvider{info: info})
	svc := oauth.NewServiceWithRegistry(store, sessSvc, reg, &cfg)

	state, stateCookie := initiateState(t, svc, &cfg, "microsoft", "")
	cbReq := httptest.NewRequest(http.MethodGet, "/auth/oauth/microsoft/callback?state="+state, nil)
	cbReq.AddCookie(stateCookie)
	sess, _, _, err := svc.HandleCallback(ctx, httptest.NewRecorder(), cbReq, "microsoft", "code-ms", state, db.SessionTypeCookie)
	if sess != nil {
		t.Fatalf("session issued for %v; want none", sess.UserID)
	}
	if !errors.Is(err, errors.ErrOAuthTenantInvalid) {
		t.Fatalf("expected ErrOAuthTenantInvalid, got %v", err)
	}

	var remainingLinks int64
	if err := database.Model(&db.OAuthAccount{}).Where("provider_id = ? AND provider_user_id = ?", "microsoft", "ms-untrusted-linked-sub").Count(&remainingLinks).Error; err != nil {
		t.Fatalf("count oauth links: %v", err)
	}
	if remainingLinks != 0 {
		t.Fatalf("expected 0 oauth links for untrusted tenant, got %d", remainingLinks)
	}
}

// untrustedTenantProvider serves a fixed profile carrying the Microsoft
// adapter's untrusted_tenant marker with a verified email, so the tenant guard
// is the only gate that can reject the flow.
type untrustedTenantProvider struct{ info *oauth.UserInfo }

func (p *untrustedTenantProvider) ID() string { return p.info.ProviderID }

func (p *untrustedTenantProvider) AuthURL(state, codeChallenge string) string {
	return "https://login.example.test/auth?state=" + state + "&code_challenge=" + codeChallenge
}

func (p *untrustedTenantProvider) AuthCodeURL(state, codeChallenge string, _ ...oauth.AuthCodeOption) string {
	return p.AuthURL(state, codeChallenge)
}

func (p *untrustedTenantProvider) ExchangeCode(context.Context, string, string) (*oauth.TokenResponse, error) {
	return &oauth.TokenResponse{AccessToken: "tenant-access-token"}, nil
}

func (p *untrustedTenantProvider) FetchUserInfo(context.Context, *oauth.TokenResponse) (*oauth.UserInfo, error) {
	return p.info, nil
}

func TestSecurity_MissingEmailFailClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupAntiHijackingDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-anti-hijack-test-state-key-32b"
	cfg.OAuth.TokenKEK = secTokenKEK
	sessSvc := session.NewService(database, &cfg)

	// Provider returns empty email
	mockX := oauthmock.New("x", "x-user-missing-email", "", false)
	defer mockX.Close()

	reg := oauth.NewRegistry()
	_ = reg.Register(mockX)

	svc := oauth.NewServiceWithRegistry(store, sessSvc, reg, &cfg)

	rec := httptest.NewRecorder()
	state, err := oauth.SetStateCookie(rec, &cfg, "x", "v-verifier", "")
	if err != nil {
		t.Fatalf("SetStateCookie failed: %v", err)
	}
	mockX.AuthURL(state, pkceChal("v-verifier"))

	cbReq := httptest.NewRequest("GET", "/auth/oauth/x/callback?state="+state, nil)
	for _, c := range rec.Result().Cookies() {
		cbReq.AddCookie(c)
	}

	cbRec := httptest.NewRecorder()
	_, _, _, err = svc.HandleCallback(ctx, cbRec, cbReq, "x", "code-x", state, db.SessionTypeCookie)

	if err == nil {
		t.Fatal("expected unauthenticated registration without email to fail closed, got nil")
	}
	if !errors.Is(err, errors.ErrOAuthEmailRequired) {
		t.Fatalf("expected ErrOAuthEmailRequired (400), got %v", err)
	}

	// Verify zero synthetic users created
	var count int64
	if err := database.Model(&db.User{}).Count(&count).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 users, got %d", count)
	}
}

func TestSecurity_StateCookieTamperingAndReplay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupAntiHijackingDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-anti-hijack-test-state-key-32b"
	cfg.OAuth.TokenKEK = secTokenKEK
	sessSvc := session.NewService(database, &cfg)

	mockGoogle := oauthmock.New("google", "google-sub-safe", "user@example.com", true)
	defer mockGoogle.Close()

	reg := oauth.NewRegistry()
	_ = reg.Register(mockGoogle)

	svc := oauth.NewServiceWithRegistry(store, sessSvc, reg, &cfg)

	rec := httptest.NewRecorder()
	state, err := oauth.SetStateCookie(rec, &cfg, "google", "v-verifier", "")
	if err != nil {
		t.Fatalf("SetStateCookie failed: %v", err)
	}
	mockGoogle.AuthURL(state, pkceChal("v-verifier"))

	// 1. Same-length tampered state -> 403 Forbidden via constant-time compare.
	tampered := state[:len(state)-1]
	if state[len(state)-1] == 'A' {
		tampered += "B"
	} else {
		tampered += "A"
	}
	tamperedReq := httptest.NewRequest("GET", "/auth/oauth/google/callback?state="+tampered, nil)
	for _, c := range rec.Result().Cookies() {
		tamperedReq.AddCookie(c)
	}
	_, _, _, err = svc.HandleCallback(ctx, httptest.NewRecorder(), tamperedReq, "google", "code", tampered, db.SessionTypeCookie)
	if !errors.Is(err, errors.ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid (403), got %v", err)
	}

	// 2. Missing cookie -> 403 Forbidden
	noCookieReq := httptest.NewRequest("GET", "/auth/oauth/google/callback?state="+state, nil)
	_, _, _, err = svc.HandleCallback(ctx, httptest.NewRecorder(), noCookieReq, "google", "code", state, db.SessionTypeCookie)
	if !errors.Is(err, errors.ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid (403), got %v", err)
	}

	// 3. First valid callback -> succeeds
	validReq := httptest.NewRequest("GET", "/auth/oauth/google/callback?state="+state, nil)
	for _, c := range rec.Result().Cookies() {
		validReq.AddCookie(c)
	}
	validRec := httptest.NewRecorder()
	sess, _, _, err := svc.HandleCallback(ctx, validRec, validReq, "google", "code", state, db.SessionTypeCookie)
	if err != nil {
		t.Fatalf("valid callback failed: %v", err)
	}
	if sess == nil {
		t.Fatal("expected valid session")
	}

	// 4. Replay attack: second callback with same state token -> 403 Forbidden
	replayReq := httptest.NewRequest("GET", "/auth/oauth/google/callback?state="+state, nil)
	for _, c := range rec.Result().Cookies() {
		replayReq.AddCookie(c)
	}
	_, _, _, err = svc.HandleCallback(ctx, httptest.NewRecorder(), replayReq, "google", "code", state, db.SessionTypeCookie)
	if !errors.Is(err, errors.ErrOAuthStateInvalid) {
		t.Fatalf("expected ErrOAuthStateInvalid on replay (403), got %v", err)
	}
}

func TestSecurity_AntiEnumerationDummyHashRunsOnce(t *testing.T) {
	// Not parallel: TotalAlloc is process-wide, and a parallel Argon2id pass
	// would mask a skipped dummy hash in the measured window.
	database, _ := setupAntiHijackingDB(t)
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"

	authSvc, err := auth.New(cfg, database, cfg.EmailHooks)
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	// Attempt password login with an email that has no user row, so the
	// lookup-miss branch must burn the configured dummy Argon2id work.
	var loginErr error
	alloc := allocDelta(func() {
		_, loginErr = authSvc.Login(context.Background(), db.LoginRequest{
			Email:    "no-such-user@example.com",
			Password: "AttemptedPassword#123",
		})
	})

	if loginErr == nil {
		t.Fatal("expected login to fail for unknown email, got nil")
	}
	if !errors.Is(loginErr, errors.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", loginErr)
	}

	// The oauth-only and missing-user entry points pin the configured work
	// floor; here the shape of the work is the property under test. One
	// derivation allocates exactly Memory*1024 bytes (Argon2 allocates one KiB
	// block per unit), so more than 1.5x means the lookup-miss branch burned the
	// dummy hash twice. Load can only raise TotalAlloc, and the 32 MiB of slack
	// at the default cost keeps the bound independent of the runner.
	derivation := uint64(cfg.Argon2.Memory) * 1024
	if alloc > derivation+derivation/2 {
		t.Fatalf("unknown-email login allocated %d bytes; want <= %d (a single Argon2id derivation at m=%d KiB)", alloc, derivation+derivation/2, cfg.Argon2.Memory)
	}
}

func TestSecurity_ZeroRawSecretsInTelemetry(t *testing.T) {
	t.Parallel()
	sink := &secLogSink{}
	logger := slog.New(slog.NewJSONHandler(sink, nil))
	prev := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(prev) })

	sensitiveSecrets := []string{
		"super-confidential-client-secret-12345",
		"super-confidential-app-secret-67890",
		"super-confidential-state-signing-hmac-32b",
		"auth-code-secret-nonce-1234567890",
	}

	// Create configs with these secrets
	msCfg := config.MicrosoftConfig{
		ClientID:     "ms-id",
		ClientSecret: sensitiveSecrets[0],
	}
	fbCfg := config.FacebookConfig{
		AppID:     "fb-id",
		AppSecret: sensitiveSecrets[1],
	}
	appCfg := config.DefaultConfig()
	appCfg.OAuth.StateSecret = sensitiveSecrets[2]

	logger.Info("config_audit", "microsoft", msCfg, "facebook", fbCfg, "oauth_config", appCfg.OAuth)

	loggedOutput := sink.String()

	for _, sec := range sensitiveSecrets[:3] {
		if strings.Contains(loggedOutput, sec) {
			t.Fatalf("CRITICAL SECURITY DEFECT: secret %q leaked in logs: %s", sec, loggedOutput)
		}
	}
	if !strings.Contains(loggedOutput, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in logs, got %s", loggedOutput)
	}
}
