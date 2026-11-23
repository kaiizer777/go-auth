package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http/httptest"
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
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider_id VARCHAR(32) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,
		created_at DATETIME, updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_uid UNIQUE (provider_id, provider_user_id)
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
	sessSvc := session.NewService(database, &cfg)

	// External untrusted tenant ID attempting to claim victim@company.com without domain verification
	untrustedInfo := &oauth.UserInfo{
		ProviderID:     "microsoft",
		ProviderUserID: "ms-attacker-controlled-sub",
		Email:          "victim@company.com",
		EmailVerified:  false,
		Name:           "Attacker Azure AD Admin",
		RawClaims: map[string]any{
			"untrusted_tenant": true,
		},
	}
	mockMS := oauthmock.New("microsoft", untrustedInfo.ProviderUserID, untrustedInfo.Email, false)
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

	// Also simulate untrusted tenant tag via Mock if needed
	// In service, untrusted external tenant returns ErrOAuthTenantInvalid
	cbRec := httptest.NewRecorder()
	_, _, _, err = svc.HandleCallback(ctx, cbRec, cbReq, "microsoft", "code-ms", state, db.SessionTypeCookie)

	// Since mockMS returns unverified email (false), it should fail closed
	if err == nil {
		t.Fatal("expected unverified tenant to fail, got nil")
	}
	if !errors.Is(err, errors.ErrOAuthEmailUnverified) && !errors.Is(err, errors.ErrOAuthTenantInvalid) {
		t.Fatalf("expected ErrOAuthTenantInvalid or ErrOAuthEmailUnverified, got: %v", err)
	}
}

func TestSecurity_MissingEmailFailClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupAntiHijackingDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-anti-hijack-test-state-key-32b"
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

	// 1. Tampered state in query parameter -> 403 Forbidden
	tamperedReq := httptest.NewRequest("GET", "/auth/oauth/google/callback?state=tampered-state-nonce", nil)
	for _, c := range rec.Result().Cookies() {
		tamperedReq.AddCookie(c)
	}
	_, _, _, err = svc.HandleCallback(ctx, httptest.NewRecorder(), tamperedReq, "google", "code", "tampered-state-nonce", db.SessionTypeCookie)
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

func TestSecurity_AntiEnumerationDummyHashTimingParity(t *testing.T) {
	t.Parallel()
	database, _ := setupAntiHijackingDB(t)
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"

	// Create an OAuth-only user (password_hash is empty or unusable)
	oauthUser := db.User{
		ID:            uuid.New(),
		Email:         "oauth-only-user@example.com",
		PasswordHash:  "", // OAuth-only passwordless account
		EmailVerified: true,
	}
	if err := database.Create(&oauthUser).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	authSvc, err := auth.New(cfg, database, cfg.EmailHooks)
	if err != nil {
		t.Fatalf("auth.New failed: %v", err)
	}

	// Attempt password login against OAuth-only account:
	// Invariant: Must burn dummy Argon2id hash and return ErrInvalidCredentials (401)
	start := time.Now()
	_, err = authSvc.Login(context.Background(), db.LoginRequest{
		Email:    oauthUser.Email,
		Password: "AttemptedPassword#123",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected login to fail for OAuth-only account, got nil")
	}
	if !errors.Is(err, errors.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// Measure dummy hash time directly to verify parity
	dummyHash, err := crypto.GenerateDummyHash(crypto.DefaultHashParams())
	if err != nil {
		t.Fatalf("GenerateDummyHash failed: %v", err)
	}
	dummyStart := time.Now()
	_, _ = crypto.VerifyPassword("AttemptedPassword#123", dummyHash)
	dummyElapsed := time.Since(dummyStart)

	// Elapsed login time should be at least within 50% of the Argon2id computation
	if elapsed < (dummyElapsed / 2) {
		t.Fatalf("timing discrepancy: login elapsed %v, dummy hash took %v (indicates bypass of Argon2id)", elapsed, dummyElapsed)
	}
}

func TestSecurity_ZeroRawSecretsInTelemetry(t *testing.T) {
	t.Parallel()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	slog.SetDefault(logger)

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

	loggedOutput := logBuf.String()

	for _, sec := range sensitiveSecrets[:3] {
		if strings.Contains(loggedOutput, sec) {
			t.Fatalf("CRITICAL SECURITY DEFECT: secret %q leaked in logs: %s", sec, loggedOutput)
		}
	}
	if !strings.Contains(loggedOutput, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in logs, got %s", loggedOutput)
	}
}
