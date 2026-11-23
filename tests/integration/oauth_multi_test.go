package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/tests/oauthmock"
)

func pkceChal(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func setupMultiOAuthDB(t *testing.T) (*gorm.DB, db.Store) {
	t.Helper()
	name := fmt.Sprintf("file:multi_oauth_%s?mode=memory&cache=shared", uuid.New().String())
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
	return database, gormstore.New(database)
}

func TestIntegration_MultiProviderLinkageAndHardDeleteCascade(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupMultiOAuthDB(t)

	// 1. Create primary user
	user := &db.User{
		ID:            uuid.New(),
		Email:         "multi-provider-user@example.com",
		PasswordHash:  "",
		EmailVerified: true,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	if err := store.Users().Create(ctx, user); err != nil {
		t.Fatalf("create user failed: %v", err)
	}

	providers := []string{"google", "github", "apple", "microsoft", "facebook", "discord", "x"}

	// 2. Link all 7 providers to the single user
	for i, p := range providers {
		link := &db.OAuthAccount{
			ID:             uuid.New(),
			UserID:         user.ID,
			ProviderID:     p,
			ProviderUserID: fmt.Sprintf("%s-uid-%d", p, 1000+i),
			Email:          user.Email,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err := store.OAuthAccounts().Create(ctx, link); err != nil {
			t.Fatalf("link provider %q failed: %v", p, err)
		}
	}

	// 3. Verify all 7 providers resolve back to the same user
	for i, p := range providers {
		uid := fmt.Sprintf("%s-uid-%d", p, 1000+i)
		fetched, err := store.OAuthAccounts().GetByProvider(ctx, p, uid)
		if err != nil {
			t.Fatalf("GetByProvider(%q) failed: %v", p, err)
		}
		if fetched == nil || fetched.UserID != user.ID {
			t.Fatalf("provider %q returned unexpected user: got %v, want %v", p, fetched, user.ID)
		}
	}

	// Verify total links in database is 7
	var totalLinks int64
	if err := database.Model(&db.OAuthAccount{}).Count(&totalLinks).Error; err != nil {
		t.Fatalf("count links: %v", err)
	}
	if totalLinks != 7 {
		t.Fatalf("expected 7 linked accounts, got %d", totalLinks)
	}

	// 4. Hard-delete user: all 7 linked rows must cascade delete
	if err := database.Exec("DELETE FROM users WHERE id = ?", user.ID.String()).Error; err != nil {
		t.Fatalf("delete user failed: %v", err)
	}

	if err := database.Model(&db.OAuthAccount{}).Count(&totalLinks).Error; err != nil {
		t.Fatalf("count links after delete: %v", err)
	}
	if totalLinks != 0 {
		t.Fatalf("expected 0 linked accounts after cascade delete, got %d", totalLinks)
	}
}

func TestIntegration_MultiProviderCallbackExecution(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, store := setupMultiOAuthDB(t)

	cfg := config.DefaultConfig()
	cfg.OAuth.StateSecret = "super-secret-integration-test-state-key-32b"
	sessSvc := session.NewService(database, &cfg)

	// Set up mock IDP servers
	mockServers, err := oauthmock.NewMockServers()
	if err != nil {
		t.Fatalf("NewMockServers failed: %v", err)
	}
	defer mockServers.Close()

	reg := oauth.NewRegistry()

	// Register all 7 providers using mock or concrete adapters
	big3MockGoogle := oauthmock.New("google", "google-sub-1", "google-user@example.com", true)
	defer big3MockGoogle.Close()
	big3MockGitHub := oauthmock.New("github", "github-sub-2", "github-user@example.com", true)
	defer big3MockGitHub.Close()
	big3MockApple := oauthmock.New("apple", "apple-sub-3", "apple-user@example.com", true)
	defer big3MockApple.Close()

	_ = reg.Register(big3MockGoogle)
	_ = reg.Register(big3MockGitHub)
	_ = reg.Register(big3MockApple)

	// Create and register mock providers for Microsoft, Facebook, Discord, X
	mockDiscord := oauthmock.New("discord", mockServers.DiscordUserID, mockServers.DiscordEmail, true)
	defer mockDiscord.Close()
	mockFacebook := oauthmock.New("facebook", mockServers.FBUserID, mockServers.FBEmail, true)
	defer mockFacebook.Close()
	mockMicrosoft := oauthmock.New("microsoft", "ms-sub-778899", mockServers.MSEmail, true)
	defer mockMicrosoft.Close()
	mockX := oauthmock.New("x", mockServers.XUserID, "", false)
	defer mockX.Close()

	_ = reg.Register(mockDiscord)
	_ = reg.Register(mockFacebook)
	_ = reg.Register(mockMicrosoft)
	_ = reg.Register(mockX)

	svc := oauth.NewServiceWithRegistry(store, sessSvc, reg, &cfg)

	// 1. Google login creates new user and session
	recG := httptest.NewRecorder()
	stateG, err := oauth.SetStateCookie(recG, &cfg, "google", "v-code-1", "")
	if err != nil {
		t.Fatalf("SetStateCookie failed: %v", err)
	}
	big3MockGoogle.AuthURL(stateG, pkceChal("v-code-1"))
	reqG := httptest.NewRequest("GET", "/auth/oauth/google/callback?state="+stateG, nil)
	for _, c := range recG.Result().Cookies() {
		reqG.AddCookie(c)
	}

	sessG, rawIDG, _, err := svc.HandleCallback(ctx, httptest.NewRecorder(), reqG, "google", "code-g", stateG, db.SessionTypeCookie)
	if err != nil {
		t.Fatalf("HandleCallback(google) failed: %v", err)
	}
	if sessG == nil || rawIDG == "" {
		t.Fatal("expected valid session from google login")
	}

	// 2. Active session links Discord identity
	recD := httptest.NewRecorder()
	stateD, err := oauth.SetStateCookieWithUser(recD, &cfg, "discord", "v-code-2", "", sessG.UserID.String())
	if err != nil {
		t.Fatalf("SetStateCookieWithUser failed: %v", err)
	}
	mockDiscord.AuthURL(stateD, pkceChal("v-code-2"))
	reqD := httptest.NewRequest("GET", "/auth/oauth/discord/callback?state="+stateD, nil)
	for _, c := range recD.Result().Cookies() {
		reqD.AddCookie(c)
	}

	sessD, _, _, err := svc.HandleCallback(ctx, httptest.NewRecorder(), reqD, "discord", "code-d", stateD, db.SessionTypeCookie)
	if err != nil {
		t.Fatalf("HandleCallback(discord) failed: %v", err)
	}
	if sessD.UserID != sessG.UserID {
		t.Fatalf("expected discord to link to user %v, got %v", sessG.UserID, sessD.UserID)
	}

	// 3. Active session links X identity without email
	recX := httptest.NewRecorder()
	stateX, err := oauth.SetStateCookieWithUser(recX, &cfg, "x", "v-code-3", "", sessG.UserID.String())
	if err != nil {
		t.Fatalf("SetStateCookieWithUser failed: %v", err)
	}
	mockX.AuthURL(stateX, pkceChal("v-code-3"))
	reqX := httptest.NewRequest("GET", "/auth/oauth/x/callback?state="+stateX, nil)
	for _, c := range recX.Result().Cookies() {
		reqX.AddCookie(c)
	}

	sessX, _, _, err := svc.HandleCallback(ctx, httptest.NewRecorder(), reqX, "x", "code-x", stateX, db.SessionTypeCookie)
	if err != nil {
		t.Fatalf("HandleCallback(x) failed: %v", err)
	}
	if sessX.UserID != sessG.UserID {
		t.Fatalf("expected x to link to user %v, got %v", sessG.UserID, sessX.UserID)
	}

	// Verify that user now has 3 linked identities (google, discord, x)
	var linksCount int64
	if err := database.Model(&db.OAuthAccount{}).Where("user_id = ?", sessG.UserID.String()).Count(&linksCount).Error; err != nil {
		t.Fatalf("count links: %v", err)
	}
	if linksCount != 3 {
		t.Fatalf("expected 3 linked accounts, got %d", linksCount)
	}
}
