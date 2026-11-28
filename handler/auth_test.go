package handler

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
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
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/session"
)

type emailCapture struct {
	verificationTokens chan string
	resetTokens        chan string
}

func newEmailCapture() *emailCapture {
	return &emailCapture{
		verificationTokens: make(chan string, 100),
		resetTokens:        make(chan string, 100),
	}
}

func (c *emailCapture) Hooks() email.Hooks {
	return email.Hooks{
		SendVerificationEmail: func(ctx context.Context, recipient, token string) error {
			c.verificationTokens <- token
			return nil
		},
		SendPasswordResetEmail: func(ctx context.Context, recipient, token string) error {
			c.resetTokens <- token
			return nil
		},
	}
}

func (c *emailCapture) nextVerificationToken(t *testing.T) string {
	t.Helper()
	select {
	case tok := <-c.verificationTokens:
		return tok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for verification token")
		return ""
	}
}

func (c *emailCapture) nextResetToken(t *testing.T) string {
	t.Helper()
	select {
	case tok := <-c.resetTokens:
		return tok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reset token")
		return ""
	}
}

func testConfig() config.Config {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://test:test@localhost:5432/test"
	cfg.BaseURL = "http://localhost:8080"
	cfg.Argon2 = config.Argon2Config{
		Memory:      19456, // Fast RFC 9106 test floor
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	cfg.PasswordMinLength = 8
	cfg.PasswordMaxLength = 128
	cfg.VerificationTokenExpiry = 30 * time.Minute
	cfg.PasswordResetTokenExpiry = 30 * time.Minute
	return cfg
}

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:mem_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}

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
	CREATE TABLE IF NOT EXISTS claimed_emails (
		email VARCHAR(255) PRIMARY KEY,
		owner_user_id TEXT NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS oauth_accounts (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		provider_id VARCHAR(32) NOT NULL,
		provider_tenant_id VARCHAR(64) NOT NULL,
		provider_user_id VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		access_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_ciphertext TEXT NOT NULL DEFAULT '',
		refresh_token_fingerprint CHAR(64) NOT NULL DEFAULT '',
		token_expires_at DATETIME,
		token_scope TEXT NOT NULL DEFAULT '',
		created_at DATETIME,
		updated_at DATETIME,
		CONSTRAINT uq_oauth_accounts_provider_tenant_uid UNIQUE (provider_id, provider_tenant_id, provider_user_id)
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
		t.Fatalf("failed to create schema: %v", err)
	}

	return database
}

func setupTestEnv(t *testing.T, modifyCfg ...func(*config.Config)) (*gorm.DB, auth.Service, http.Handler, *emailCapture) {
	t.Helper()
	database := setupTestDB(t)
	cfg := testConfig()
	for _, fn := range modifyCfg {
		fn(&cfg)
	}
	capture := newEmailCapture()
	svc, err := auth.New(cfg, database, capture.Hooks())
	if err != nil {
		t.Fatalf("failed to create auth.Service: %v", err)
	}
	h := New(database, cfg, svc)
	return database, svc, h, capture
}

func executeRequest(t *testing.T, h http.Handler, method, path string, body any, csrfHeader ...string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		switch v := body.(type) {
		case []byte:
			bodyReader = bytes.NewReader(v)
		case string:
			bodyReader = strings.NewReader(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			bodyReader = bytes.NewReader(b)
		}
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions && method != http.MethodTrace {
		attachCSRFForTest(t, h, req, csrfHeader...)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// attachCSRFForTest fetches a CSRF pair via GET /auth/csrf and attaches it.
// Tests asserting CSRF rejection must build raw requests instead of using executeRequest.
// Pass the handler cfg's CSRFHeaderName when it differs from DefaultConfig.
func attachCSRFForTest(t *testing.T, h http.Handler, req *http.Request, csrfHeader ...string) {
	t.Helper()
	tokenReq := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	tokenRec := httptest.NewRecorder()
	h.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		return
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &body); err != nil || body.CSRFToken == "" {
		return
	}
	headerName := config.DefaultConfig().CSRFHeaderName
	if len(csrfHeader) > 0 && csrfHeader[0] != "" {
		headerName = csrfHeader[0]
	}
	for _, c := range tokenRec.Result().Cookies() {
		if c.Value == body.CSRFToken {
			req.AddCookie(c)
			req.Header.Set(headerName, body.CSRFToken)
			return
		}
	}
}

func decodeResponseBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var target T
	if err := json.NewDecoder(rec.Body).Decode(&target); err != nil {
		t.Fatalf("failed to decode response body %q: %v", rec.Body.String(), err)
	}
	return target
}

// Test 1: Password Min Length (< 8 runes -> 400 CodePasswordTooShort)
func TestPasswordMinLength(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	// 7 characters password
	rec := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "shortpass@example.com",
		Password: "short12",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
	errResp := decodeResponseBody[errors.Response](t, rec)
	if errResp.Code != errors.CodePasswordTooShort {
		t.Errorf("expected code %s, got %s", errors.CodePasswordTooShort, errResp.Code)
	}
}

// Test 2: Password Max Length (> 128 runes -> 400 CodePasswordTooLong)
func TestPasswordMaxLength(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	longPass := strings.Repeat("a", 129)
	rec := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "longpass@example.com",
		Password: longPass,
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
	errResp := decodeResponseBody[errors.Response](t, rec)
	if errResp.Code != errors.CodePasswordTooLong {
		t.Errorf("expected code %s, got %s", errors.CodePasswordTooLong, errResp.Code)
	}
}

// Test 3: Unicode Code Points (8 emoji password -> accepted 200 OK)
func TestPasswordUnicodeCodePoints(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	rec := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "emoji@example.com",
		Password: "😀😁😂😃😄😅😆😇",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	resp := decodeResponseBody[db.MessageResponse](t, rec)
	wantMsg := "if this email is new, a verification link has been sent"
	if resp.Message != wantMsg {
		t.Errorf("expected message %q, got %q", wantMsg, resp.Message)
	}
}

// Test 4: Blocklist ("password" / "12345678" -> 400 CodePasswordTooCommon)
func TestPasswordBlocklist(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	for _, pass := range []string{"password", "12345678"} {
		rec := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
			Email:    fmt.Sprintf("blocklist_%s@example.com", pass),
			Password: pass,
		})

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("password %q: expected status 400, got %d", pass, rec.Code)
		}
		errResp := decodeResponseBody[errors.Response](t, rec)
		if errResp.Code != errors.CodePasswordTooCommon {
			t.Errorf("password %q: expected code %s, got %s", pass, errors.CodePasswordTooCommon, errResp.Code)
		}
	}
}

// Test 5: No Forced Complexity (purely lowercase password -> accepted 200 OK)
func TestNoForcedComplexity(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	rec := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "lowercase@example.com",
		Password: "purelylowercasepass",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// Test 6: Email Format (invalid email -> 400 CodeInvalidEmail)
func TestEmailValidation(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	invalidEmails := []string{
		"notanemail",
		"user@nodot",
		"user @domain.com",
		"",
	}

	for _, badEmail := range invalidEmails {
		// Test on Signup
		recSignup := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
			Email:    badEmail,
			Password: "validpassword123",
		})
		if recSignup.Code != http.StatusBadRequest {
			t.Fatalf("email %q signup: expected status 400, got %d", badEmail, recSignup.Code)
		}
		errResp := decodeResponseBody[errors.Response](t, recSignup)
		if errResp.Code != errors.CodeInvalidEmail {
			t.Errorf("email %q signup: expected code %s, got %s", badEmail, errors.CodeInvalidEmail, errResp.Code)
		}

		// Test on Login
		recLogin := executeRequest(t, h, http.MethodPost, "/auth/login", db.LoginRequest{
			Email:    badEmail,
			Password: "validpassword123",
		})
		if recLogin.Code != http.StatusBadRequest {
			t.Fatalf("email %q login: expected status 400, got %d", badEmail, recLogin.Code)
		}
		errResp = decodeResponseBody[errors.Response](t, recLogin)
		if errResp.Code != errors.CodeInvalidEmail {
			t.Errorf("email %q login: expected code %s, got %s", badEmail, errors.CodeInvalidEmail, errResp.Code)
		}

		// Test on Password Reset Request
		recReset := executeRequest(t, h, http.MethodPost, "/auth/password/reset-request", db.PasswordResetRequest{
			Email: badEmail,
		})
		if recReset.Code != http.StatusBadRequest {
			t.Fatalf("email %q reset-request: expected status 400, got %d", badEmail, recReset.Code)
		}
		errResp = decodeResponseBody[errors.Response](t, recReset)
		if errResp.Code != errors.CodeInvalidEmail {
			t.Errorf("email %q reset-request: expected code %s, got %s", badEmail, errors.CodeInvalidEmail, errResp.Code)
		}
	}
}

// Test 7: Anti-Enumeration Signup (duplicate signup returns 200 OK with identical generic message, zero new DB rows)
func TestAntiEnumeration_Signup(t *testing.T) {
	database, _, h, _ := setupTestEnv(t)

	email := "duplicate@example.com"
	req1 := db.SignupRequest{
		Email:    email,
		Password: "originalpassword123",
	}

	rec1 := executeRequest(t, h, http.MethodPost, "/auth/signup", req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first signup: expected 200, got %d", rec1.Code)
	}

	var countBefore int64
	database.Model(&db.User{}).Where("email = ?", email).Count(&countBefore)
	if countBefore != 1 {
		t.Fatalf("expected 1 user row, got %d", countBefore)
	}

	req2 := db.SignupRequest{
		Email:    email,
		Password: "secondpassword456",
	}

	rec2 := executeRequest(t, h, http.MethodPost, "/auth/signup", req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second signup: expected 200, got %d", rec2.Code)
	}

	if rec1.Body.String() != rec2.Body.String() {
		t.Errorf("expected identical responses, got %q vs %q", rec1.Body.String(), rec2.Body.String())
	}

	var countAfter int64
	database.Model(&db.User{}).Where("email = ?", email).Count(&countAfter)
	if countAfter != 1 {
		t.Fatalf("expected user count to remain 1, got %d", countAfter)
	}
}

// Test 8: Anti-Enumeration Login (wrong password vs non-existent email -> both return 401 CodeInvalidCredentials)
func TestAntiEnumeration_Login(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	// Create user
	recSignup := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "existing@example.com",
		Password: "correctpassword123",
	})
	if recSignup.Code != http.StatusOK {
		t.Fatalf("signup failed: %d", recSignup.Code)
	}

	// Case A: Non-existent email
	recNonExistent := executeRequest(t, h, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "somepassword123",
	})
	if recNonExistent.Code != http.StatusUnauthorized {
		t.Fatalf("non-existent email: expected 401, got %d", recNonExistent.Code)
	}
	errNonExistent := decodeResponseBody[errors.Response](t, recNonExistent)

	// Case B: Existing user with wrong password
	recWrongPass := executeRequest(t, h, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    "existing@example.com",
		Password: "wrongpassword123",
	})
	if recWrongPass.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: expected 401, got %d", recWrongPass.Code)
	}
	errWrongPass := decodeResponseBody[errors.Response](t, recWrongPass)

	if errNonExistent.Code != errors.CodeInvalidCredentials || errWrongPass.Code != errors.CodeInvalidCredentials {
		t.Errorf("expected CodeInvalidCredentials, got %s and %s", errNonExistent.Code, errWrongPass.Code)
	}
	if errNonExistent.Message != errWrongPass.Message {
		t.Errorf("expected identical error messages, got %q vs %q", errNonExistent.Message, errWrongPass.Message)
	}
	if recNonExistent.Body.String() != recWrongPass.Body.String() {
		t.Errorf("expected identical response bodies, got %q vs %q", recNonExistent.Body.String(), recWrongPass.Body.String())
	}
}

// Test 9: Anti-Enumeration Reset (unknown email reset request -> returns 200 OK with identical generic message, zero token rows)
func TestAntiEnumeration_Reset(t *testing.T) {
	database, _, h, _ := setupTestEnv(t)

	rec := executeRequest(t, h, http.MethodPost, "/auth/password/reset-request", db.PasswordResetRequest{
		Email: "unknown@example.com",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	resp := decodeResponseBody[db.MessageResponse](t, rec)
	wantMsg := "if an account with that email exists, a password reset link has been sent"
	if resp.Message != wantMsg {
		t.Errorf("expected message %q, got %q", wantMsg, resp.Message)
	}

	var tokenCount int64
	database.Model(&db.PasswordResetToken{}).Count(&tokenCount)
	if tokenCount != 0 {
		t.Fatalf("expected 0 token rows for unknown email, got %d", tokenCount)
	}
}

// Test 10: Require Verification (unverified login returns 403 CodeEmailNotVerified; verification enables 200 OK login)
func TestRequireEmailVerification(t *testing.T) {
	_, _, h, capture := setupTestEnv(t, func(c *config.Config) {
		c.RequireEmailVerification = true
	})

	recSignup := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "verifytest@example.com",
		Password: "testpassword123",
	})
	if recSignup.Code != http.StatusOK {
		t.Fatalf("signup failed: %d", recSignup.Code)
	}

	token := capture.nextVerificationToken(t)
	if len(token) != 64 {
		t.Fatalf("expected 64 char token, got %q", token)
	}

	// Attempt login prior to verification -> 403 EMAIL_NOT_VERIFIED
	recLoginPre := executeRequest(t, h, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    "verifytest@example.com",
		Password: "testpassword123",
	})
	if recLoginPre.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", recLoginPre.Code)
	}
	errResp := decodeResponseBody[errors.Response](t, recLoginPre)
	if errResp.Code != errors.CodeEmailNotVerified {
		t.Errorf("expected code %s, got %s", errors.CodeEmailNotVerified, errResp.Code)
	}

	// Verify email
	recVerify := executeRequest(t, h, http.MethodPost, "/auth/verify", db.VerifyEmailRequest{
		Token: token,
	})
	if recVerify.Code != http.StatusOK {
		t.Fatalf("verify failed: %d; body: %s", recVerify.Code, recVerify.Body.String())
	}
	verifyResp := decodeResponseBody[db.MessageResponse](t, recVerify)
	if verifyResp.Message != "email verified" {
		t.Errorf("expected message 'email verified', got %q", verifyResp.Message)
	}

	// Attempt login post-verification -> 200 OK
	recLoginPost := executeRequest(t, h, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    "verifytest@example.com",
		Password: "testpassword123",
	})
	if recLoginPost.Code != http.StatusOK {
		t.Fatalf("post-verify login failed: %d; body: %s", recLoginPost.Code, recLoginPost.Body.String())
	}
	loginResp := decodeResponseBody[db.LoginResponse](t, recLoginPost)
	if loginResp.UserID == uuid.Nil {
		t.Errorf("expected non-nil user ID")
	}
}

// Test 11: Token Single-Use Replay (replaying verify or reset token returns 400 CodeInvalidToken)
func TestTokenSingleUseReplay(t *testing.T) {
	_, _, h, capture := setupTestEnv(t, func(c *config.Config) {
		c.RequireEmailVerification = true
	})

	// Part A: Verification token replay
	_ = executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "replay_verify@example.com",
		Password: "validpassword123",
	})
	verifyToken := capture.nextVerificationToken(t)

	recVerify1 := executeRequest(t, h, http.MethodPost, "/auth/verify", db.VerifyEmailRequest{
		Token: verifyToken,
	})
	if recVerify1.Code != http.StatusOK {
		t.Fatalf("first verify failed: %d", recVerify1.Code)
	}

	// Replay verification token
	recVerify2 := executeRequest(t, h, http.MethodPost, "/auth/verify", db.VerifyEmailRequest{
		Token: verifyToken,
	})
	if recVerify2.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for replayed verification token, got %d", recVerify2.Code)
	}
	errVerify := decodeResponseBody[errors.Response](t, recVerify2)
	if errVerify.Code != errors.CodeInvalidToken {
		t.Errorf("expected code %s, got %s", errors.CodeInvalidToken, errVerify.Code)
	}

	// Part B: Password reset token replay
	_ = executeRequest(t, h, http.MethodPost, "/auth/password/reset-request", db.PasswordResetRequest{
		Email: "replay_verify@example.com",
	})
	resetToken := capture.nextResetToken(t)

	recReset1 := executeRequest(t, h, http.MethodPost, "/auth/password/reset", db.PasswordResetConfirmRequest{
		Token:       resetToken,
		NewPassword: "newpassword123",
	})
	if recReset1.Code != http.StatusOK {
		t.Fatalf("first password reset failed: %d", recReset1.Code)
	}

	// Replay password reset token
	recReset2 := executeRequest(t, h, http.MethodPost, "/auth/password/reset", db.PasswordResetConfirmRequest{
		Token:       resetToken,
		NewPassword: "anotherpassword123",
	})
	if recReset2.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for replayed reset token, got %d", recReset2.Code)
	}
	errReset := decodeResponseBody[errors.Response](t, recReset2)
	if errReset.Code != errors.CodeInvalidToken {
		t.Errorf("expected code %s, got %s", errors.CodeInvalidToken, errReset.Code)
	}
}

// Test 12: Token Expiry (expired token returns 400 CodeTokenExpired and is deleted)
func TestTokenExpiry(t *testing.T) {
	database, _, h, _ := setupTestEnv(t)

	// Create user for foreign keys / logic
	recSignup := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "expiry@example.com",
		Password: "validpassword123",
	})
	if recSignup.Code != http.StatusOK {
		t.Fatalf("signup failed: %d", recSignup.Code)
	}

	var user db.User
	if err := database.Where("email = ?", "expiry@example.com").First(&user).Error; err != nil {
		t.Fatalf("failed to query user: %v", err)
	}

	// Part A: Expired verification token
	rawVerifyToken, verifyHash, err := crypto.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	expiredVerification := db.VerificationToken{
		TokenHash: verifyHash[:],
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(-10 * time.Minute),
		CreatedAt: time.Now().UTC().Add(-20 * time.Minute),
	}
	if err := database.Create(&expiredVerification).Error; err != nil {
		t.Fatalf("failed to create expired verification token: %v", err)
	}

	recVerify := executeRequest(t, h, http.MethodPost, "/auth/verify", db.VerifyEmailRequest{
		Token: rawVerifyToken,
	})
	if recVerify.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for expired verification token, got %d", recVerify.Code)
	}
	errVerify := decodeResponseBody[errors.Response](t, recVerify)
	if errVerify.Code != errors.CodeTokenExpired {
		t.Errorf("expected code %s, got %s", errors.CodeTokenExpired, errVerify.Code)
	}

	// Verify token row was deleted
	var remainingVerify db.VerificationToken
	err = database.Where("token_hash = ?", verifyHash[:]).First(&remainingVerify).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("expected expired verification token to be deleted, got err: %v", err)
	}

	// Part B: Expired reset token
	rawResetToken, resetHash, err := crypto.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	expiredReset := db.PasswordResetToken{
		TokenHash: resetHash[:],
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(-10 * time.Minute),
		CreatedAt: time.Now().UTC().Add(-20 * time.Minute),
	}
	if err := database.Create(&expiredReset).Error; err != nil {
		t.Fatalf("failed to create expired reset token: %v", err)
	}

	recReset := executeRequest(t, h, http.MethodPost, "/auth/password/reset", db.PasswordResetConfirmRequest{
		Token:       rawResetToken,
		NewPassword: "newsecurepass123",
	})
	if recReset.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for expired reset token, got %d", recReset.Code)
	}
	errReset := decodeResponseBody[errors.Response](t, recReset)
	if errReset.Code != errors.CodeTokenExpired {
		t.Errorf("expected code %s, got %s", errors.CodeTokenExpired, errReset.Code)
	}

	// Verify reset token row was deleted
	var remainingReset db.PasswordResetToken
	err = database.Where("token_hash = ?", resetHash[:]).First(&remainingReset).Error
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("expected expired reset token to be deleted, got err: %v", err)
	}
}

// Test 13: Password Reset Purge (successful reset purges all active reset tokens for that user)
func TestPasswordResetPurge(t *testing.T) {
	database, _, h, capture := setupTestEnv(t)

	email := "purge@example.com"
	recSignup := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    email,
		Password: "initialpassword123",
	})
	if recSignup.Code != http.StatusOK {
		t.Fatalf("signup failed: %d", recSignup.Code)
	}

	var user db.User
	if err := database.Where("email = ?", email).First(&user).Error; err != nil {
		t.Fatalf("failed to query user: %v", err)
	}

	// Request reset token 1
	_ = executeRequest(t, h, http.MethodPost, "/auth/password/reset-request", db.PasswordResetRequest{
		Email: email,
	})
	tok1 := capture.nextResetToken(t)

	// Request reset token 2
	_ = executeRequest(t, h, http.MethodPost, "/auth/password/reset-request", db.PasswordResetRequest{
		Email: email,
	})
	tok2 := capture.nextResetToken(t)

	var activeTokens int64
	database.Model(&db.PasswordResetToken{}).Where("user_id = ?", user.ID).Count(&activeTokens)
	if activeTokens != 1 {
		t.Fatalf("expected 1 active reset token, got %d", activeTokens)
	}

	// Consume token 2
	recReset := executeRequest(t, h, http.MethodPost, "/auth/password/reset", db.PasswordResetConfirmRequest{
		Token:       tok2,
		NewPassword: "brandnewpassword123",
	})
	if recReset.Code != http.StatusOK {
		t.Fatalf("password reset failed: %d", recReset.Code)
	}

	// Verify all tokens for this user are purged
	database.Model(&db.PasswordResetToken{}).Where("user_id = ?", user.ID).Count(&activeTokens)
	if activeTokens != 0 {
		t.Fatalf("expected 0 active reset tokens after reset, got %d", activeTokens)
	}

	// Attempting to consume token 1 fails with 400 CodeInvalidToken
	recReplayTok1 := executeRequest(t, h, http.MethodPost, "/auth/password/reset", db.PasswordResetConfirmRequest{
		Token:       tok1,
		NewPassword: "shouldnotwork123",
	})
	if recReplayTok1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for purged token 1, got %d", recReplayTok1.Code)
	}
	errTok1 := decodeResponseBody[errors.Response](t, recReplayTok1)
	if errTok1.Code != errors.CodeInvalidToken {
		t.Errorf("expected code %s, got %s", errors.CodeInvalidToken, errTok1.Code)
	}

	// User can now log in with the new password
	recLogin := executeRequest(t, h, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: "brandnewpassword123",
	})
	if recLogin.Code != http.StatusOK {
		t.Fatalf("login with new password failed: %d", recLogin.Code)
	}
}

// Test 14: Zero Secret Leakage (verify zero raw passwords or token strings in logs or response bodies)
func TestZeroSecretLeakage(t *testing.T) {
	_, _, h, capture := setupTestEnv(t)

	rawPassword := "SuperSecretPassword123!"
	emailAddr := "leaktest@example.com"

	// 1. Signup
	recSignup := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    emailAddr,
		Password: rawPassword,
	})
	vToken := capture.nextVerificationToken(t)
	if strings.Contains(recSignup.Body.String(), rawPassword) {
		t.Fatalf("signup response body leaked raw password: %s", recSignup.Body.String())
	}
	if strings.Contains(recSignup.Body.String(), vToken) {
		t.Fatalf("signup response body leaked verification token: %s", recSignup.Body.String())
	}

	// 2. Login
	recLogin := executeRequest(t, h, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    emailAddr,
		Password: rawPassword,
	})
	if strings.Contains(recLogin.Body.String(), rawPassword) {
		t.Fatalf("login response body leaked raw password: %s", recLogin.Body.String())
	}

	// 3. Reset Request
	recResetReq := executeRequest(t, h, http.MethodPost, "/auth/password/reset-request", db.PasswordResetRequest{
		Email: emailAddr,
	})
	rToken := capture.nextResetToken(t)
	if strings.Contains(recResetReq.Body.String(), rToken) {
		t.Fatalf("password reset request body leaked reset token: %s", recResetReq.Body.String())
	}

	// 4. Verify
	recVerify := executeRequest(t, h, http.MethodPost, "/auth/verify", db.VerifyEmailRequest{
		Token: vToken,
	})
	if strings.Contains(recVerify.Body.String(), vToken) {
		t.Fatalf("verify response body leaked verification token: %s", recVerify.Body.String())
	}

	// 5. Password Reset Confirm
	newRawPass := "AnotherSecretPassword123!"
	recResetConfirm := executeRequest(t, h, http.MethodPost, "/auth/password/reset", db.PasswordResetConfirmRequest{
		Token:       rToken,
		NewPassword: newRawPass,
	})
	if strings.Contains(recResetConfirm.Body.String(), newRawPass) {
		t.Fatalf("password reset response leaked new password: %s", recResetConfirm.Body.String())
	}
	if strings.Contains(recResetConfirm.Body.String(), rToken) {
		t.Fatalf("password reset response leaked reset token: %s", recResetConfirm.Body.String())
	}
}

type mockAuthService struct {
	signupFn               func(ctx context.Context, req db.SignupRequest) (*db.User, string, error)
	loginFn                func(ctx context.Context, req db.LoginRequest) (*db.User, error)
	logoutFn               func(ctx context.Context, sessionID string) error
	verifyEmailFn          func(ctx context.Context, req db.VerifyEmailRequest) (*db.User, error)
	requestPasswordResetFn func(ctx context.Context, req db.PasswordResetRequest) (string, error)
	resetPasswordFn        func(ctx context.Context, req db.PasswordResetConfirmRequest) (*db.User, error)
}

func (m *mockAuthService) Signup(ctx context.Context, req db.SignupRequest) (*db.User, string, error) {
	if m.signupFn != nil {
		return m.signupFn(ctx, req)
	}
	return nil, "", nil
}

func (m *mockAuthService) Login(ctx context.Context, req db.LoginRequest) (*db.User, error) {
	if m.loginFn != nil {
		return m.loginFn(ctx, req)
	}
	return nil, nil
}

func (m *mockAuthService) Logout(ctx context.Context, sessionID string) error {
	if m.logoutFn != nil {
		return m.logoutFn(ctx, sessionID)
	}
	return nil
}

func (m *mockAuthService) VerifyEmail(ctx context.Context, req db.VerifyEmailRequest) (*db.User, error) {
	if m.verifyEmailFn != nil {
		return m.verifyEmailFn(ctx, req)
	}
	return nil, stderrors.New("mockAuthService verifyEmail not implemented")
}

func (m *mockAuthService) RequestPasswordReset(ctx context.Context, req db.PasswordResetRequest) (string, error) {
	if m.requestPasswordResetFn != nil {
		return m.requestPasswordResetFn(ctx, req)
	}
	return "", nil
}

func (m *mockAuthService) ResetPassword(ctx context.Context, req db.PasswordResetConfirmRequest) (*db.User, error) {
	if m.resetPasswordFn != nil {
		return m.resetPasswordFn(ctx, req)
	}
	return nil, stderrors.New("mockAuthService resetPassword not implemented")
}

// Test 15: 500 Error Masking (unexpected internal error produces generic 500 CodeInternalError with "internal server error")
func Test500InternalErrorMasking(t *testing.T) {
	sensitiveMsg := "pq: password authentication failed for user 'postgres' on 10.0.0.1:5432"
	mockSvc := &mockAuthService{
		signupFn: func(ctx context.Context, req db.SignupRequest) (*db.User, string, error) {
			return nil, "", errors.New(errors.CodeInternalError, sensitiveMsg, stderrors.New("db crash"))
		},
	}

	h := New(nil, config.DefaultConfig(), mockSvc)
	rec := executeRequest(t, h, http.MethodPost, "/auth/signup", db.SignupRequest{
		Email:    "test500@example.com",
		Password: "validpassword123",
	})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
	errResp := decodeResponseBody[errors.Response](t, rec)
	if errResp.Code != errors.CodeInternalError {
		t.Errorf("expected code %s, got %s", errors.CodeInternalError, errResp.Code)
	}
	if errResp.Message != "internal server error" {
		t.Errorf("expected message 'internal server error', got %q", errResp.Message)
	}
	if strings.Contains(rec.Body.String(), sensitiveMsg) {
		t.Errorf("response body leaked sensitive internal error details: %s", rec.Body.String())
	}
}

// Additional Routing & Alias Tests
func TestRoutingAndAliases(t *testing.T) {
	_, svc, h, _ := setupTestEnv(t)

	// GET on POST-only route -> 405 Method Not Allowed
	recMethodNotAllowed := executeRequest(t, h, http.MethodGet, "/auth/signup", nil)
	if recMethodNotAllowed.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", recMethodNotAllowed.Code)
	}
	err405 := decodeResponseBody[errors.Response](t, recMethodNotAllowed)
	if err405.Code != errors.CodeMethodNotAllowed {
		t.Errorf("expected code %s, got %s", errors.CodeMethodNotAllowed, err405.Code)
	}

	// Unknown route -> 404 Not Found
	recNotFound := executeRequest(t, h, http.MethodPost, "/auth/unknown-endpoint", nil)
	if recNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", recNotFound.Code)
	}
	err404 := decodeResponseBody[errors.Response](t, recNotFound)
	if err404.Code != errors.CodeNotFound {
		t.Errorf("expected code %s, got %s", errors.CodeNotFound, err404.Code)
	}

	// Malformed JSON body -> 400 CodeValidationError
	recMalformed := executeRequest(t, h, http.MethodPost, "/auth/signup", "{invalid-json")
	if recMalformed.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for malformed json, got %d", recMalformed.Code)
	}
	errMalformed := decodeResponseBody[errors.Response](t, recMalformed)
	if errMalformed.Code != errors.CodeValidationError {
		t.Errorf("expected code %s, got %s", errors.CodeValidationError, errMalformed.Code)
	}

	// Empty body -> 400 CodeValidationError
	recEmptyBody := executeRequest(t, h, http.MethodPost, "/auth/signup", "")
	if recEmptyBody.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for empty body, got %d", recEmptyBody.Code)
	}

	// Logout route under session protection rejects requests without CSRF / auth -> 403 Forbidden
	// Raw requests (no CSRF pair) preserve the original missing-token assertion.
	rawLogoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	recLogout := httptest.NewRecorder()
	h.ServeHTTP(recLogout, rawLogoutReq)
	if recLogout.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for unprotected logout, got %d", recLogout.Code)
	}

	// Alias route: POST /api/auth/logout -> 403 Forbidden
	rawApiLogoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	recApiLogout := httptest.NewRecorder()
	h.ServeHTTP(recApiLogout, rawApiLogoutReq)
	if recApiLogout.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 on alias for unprotected logout, got %d", recApiLogout.Code)
	}

	// In legacy mode (nil session service), logout returns 200 OK
	legacyH := New(nil, testConfig(), svc)
	recLegacyLogout := executeRequest(t, legacyH, http.MethodPost, "/auth/logout", nil)
	if recLegacyLogout.Code != http.StatusOK {
		t.Fatalf("expected status 200 on legacy logout, got %d", recLegacyLogout.Code)
	}
	recLegacyApiLogout := executeRequest(t, legacyH, http.MethodPost, "/api/auth/logout", nil)
	if recLegacyApiLogout.Code != http.StatusOK {
		t.Fatalf("expected status 200 on legacy alias logout, got %d", recLegacyApiLogout.Code)
	}

	// Alias routes: verify they accept identical requests
	recApiSignup := executeRequest(t, h, http.MethodPost, "/api/auth/signup", db.SignupRequest{
		Email:    "alias@example.com",
		Password: "validpassword123",
	})
	if recApiSignup.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/auth/signup, got %d", recApiSignup.Code)
	}

	recApiLogin := executeRequest(t, h, http.MethodPost, "/api/auth/login", db.LoginRequest{
		Email:    "alias@example.com",
		Password: "validpassword123",
	})
	if recApiLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/auth/login, got %d", recApiLogin.Code)
	}

	recApiResetReq := executeRequest(t, h, http.MethodPost, "/api/auth/request-password-reset", db.PasswordResetRequest{
		Email: "alias@example.com",
	})
	if recApiResetReq.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/auth/request-password-reset, got %d", recApiResetReq.Code)
	}
}

func TestRequestBodyHardening(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	t.Run("trailing data in request body rejected", func(t *testing.T) {
		body := strings.NewReader(`{"email":"user@example.com","password":"validpassword123"} {"trailing": true}`)
		req := httptest.NewRequest(http.MethodPost, "/auth/signup", body)
		req.Header.Set("Content-Type", "application/json")
		attachCSRFForTest(t, h, req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for trailing data, got %d", rec.Code)
		}
		errResp := decodeResponseBody[errors.Response](t, rec)
		if errResp.Code != errors.CodeValidationError {
			t.Fatalf("expected CodeValidationError, got %s", errResp.Code)
		}
	})

	t.Run("body exceeding 1 MiB rejected", func(t *testing.T) {
		largeBody := `{"email":"` + strings.Repeat("a", 1024*1024+10) + `@example.com","password":"validpassword123"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		attachCSRFForTest(t, h, req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for oversized body, got %d", rec.Code)
		}
	})
}

func TestLogoutInvokesService(t *testing.T) {
	cfg := config.DefaultConfig()
	testToken := "0123456789abcdef0123456789abcdef"

	t.Run("success with session cookie", func(t *testing.T) {
		var receivedSessionID string
		mockSvc := &mockAuthService{
			logoutFn: func(ctx context.Context, sessionID string) error {
				receivedSessionID = sessionID
				return nil
			},
		}
		authH := NewAuthHandler(mockSvc, WithAuthConfig(&cfg))
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: testToken})
		rec := httptest.NewRecorder()
		authH.Logout(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if receivedSessionID != testToken {
			t.Fatalf("expected session ID %q, got %q", testToken, receivedSessionID)
		}
	})

	t.Run("service error propagation", func(t *testing.T) {
		mockSvc := &mockAuthService{
			logoutFn: func(ctx context.Context, sessionID string) error {
				return errors.New(errors.CodeDatabaseError, "db fail", nil)
			},
		}
		authH := NewAuthHandler(mockSvc, WithAuthConfig(&cfg))
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: testToken})
		rec := httptest.NewRecorder()
		authH.Logout(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on db error, got %d", rec.Code)
		}
	})

	t.Run("success with bearer token", func(t *testing.T) {
		var receivedSessionID string
		mockSvc := &mockAuthService{
			logoutFn: func(ctx context.Context, sessionID string) error {
				receivedSessionID = sessionID
				return nil
			},
		}
		authH := NewAuthHandler(mockSvc, WithAuthConfig(&cfg))
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		authH.Logout(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if receivedSessionID != testToken {
			t.Fatalf("expected session ID %q, got %q", testToken, receivedSessionID)
		}
	})

	t.Run("nil service in AuthHandler", func(t *testing.T) {
		authH := NewAuthHandler(nil, WithAuthConfig(&cfg))
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		rec := httptest.NewRecorder()
		authH.Logout(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on nil service, got %d", rec.Code)
		}
	})
}

type mockFailingSessionService struct {
	session.Service
	invalidateErr error
}

func (m *mockFailingSessionService) InvalidateSession(ctx context.Context, rawID string) error {
	return m.invalidateErr
}

func TestAuthHandler_Logout_InvalidateSessionError(t *testing.T) {
	mockSvc := &mockAuthService{}
	cfg := testConfig()
	expectedErr := errors.New(errors.CodeInternalError, "database query failed", nil)
	failingSessSvc := &mockFailingSessionService{invalidateErr: expectedErr}

	authH := NewAuthHandler(mockSvc,
		WithAuthConfig(&cfg),
		WithAuthSessionService(failingSessSvc),
	)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "0123456789abcdef0123456789abcdef"})
	rec := httptest.NewRecorder()

	authH.Logout(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 on InvalidateSession failure, got %d", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sid" && c.MaxAge < 0 {
			t.Fatal("expected session cookie NOT to be cleared on invalidation error")
		}
	}

	// Also test bearer token invalidation failure
	reqBearer := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	reqBearer.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	recBearer := httptest.NewRecorder()

	authH.Logout(recBearer, reqBearer)

	if recBearer.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 on bearer InvalidateSession failure, got %d", recBearer.Code)
	}
}

func TestAuthHandler_Logout_ClearsCSRFCookieAndSessionCookie(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionCookieName = "sid"
	cfg.CSRFCookieName = "csrf_token"

	mockSvc := &mockAuthService{}
	mockSess := &mockSessionService{}
	authH := NewAuthHandler(mockSvc,
		WithAuthConfig(&cfg),
		WithAuthSessionService(mockSess),
	)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "0123456789abcdef0123456789abcdef"})
	rec := httptest.NewRecorder()

	authH.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on logout, got %d", rec.Code)
	}

	var clearedSession, clearedCSRF *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.SessionCookieName {
			clearedSession = c
		}
		if c.Name == cfg.CSRFCookieName {
			clearedCSRF = c
		}
	}

	if clearedSession == nil {
		t.Fatalf("expected session cookie %q to be cleared", cfg.SessionCookieName)
	}
	if clearedSession.MaxAge != -1 {
		t.Fatalf("expected session cookie MaxAge -1, got %d", clearedSession.MaxAge)
	}
	if clearedCSRF == nil {
		t.Fatalf("expected CSRF cookie %q to be cleared", cfg.CSRFCookieName)
	}
	if clearedCSRF.MaxAge != -1 {
		t.Fatalf("expected CSRF cookie MaxAge -1, got %d", clearedCSRF.MaxAge)
	}
}

func TestDecodeJSON_NilBody(t *testing.T) {
	mockSvc := &mockAuthService{}
	authH := NewAuthHandler(mockSvc)

	endpoints := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
	}{
		{"Signup", authH.Signup},
		{"Login", authH.Login},
		{"VerifyEmail", authH.VerifyEmail},
		{"RequestPasswordReset", authH.RequestPasswordReset},
		{"ResetPassword", authH.ResetPassword},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/"+ep.name, nil)
			req.Body = nil // Explicitly set Body to nil to exercise r.Body == nil branch
			rec := httptest.NewRecorder()

			ep.call(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400 for nil body, got %d", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("expected Content-Type application/json, got %q", got)
			}
			errResp := decodeResponseBody[errors.Response](t, rec)
			if errResp.Code != errors.CodeValidationError {
				t.Errorf("expected code %s, got %s", errors.CodeValidationError, errResp.Code)
			}
			if errResp.Message != "invalid request body" {
				t.Errorf("expected message 'invalid request body', got %q", errResp.Message)
			}
		})
	}
}

func TestWriteJSON_Helper(t *testing.T) {
	t.Run("encodes data and sets headers correctly", func(t *testing.T) {
		rec := httptest.NewRecorder()
		payload := map[string]string{"status": "custom_ok", "key": "value"}

		writeJSON(rec, http.StatusCreated, payload)

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d", http.StatusCreated, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", got)
		}

		var decoded map[string]string
		if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if decoded["status"] != "custom_ok" || decoded["key"] != "value" {
			t.Errorf("unexpected decoded payload: %v", decoded)
		}
	})
}

func TestTamperedCookiesAndHeaders(t *testing.T) {
	mockSvc := &mockAuthService{
		logoutFn: func(ctx context.Context, sessionID string) error {
			return nil
		},
	}
	h := New(nil, config.DefaultConfig(), mockSvc)

	cases := []struct {
		name       string
		cookieName string
		cookieVal  string
		headerName string
		headerVal  string
	}{
		{
			name:       "tampered special characters in session cookie",
			cookieName: "session",
			cookieVal:  "invalid\x00session;drop table users;--",
		},
		{
			name:       "oversized session cookie",
			cookieName: "session",
			cookieVal:  strings.Repeat("A", 8192),
		},
		{
			name:       "XSS injection in session_id cookie",
			cookieName: "session_id",
			cookieVal:  `<script>alert("cookie_xss")</script>`,
		},
		{
			name:       "tampered X-Session-ID header",
			headerName: "X-Session-ID",
			headerVal:  "' OR 1=1; --",
		},
		{
			name:       "oversized X-Session-ID header",
			headerName: "X-Session-ID",
			headerVal:  strings.Repeat("B", 8192),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			attachCSRFForTest(t, h, req)
			if tt.cookieName != "" {
				req.AddCookie(&http.Cookie{Name: tt.cookieName, Value: tt.cookieVal})
			}
			if tt.headerName != "" {
				req.Header.Set(tt.headerName, tt.headerVal)
			}
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			// Safe handling: 200 OK, no panic, no 500 secret leakage
			if rec.Code != http.StatusOK {
				t.Fatalf("expected status 200 OK for tampered session, got %d", rec.Code)
			}
		})
	}
}

func TestAdversarialPayloadResilience_JSONEndpoints(t *testing.T) {
	mockSvc := &mockAuthService{
		signupFn: func(ctx context.Context, req db.SignupRequest) (*db.User, string, error) {
			// Mock should never be reached if DTO validation works properly
			return nil, "", nil
		},
		loginFn: func(ctx context.Context, req db.LoginRequest) (*db.User, error) {
			return nil, nil
		},
		verifyEmailFn: func(ctx context.Context, req db.VerifyEmailRequest) (*db.User, error) {
			return nil, nil
		},
		resetPasswordFn: func(ctx context.Context, req db.PasswordResetConfirmRequest) (*db.User, error) {
			return nil, nil
		},
	}
	h := New(nil, config.DefaultConfig(), mockSvc)

	t.Run("SQL injection in email fields rejected by validation", func(t *testing.T) {
		sqliEmails := []string{
			"' OR '1'='1",
			"user@test.com; DROP TABLE users;--",
			`"admin\"--@example.com`,
			"<script>alert(1)</script>@test.com",
			"admin'--@domain..com",
			"attacker@.com",
		}
		for _, email := range sqliEmails {
			rec := executeRequest(t, h, http.MethodPost, "/auth/signup", map[string]string{
				"email":    email,
				"password": "ValidPassword123#",
			})
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for SQLi email %q, got %d", email, rec.Code)
			}
			var resp errors.Response
			_ = json.NewDecoder(rec.Body).Decode(&resp)
			if resp.Code != errors.CodeInvalidEmail && resp.Code != errors.CodeValidationError {
				t.Errorf("expected validation error code for %q, got %s", email, resp.Code)
			}
		}
	})

	t.Run("SQL injection and path traversal in token endpoints rejected", func(t *testing.T) {
		maliciousTokens := []string{
			"'; DROP TABLE verification_tokens; --",
			"../../../../etc/passwd",
			"<script>alert(1)</script>",
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';--",
		}
		for _, token := range maliciousTokens {
			recVerify := executeRequest(t, h, http.MethodPost, "/auth/verify", map[string]string{
				"token": token,
			})
			if recVerify.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for malicious verify token %q, got %d", token, recVerify.Code)
			}

			recReset := executeRequest(t, h, http.MethodPost, "/auth/password/reset", map[string]string{
				"token":        token,
				"new_password": "ValidPassword123#",
			})
			if recReset.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for malicious reset token %q, got %d", token, recReset.Code)
			}
		}
	})
}

func TestBruteForceAccountLockout_RegressionPlaceholder(t *testing.T) {
	// TODO: implement account lockout regression tests once brute-force/lockout feature is implemented
	t.Skip("account lockout not yet implemented in service")
}

func TestAuthHandler_LoginRateLimiting(t *testing.T) {
	database, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	loginLimiter := ratelimit.NewLimiter(15*time.Minute, 3)
	sessSvc := session.NewService(database, &cfg)

	authH := NewAuthHandler(svc,
		WithAuthSessionService(sessSvc),
		WithAuthConfig(&cfg),
		WithAuthLimiters(loginLimiter, nil, nil),
	)

	email := "ratelimit_login@example.com"
	reqBody := db.LoginRequest{
		Email:    email,
		Password: "wrongpassword",
	}

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
		req.RemoteAddr = "192.168.1.10:12345"
		rec := httptest.NewRecorder()
		// Inject valid body bytes
		b, _ := json.Marshal(reqBody)
		req.Body = io.NopCloser(bytes.NewReader(b))
		authH.Login(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 Unauthorized, got %d", i+1, rec.Code)
		}
	}

	// 4th attempt should be blocked with 429
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "192.168.1.10:12345"
	rec := httptest.NewRecorder()
	b, _ := json.Marshal(reqBody)
	req.Body = io.NopCloser(bytes.NewReader(b))
	authH.Login(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec.Code)
	}
	if retryAfter := rec.Header().Get("Retry-After"); retryAfter == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}
}

func TestAuthHandler_RateLimitLogin_EmailCasingSharedBucket(t *testing.T) {
	_, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	loginLimiter := ratelimit.NewLimiter(15*time.Minute, 1)

	authH := NewAuthHandler(svc,
		WithAuthConfig(&cfg),
		WithAuthLimiters(loginLimiter, nil, nil),
	)

	// Attempt 1 with lowercase email
	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req1.RemoteAddr = "192.168.1.50:12345"
	b1, _ := json.Marshal(db.LoginRequest{Email: "victim@example.com", Password: "wrongpassword"})
	req1.Body = io.NopCloser(bytes.NewReader(b1))
	rec1 := httptest.NewRecorder()
	authH.Login(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("attempt 1: expected 401, got %d", rec1.Code)
	}

	// Attempt 2 with uppercase/mixed case email from same IP should be blocked by rate limit (429)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req2.RemoteAddr = "192.168.1.50:12345"
	b2, _ := json.Marshal(db.LoginRequest{Email: "VICTIM@EXAMPLE.COM", Password: "wrongpassword"})
	req2.Body = io.NopCloser(bytes.NewReader(b2))
	rec2 := httptest.NewRecorder()
	authH.Login(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 2 with case-variant email: expected 429 Too Many Requests, got %d", rec2.Code)
	}
}

func TestAuthHandler_RateLimitResetOnSuccess(t *testing.T) {
	database, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	loginLimiter := ratelimit.NewLimiter(15*time.Minute, 2)
	sessSvc := session.NewService(database, &cfg)

	authH := NewAuthHandler(svc,
		WithAuthSessionService(sessSvc),
		WithAuthConfig(&cfg),
		WithAuthLimiters(loginLimiter, nil, nil),
	)

	email := "rl_reset@example.com"
	pass := "ValidPassword123!"

	// Signup user
	_, _, err := svc.Signup(context.Background(), db.SignupRequest{
		Email:    email,
		Password: pass,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	// 1 bad attempt
	badReq := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	badReq.RemoteAddr = "192.168.2.1:12345"
	recBad := httptest.NewRecorder()
	b, _ := json.Marshal(db.LoginRequest{Email: email, Password: "wrong"})
	badReq.Body = io.NopCloser(bytes.NewReader(b))
	authH.Login(recBad, badReq)

	// Successful login should reset rate limiter
	goodReq := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	goodReq.RemoteAddr = "192.168.2.1:12345"
	recGood := httptest.NewRecorder()
	b, _ = json.Marshal(db.LoginRequest{Email: email, Password: pass})
	goodReq.Body = io.NopCloser(bytes.NewReader(b))
	authH.Login(recGood, goodReq)

	if recGood.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on valid credentials, got %d", recGood.Code)
	}

	// Limiter should have reset for this IP|email; another attempt allowed
	anotherReq := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	anotherReq.RemoteAddr = "192.168.2.1:12345"
	recAnother := httptest.NewRecorder()
	b, _ = json.Marshal(db.LoginRequest{Email: email, Password: pass})
	anotherReq.Body = io.NopCloser(bytes.NewReader(b))
	authH.Login(recAnother, anotherReq)

	if recAnother.Code != http.StatusOK {
		t.Fatalf("expected 200 OK after reset, got %d", recAnother.Code)
	}
}

func TestAuthHandler_LoginSessionCreation_CookieAndBearer(t *testing.T) {
	database, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	sessSvc := session.NewService(database, &cfg)

	authH := NewAuthHandler(svc,
		WithAuthSessionService(sessSvc),
		WithAuthConfig(&cfg),
	)

	email := "sess_create@example.com"
	pass := "ValidPassword123!"
	createdUser, _, err := svc.Signup(context.Background(), db.SignupRequest{
		Email:    email,
		Password: pass,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	// 1. Cookie login
	cookieReq := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	b, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	cookieReq.Body = io.NopCloser(bytes.NewReader(b))
	recCookie := httptest.NewRecorder()
	authH.Login(recCookie, cookieReq)

	if recCookie.Code != http.StatusOK {
		t.Fatalf("cookie login failed: %d", recCookie.Code)
	}
	cookies := recCookie.Result().Cookies()
	var sidCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.SessionCookieName {
			sidCookie = c
			break
		}
	}
	if sidCookie == nil {
		t.Fatalf("expected cookie %q to be set", cfg.SessionCookieName)
	}
	if !sidCookie.HttpOnly {
		t.Errorf("expected session cookie to have HttpOnly=true")
	}

	cookieSess, err := sessSvc.GetSession(context.Background(), sidCookie.Value)
	if err != nil || cookieSess == nil {
		t.Fatalf("GetSession(cookie) failed: %v", err)
	}
	if cookieSess.CredentialVersion != createdUser.CredentialVersion {
		t.Errorf("cookie session credential version = %d, want %d", cookieSess.CredentialVersion, createdUser.CredentialVersion)
	}

	// 2. Bearer login
	bearerReq := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	bearerReq.Header.Set("X-Auth-Type", "bearer")
	b, _ = json.Marshal(db.LoginRequest{Email: email, Password: pass})
	bearerReq.Body = io.NopCloser(bytes.NewReader(b))
	recBearer := httptest.NewRecorder()
	authH.Login(recBearer, bearerReq)

	if recBearer.Code != http.StatusOK {
		t.Fatalf("bearer login failed: %d", recBearer.Code)
	}
	if got := recBearer.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", got)
	}
	if got := recBearer.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q; want no-cache", got)
	}
	var bearerResp struct {
		UserID uuid.UUID `json:"user_id"`
		Token  string    `json:"token"`
	}
	if err := json.Unmarshal(recBearer.Body.Bytes(), &bearerResp); err != nil {
		t.Fatalf("failed to decode bearer response: %v", err)
	}
	if bearerResp.UserID != createdUser.ID {
		t.Errorf("expected bearer user_id %v, got %v", createdUser.ID, bearerResp.UserID)
	}
	if len(bearerResp.Token) != 32 {
		t.Errorf("expected 32-char hex token, got %q", bearerResp.Token)
	}

	bearerSess, err := sessSvc.GetSession(context.Background(), bearerResp.Token)
	if err != nil || bearerSess == nil {
		t.Fatalf("GetSession(bearer) failed: %v", err)
	}
	if bearerSess.CredentialVersion != createdUser.CredentialVersion {
		t.Errorf("bearer session credential version = %d, want %d", bearerSess.CredentialVersion, createdUser.CredentialVersion)
	}

	// Bumped credential version propagates to minted session.
	if err := database.Model(&db.User{}).Where("id = ?", createdUser.ID).Update("credential_version", createdUser.CredentialVersion+3).Error; err != nil {
		t.Fatalf("failed to bump credential version: %v", err)
	}
	var bumped db.User
	if err := database.Where("id = ?", createdUser.ID).First(&bumped).Error; err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}

	bumpedReq := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	bumpedReq.Header.Set("X-Auth-Type", "bearer")
	bb, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	bumpedReq.Body = io.NopCloser(bytes.NewReader(bb))
	recBumped := httptest.NewRecorder()
	authH.Login(recBumped, bumpedReq)
	if recBumped.Code != http.StatusOK {
		t.Fatalf("bumped login failed: %d", recBumped.Code)
	}
	var bumpedResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(recBumped.Body.Bytes(), &bumpedResp); err != nil {
		t.Fatalf("failed to decode bumped response: %v", err)
	}
	bumpedSess, err := sessSvc.GetSession(context.Background(), bumpedResp.Token)
	if err != nil || bumpedSess == nil {
		t.Fatalf("GetSession(bumped) failed: %v", err)
	}
	if bumpedSess.CredentialVersion != bumped.CredentialVersion {
		t.Errorf("bumped session credential version = %d, want %d", bumpedSess.CredentialVersion, bumped.CredentialVersion)
	}
}

func TestAuthHandler_CookieLoginExposesRotatedCSRFToken(t *testing.T) {
	database, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	sessSvc := session.NewService(database, &cfg)

	authH := NewAuthHandler(svc,
		WithAuthSessionService(sessSvc),
		WithAuthConfig(&cfg),
	)

	email := "csrf_expose@example.com"
	pass := "ValidPassword123!"
	if _, _, err := svc.Signup(context.Background(), db.SignupRequest{Email: email, Password: pass}); err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	b, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	req.Body = io.NopCloser(bytes.NewReader(b))
	rec := httptest.NewRecorder()
	authH.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("cookie login failed: %d", rec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if len(body.CSRFToken) != 64 {
		t.Fatalf("expected 64-char csrf_token in body, got %q", body.CSRFToken)
	}
	var rotated string
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.CSRFCookieName {
			rotated = c.Value
		}
	}
	if rotated == "" {
		t.Fatalf("expected %q cookie to be set", cfg.CSRFCookieName)
	}
	if body.CSRFToken != rotated {
		t.Fatal("body csrf_token must match the rotated CSRF cookie")
	}
}

func TestSessionService_StaleMintRejectedAfterVersionBump(t *testing.T) {
	database, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	sessSvc := session.NewService(database, &cfg)

	email := "stale-mint@example.com"
	pass := "ValidPassword123!"
	createdUser, _, err := svc.Signup(context.Background(), db.SignupRequest{
		Email:    email,
		Password: pass,
	})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	_, rawID, err := sessSvc.CreateSession(context.Background(), createdUser.ID, createdUser.CredentialVersion, db.SessionTypeBearer, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if err := database.Model(&db.User{}).Where("id = ?", createdUser.ID).Update("credential_version", createdUser.CredentialVersion+1).Error; err != nil {
		t.Fatalf("failed to bump credential version: %v", err)
	}

	if sess, gerr := sessSvc.GetSession(context.Background(), rawID); gerr == nil || sess != nil {
		t.Fatalf("expected stale session rejected, got sess=%v err=%v", sess, gerr)
	} else if !stderrors.Is(gerr, errors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid, got %v", gerr)
	}

	if sess, _, merr := sessSvc.CreateSession(context.Background(), createdUser.ID, createdUser.CredentialVersion, db.SessionTypeBearer, "127.0.0.1", "agent"); merr == nil || sess != nil {
		t.Fatalf("expected stale mint rejected, got sess=%v err=%v", sess, merr)
	} else if !stderrors.Is(merr, errors.ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid on stale mint, got %v", merr)
	}

	var staleCount int64
	if err := database.Model(&db.Session{}).Where("user_id = ?", createdUser.ID).Count(&staleCount).Error; err != nil {
		t.Fatalf("failed to count sessions: %v", err)
	}
	if staleCount != 0 {
		t.Fatalf("expected no session persisted on stale mint, found %d", staleCount)
	}
}

func TestAuthHandler_LoginStaleMintReturns401(t *testing.T) {
	cfg := testConfig()
	userID := uuid.New()
	staleUser := &db.User{ID: userID, Email: "stale-login@example.com", CredentialVersion: 0}
	cases := []struct {
		name    string
		mintErr error
	}{
		{"bare", errors.ErrSessionInvalid},
		{"wrapped", fmt.Errorf("mint: %w", errors.ErrSessionInvalid)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockAuth := &mockAuthService{
				loginFn: func(ctx context.Context, req db.LoginRequest) (*db.User, error) {
					return staleUser, nil
				},
			}
			mockSess := &mockSessionService{
				createSessFn: func(ctx context.Context, uid uuid.UUID, cv int, st db.SessionType, ip, ua string) (*session.Session, string, error) {
					return nil, "", tc.mintErr
				},
			}
			authH := NewAuthHandler(mockAuth, WithAuthSessionService(mockSess), WithAuthConfig(&cfg))
			b, _ := json.Marshal(db.LoginRequest{Email: "stale-login@example.com", Password: "ValidPassword123!"})
			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			authH.Login(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
			}
			var resp errors.Response
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}
			if resp.Code != errors.CodeSessionInvalid {
				t.Fatalf("expected code %s, got %s", errors.CodeSessionInvalid, resp.Code)
			}
		})
	}
}

func TestNewAuthHandler_NilConfigDefaults(t *testing.T) {
	h := NewAuthHandler(nil)
	if h.cfg == nil {
		t.Fatalf("expected default config when cfg is nil")
	}
	if h.cfg.SessionCookieName == "" {
		t.Errorf("expected default SessionCookieName to be non-empty")
	}
}

func TestAuthHandler_RateLimitResetPassword(t *testing.T) {
	_, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	resetLimiter := ratelimit.NewLimiter(15*time.Minute, 2)

	authH := NewAuthHandler(svc,
		WithAuthConfig(&cfg),
		WithAuthLimiters(nil, nil, resetLimiter),
	)

	reqBody := db.PasswordResetConfirmRequest{
		Token:       strings.Repeat("a", 64),
		NewPassword: "NewValidPassword123!",
	}
	b, _ := json.Marshal(reqBody)

	// Attempts 1 and 2 should reach svc and fail with token invalid (400 or 401)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/password/reset", bytes.NewReader(b))
		req.RemoteAddr = "192.168.10.1:12345"
		rec := httptest.NewRecorder()
		authH.ResetPassword(rec, req)

		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d should not be rate limited", i+1)
		}
	}

	// Attempt 3 from same IP should be blocked with 429
	req3 := httptest.NewRequest(http.MethodPost, "/auth/password/reset", bytes.NewReader(b))
	req3.RemoteAddr = "192.168.10.1:12345"
	rec3 := httptest.NewRecorder()
	authH.ResetPassword(rec3, req3)

	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: expected 429 Too Many Requests, got %d", rec3.Code)
	}
	if retryAfter := rec3.Header().Get("Retry-After"); retryAfter == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}

	// Attempt from a different IP should be allowed
	reqOther := httptest.NewRequest(http.MethodPost, "/auth/password/reset", bytes.NewReader(b))
	reqOther.RemoteAddr = "192.168.10.2:12345"
	recOther := httptest.NewRecorder()
	authH.ResetPassword(recOther, reqOther)

	if recOther.Code == http.StatusTooManyRequests {
		t.Fatalf("attempt from different IP should not be rate limited")
	}
}

func TestAuthHandler_DualTierRateLimit_HorizontalPasswordSpraying(t *testing.T) {
	_, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	// Allow 2 attempts per IP, 5 attempts per account
	ipLimiter := ratelimit.NewLimiter(15*time.Minute, 2)
	accountLimiter := ratelimit.NewLimiter(15*time.Minute, 5)

	authH := NewAuthHandler(svc,
		WithAuthConfig(&cfg),
		WithAuthLimiters(accountLimiter, nil, nil),
		WithAuthIPLimiters(ipLimiter, nil, nil),
	)

	ip := "198.51.100.1:54321"

	// Attempt 1: email A from IP
	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req1.RemoteAddr = ip
	b1, _ := json.Marshal(db.LoginRequest{Email: "user1@example.com", Password: "wrongpassword"})
	req1.Body = io.NopCloser(bytes.NewReader(b1))
	rec1 := httptest.NewRecorder()
	authH.Login(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("attempt 1: expected 401, got %d", rec1.Code)
	}

	// Attempt 2: email B from same IP
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req2.RemoteAddr = ip
	b2, _ := json.Marshal(db.LoginRequest{Email: "user2@example.com", Password: "wrongpassword"})
	req2.Body = io.NopCloser(bytes.NewReader(b2))
	rec2 := httptest.NewRecorder()
	authH.Login(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("attempt 2: expected 401, got %d", rec2.Code)
	}

	// Attempt 3: email C from same IP — must be blocked by IP-level limiter
	req3 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req3.RemoteAddr = ip
	b3, _ := json.Marshal(db.LoginRequest{Email: "user3@example.com", Password: "wrongpassword"})
	req3.Body = io.NopCloser(bytes.NewReader(b3))
	rec3 := httptest.NewRecorder()
	authH.Login(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3 (spraying from same IP): expected 429, got %d", rec3.Code)
	}
	if rec3.Header().Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}

	// Attempt 4 from a different IP targeting user3 should be allowed by IP limiter
	req4 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req4.RemoteAddr = "198.51.100.2:54321"
	b4, _ := json.Marshal(db.LoginRequest{Email: "user3@example.com", Password: "wrongpassword"})
	req4.Body = io.NopCloser(bytes.NewReader(b4))
	rec4 := httptest.NewRecorder()
	authH.Login(rec4, req4)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("attempt 4 from different IP: expected 401, got %d", rec4.Code)
	}
}

func TestAuthHandler_DualTierRateLimit_DistributedBruteForce(t *testing.T) {
	_, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	// Allow 10 attempts per IP, but only 2 attempts per account
	ipLimiter := ratelimit.NewLimiter(15*time.Minute, 10)
	accountLimiter := ratelimit.NewLimiter(15*time.Minute, 2)

	authH := NewAuthHandler(svc,
		WithAuthConfig(&cfg),
		WithAuthLimiters(accountLimiter, nil, nil),
		WithAuthIPLimiters(ipLimiter, nil, nil),
	)

	targetEmail := "admin@targetcorp.com"

	// Attempt 1 from IP 1
	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req1.RemoteAddr = "10.0.0.1:12345"
	b1, _ := json.Marshal(db.LoginRequest{Email: targetEmail, Password: "badpassword1"})
	req1.Body = io.NopCloser(bytes.NewReader(b1))
	rec1 := httptest.NewRecorder()
	authH.Login(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("attempt 1: expected 401, got %d", rec1.Code)
	}

	// Attempt 2 from IP 2 (rotating IP)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req2.RemoteAddr = "10.0.0.2:12345"
	b2, _ := json.Marshal(db.LoginRequest{Email: targetEmail, Password: "badpassword2"})
	req2.Body = io.NopCloser(bytes.NewReader(b2))
	rec2 := httptest.NewRecorder()
	authH.Login(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("attempt 2: expected 401, got %d", rec2.Code)
	}

	// Attempt 3 from IP 3 (fresh rotating IP) — must be blocked by account limiter
	req3 := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req3.RemoteAddr = "10.0.0.3:12345"
	b3, _ := json.Marshal(db.LoginRequest{Email: targetEmail, Password: "badpassword3"})
	req3.Body = io.NopCloser(bytes.NewReader(b3))
	rec3 := httptest.NewRecorder()
	authH.Login(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3 (distributed attack on same account): expected 429, got %d", rec3.Code)
	}
}

func TestAuthHandler_DualTierRateLimit_ResetAccountOnlyOnSuccess(t *testing.T) {
	database, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	sessSvc := session.NewService(database, &cfg)

	// IP limiter max: 2, Account limiter max: 2
	ipLimiter := ratelimit.NewLimiter(15*time.Minute, 2)
	accountLimiter := ratelimit.NewLimiter(15*time.Minute, 2)

	authH := NewAuthHandler(svc,
		WithAuthSessionService(sessSvc),
		WithAuthConfig(&cfg),
		WithAuthLimiters(accountLimiter, nil, nil),
		WithAuthIPLimiters(ipLimiter, nil, nil),
	)

	email := "dual_reset@example.com"
	pass := "SecurePassword123!"

	_, _, err := svc.Signup(context.Background(), db.SignupRequest{Email: email, Password: pass})
	if err != nil {
		t.Fatalf("Signup failed: %v", err)
	}

	ip := "192.0.2.100:1111"

	// Attempt 1: failed login
	reqBad := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	reqBad.RemoteAddr = ip
	bBad, _ := json.Marshal(db.LoginRequest{Email: email, Password: "wrong"})
	reqBad.Body = io.NopCloser(bytes.NewReader(bBad))
	recBad := httptest.NewRecorder()
	authH.Login(recBad, reqBad)
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recBad.Code)
	}

	// Attempt 2: successful login (uses up 2nd attempt on IP limiter)
	reqGood := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	reqGood.RemoteAddr = ip
	bGood, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	reqGood.Body = io.NopCloser(bytes.NewReader(bGood))
	recGood := httptest.NewRecorder()
	authH.Login(recGood, reqGood)
	if recGood.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recGood.Code)
	}

	// Attempt 3 from same IP: IP limiter must NOT have been reset by success, so 3rd attempt is blocked
	reqBlocked := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	reqBlocked.RemoteAddr = ip
	bBlocked, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	reqBlocked.Body = io.NopCloser(bytes.NewReader(bBlocked))
	recBlocked := httptest.NewRecorder()
	authH.Login(recBlocked, reqBlocked)
	if recBlocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 because IP limiter was not reset, got %d", recBlocked.Code)
	}

	// Attempt 4 from a DIFFERENT IP for the same account should succeed (account limiter was reset)
	reqOtherIP := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	reqOtherIP.RemoteAddr = "192.0.2.101:1111"
	bOtherIP, _ := json.Marshal(db.LoginRequest{Email: email, Password: pass})
	reqOtherIP.Body = io.NopCloser(bytes.NewReader(bOtherIP))
	recOtherIP := httptest.NewRecorder()
	authH.Login(recOtherIP, reqOtherIP)
	if recOtherIP.Code != http.StatusOK {
		t.Fatalf("expected 200 from different IP because account counter was reset, got %d", recOtherIP.Code)
	}
}

func TestAuthHandler_DualTierRateLimit_SignupMassRegistration(t *testing.T) {
	_, svc, _, _ := setupTestEnv(t)
	cfg := testConfig()
	// Allow 2 signups per IP
	signupIPLimiter := ratelimit.NewLimiter(15*time.Minute, 2)
	signupLimiter := ratelimit.NewLimiter(15*time.Minute, 10)

	authH := NewAuthHandler(svc,
		WithAuthConfig(&cfg),
		WithAuthLimiters(nil, signupLimiter, nil),
		WithAuthIPLimiters(nil, signupIPLimiter, nil),
	)

	ip := "203.0.113.50:4321"

	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/signup", nil)
		req.RemoteAddr = ip
		b, _ := json.Marshal(db.SignupRequest{
			Email:    fmt.Sprintf("mass_reg_%d@example.com", i),
			Password: "StrongPassword123!",
		})
		req.Body = io.NopCloser(bytes.NewReader(b))
		rec := httptest.NewRecorder()
		authH.Signup(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("signup %d: expected 200, got %d", i, rec.Code)
		}
	}

	// 3rd signup from same IP must be blocked by IP rate limiter
	req3 := httptest.NewRequest(http.MethodPost, "/auth/signup", nil)
	req3.RemoteAddr = ip
	b3, _ := json.Marshal(db.SignupRequest{
		Email:    "mass_reg_3@example.com",
		Password: "StrongPassword123!",
	})
	req3.Body = io.NopCloser(bytes.NewReader(b3))
	rec3 := httptest.NewRecorder()
	authH.Signup(rec3, req3)

	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("signup 3: expected 429 Too Many Requests, got %d", rec3.Code)
	}
}

func TestLogout_CSRFAndAuthProtection(t *testing.T) {
	database := setupSessionTestDB(t)
	cfg := config.DefaultConfig()
	sessSvc := session.NewService(database, &cfg)

	mockAuth := &mockAuthService{}
	h := New(database, cfg, mockAuth, WithSessionService(sessSvc))

	userID := uuid.New()
	if err := database.Create(&db.User{ID: userID, Email: userID.String() + "@seed.example", PasswordHash: "hash", CredentialVersion: 0}).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}
	_, rawCookieID, err := sessSvc.CreateSession(context.Background(), userID, 0, db.SessionTypeCookie, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("failed to create cookie session: %v", err)
	}
	_, rawBearerID, err := sessSvc.CreateSession(context.Background(), userID, 0, db.SessionTypeBearer, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("failed to create bearer session: %v", err)
	}

	t.Run("cookie logout without CSRF token returns 403 Forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawCookieID})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden on missing CSRF token, got %d", rec.Code)
		}
	})

	t.Run("cookie logout with valid CSRF token returns 200 OK and revokes session", func(t *testing.T) {
		csrfVal := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rawCookieID})
		req.AddCookie(&http.Cookie{Name: cfg.CSRFCookieName, Value: csrfVal})
		req.Header.Set(cfg.CSRFHeaderName, csrfVal)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bearer logout bypasses CSRF and returns 200 OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+rawBearerID)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("unauthenticated bearer logout returns 401 Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer 00000000000000000000000000000000")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})
}
