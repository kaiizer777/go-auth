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

func executeRequest(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
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
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
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
	if activeTokens != 2 {
		t.Fatalf("expected 2 active reset tokens, got %d", activeTokens)
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
	verifyEmailFn          func(ctx context.Context, req db.VerifyEmailRequest) error
	requestPasswordResetFn func(ctx context.Context, req db.PasswordResetRequest) (string, error)
	resetPasswordFn        func(ctx context.Context, req db.PasswordResetConfirmRequest) error
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

func (m *mockAuthService) VerifyEmail(ctx context.Context, req db.VerifyEmailRequest) error {
	if m.verifyEmailFn != nil {
		return m.verifyEmailFn(ctx, req)
	}
	return nil
}

func (m *mockAuthService) RequestPasswordReset(ctx context.Context, req db.PasswordResetRequest) (string, error) {
	if m.requestPasswordResetFn != nil {
		return m.requestPasswordResetFn(ctx, req)
	}
	return "", nil
}

func (m *mockAuthService) ResetPassword(ctx context.Context, req db.PasswordResetConfirmRequest) error {
	if m.resetPasswordFn != nil {
		return m.resetPasswordFn(ctx, req)
	}
	return nil
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
	_, _, h, _ := setupTestEnv(t)

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

	// Logout route -> 204 No Content
	recLogout := executeRequest(t, h, http.MethodPost, "/auth/logout", nil)
	if recLogout.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", recLogout.Code)
	}
	if recLogout.Body.Len() != 0 {
		t.Errorf("expected empty body for 204, got %q", recLogout.Body.String())
	}

	// Alias route: POST /api/auth/logout -> 204 No Content
	recApiLogout := executeRequest(t, h, http.MethodPost, "/api/auth/logout", nil)
	if recApiLogout.Code != http.StatusNoContent {
		t.Fatalf("expected status 204 on alias, got %d", recApiLogout.Code)
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
