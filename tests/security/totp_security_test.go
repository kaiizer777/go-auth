package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	ptotp "github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/crypto"
	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/totp"
)

const secEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func init() {
	totp.SetBackupHashParamsForTesting(totp.FastTestHashParams())
}

func setupTotpSecurityApp(t *testing.T, modifyCfg ...func(*config.Config)) (*goauth.Auth, *gorm.DB, config.Config) {
	t.Helper()

	dbName := fmt.Sprintf("file:totp_sec_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}
	sqlDB, err := database.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	ddl := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		credential_version INTEGER NOT NULL DEFAULT 0,
		email_verified INTEGER NOT NULL DEFAULT 1,
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
	CREATE TABLE IF NOT EXISTS totp_secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT UNIQUE NOT NULL,
		encrypted_secret BLOB NOT NULL,
		backup_codes TEXT NOT NULL DEFAULT '[]',
		enabled INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS totp_used_codes (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		code_hash BLOB NOT NULL,
		used_at DATETIME NOT NULL,
		CONSTRAINT uq_totp_used_codes_user_code UNIQUE (user_id, code_hash)
	);
	CREATE TABLE IF NOT EXISTS two_factor_tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		token_hash BLOB UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		attempts INTEGER NOT NULL DEFAULT 0
	);`
	if err := database.Exec(ddl).Error; err != nil {
		t.Fatalf("failed to execute sqlite ddl: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://postgres:postgres@localhost:5432/testdb"
	cfg.BaseURL = "http://localhost:8080"
	cfg.DisableAsyncEmailDispatch = true
	cfg.SessionIdleTimeout = 30 * time.Minute
	cfg.SessionAbsoluteMaxAge = 24 * time.Hour
	cfg.SessionCookieSecure = false
	cfg.Argon2 = config.Argon2Config{
		Memory:      19456,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	cfg.TOTP.EncryptionKey = secEncryptionKey
	cfg.TOTP.Issuer = "GoAuthTest"
	cfg.TOTP.ChallengeTokenTTL = 5 * time.Minute
	cfg.TOTP.MaxAttemptsPerWindow = 5
	cfg.TOTP.AttemptWindow = 5 * time.Minute

	for _, fn := range modifyCfg {
		fn(&cfg)
	}

	app, err := goauth.NewWithDB(database, cfg)
	if err != nil {
		t.Fatalf("goauth.NewWithDB failed: %v", err)
	}
	t.Cleanup(func() {
		_ = app.Close()
	})

	return app, database, cfg
}

func createTotpSecUser(t *testing.T, dbConn *gorm.DB, email, rawPassword string, verified bool) db.User {
	t.Helper()
	hash, err := crypto.HashPassword(rawPassword, crypto.DefaultHashParams())
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := db.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  hash,
		EmailVerified: verified,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := dbConn.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func doSecRequest(h http.Handler, method, path string, payload any, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		if k == "Remote-Addr" {
			req.RemoteAddr = v
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func fetchTotpCSRFPair(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	rec := doSecRequest(h, http.MethodGet, "/auth/csrf", nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("failed to fetch CSRF token: status %d", rec.Code)
	}
	var res struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode csrf: %v", err)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Value == res.CSRFToken {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("missing csrf cookie")
	}
	return cookie, res.CSRFToken
}

func enrollAndConfirmUser(t *testing.T, app *goauth.Auth, userID string) (string, []string) {
	t.Helper()
	enrollRes, err := app.Totp().Enroll(context.Background(), userID)
	if err != nil {
		t.Fatalf("totp enroll: %v", err)
	}
	// Generate code for previous 30s step so the current step code remains fresh and unconsumed
	setupCode, err := ptotp.GenerateCode(enrollRes.Secret, time.Now().UTC().Add(-30*time.Second))
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	backupCodes, err := app.Totp().ConfirmEnrollment(context.Background(), userID, setupCode)
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	return enrollRes.Secret, backupCodes
}

func interceptLogin(t *testing.T, app *goauth.Auth, email, password string) string {
	t.Helper()
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: password,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login intercepted expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res struct {
		TwoFactorRequired bool   `json:"two_factor_required"`
		ChallengeToken    string `json:"challenge_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal intercept response: %v", err)
	}
	if !res.TwoFactorRequired || res.ChallengeToken == "" {
		t.Fatalf("expected two_factor_required=true and challenge token, got %+v", res)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store, private" {
		t.Errorf("expected Cache-Control 'no-store, private', got %q", cc)
	}
	if pragma := rec.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("expected Pragma 'no-cache', got %q", pragma)
	}
	return res.ChallengeToken
}

// 1. TestConcurrentCodeReplayRace: 16 concurrent goroutines submit the EXACT same valid code simultaneously with distinct challenge tokens.
// Exactly 1 must succeed (200 OK); all other 15 must fail with code replay error.
func TestConcurrentCodeReplayRace(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t, func(c *config.Config) {
		c.TOTP.MaxAttemptsPerWindow = 50
	})

	email := "concurrency_totp@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	secret, _ := enrollAndConfirmUser(t, app, user.ID.String())

	const concurrency = 16
	challengeTokens := make([]string, concurrency)
	for i := 0; i < concurrency; i++ {
		challengeTokens[i] = interceptLogin(t, app, email, rawPass)
	}

	type reqPayload struct {
		challengeToken string
		csrfCookie     *http.Cookie
		csrfToken      string
	}
	payloads := make([]reqPayload, concurrency)
	for i := 0; i < concurrency; i++ {
		cookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
		payloads[i] = reqPayload{
			challengeToken: challengeTokens[i],
			csrfCookie:     cookie,
			csrfToken:      csrfToken,
		}
	}

	// Ensure at least 10s remain in the current 30s TOTP window to eliminate timestep rollover flakes on slow CI runners.
	for {
		remaining := 30 - (time.Now().Unix() % 30)
		if remaining >= 10 {
			break
		}
		time.Sleep(time.Duration(remaining)*time.Second + 100*time.Millisecond)
	}

	validCode, err := ptotp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate valid code: %v", err)
	}

	type result struct {
		code int
		body string
	}
	results := make([]result, concurrency)
	var readyWg sync.WaitGroup
	var wg sync.WaitGroup
	startGate := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		readyWg.Add(1)
		go func(idx int) {
			defer wg.Done()
			readyWg.Done()
			<-startGate

			rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
				"challenge_token": payloads[idx].challengeToken,
				"code":            validCode,
			}, []*http.Cookie{payloads[idx].csrfCookie}, map[string]string{
				"X-CSRF-Token": payloads[idx].csrfToken,
				"Remote-Addr":  fmt.Sprintf("198.51.100.%d:12345", idx+1),
			})
			results[idx] = result{code: rec.Code, body: rec.Body.String()}
		}(i)
	}

	readyWg.Wait()
	close(startGate)
	wg.Wait()

	successCount := 0
	replayCount := 0
	otherCount := 0

	for _, res := range results {
		if res.code == http.StatusOK {
			successCount++
		} else if res.code == http.StatusBadRequest && (strings.Contains(res.body, "TOTP_CODE_REPLAYED") || strings.Contains(res.body, "TOTP_CODE_ALREADY_USED")) {
			replayCount++
		} else {
			otherCount++
		}
	}

	if successCount != 1 {
		for idx, res := range results {
			t.Logf("[%d] code=%d body=%s", idx, res.code, res.body)
		}
		t.Fatalf("concurrency race failure: expected EXACTLY 1 success (200 OK), got %d (replays=%d, other=%d)",
			successCount, replayCount, otherCount)
	}
	if replayCount != concurrency-1 {
		for idx, res := range results {
			t.Logf("[%d] code=%d body=%s", idx, res.code, res.body)
		}
		t.Fatalf("expected %d rejected replay attempts, got %d (other=%d)", concurrency-1, replayCount, otherCount)
	}
}

// 2. TestChallengeTokenMistypeRetry: mistyped code returns 400 TOTP_CODE_INVALID; attempt 2 succeeds.
func TestChallengeTokenMistypeRetry(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "mistype_retry@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	secret, _ := enrollAndConfirmUser(t, app, user.ID.String())

	challengeToken := interceptLogin(t, app, email, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	// Attempt 1: wrong code -> 400 TOTP_CODE_INVALID
	rec1 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": challengeToken,
		"code":            "000000",
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec1.Code != http.StatusBadRequest || !strings.Contains(rec1.Body.String(), "TOTP_CODE_INVALID") {
		t.Fatalf("expected 400 TOTP_CODE_INVALID on mistype, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Verify token attempt count incremented to 1 in DB
	var tok db.TwoFactorToken
	if err := dbConn.First(&tok).Error; err != nil {
		t.Fatalf("fetch token: %v", err)
	}
	if tok.Attempts != 1 {
		t.Fatalf("expected attempts=1, got %d", tok.Attempts)
	}

	// Attempt 2: valid code on same token -> 200 OK
	validCode, err := ptotp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate valid code: %v", err)
	}
	rec2 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": challengeToken,
		"code":            validCode,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 on retry with valid code, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// 3. TestChallengeTokenExhaustion: submitting MaxAttemptsPerWindow wrong codes hard-deletes token.
func TestChallengeTokenExhaustion(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t, func(c *config.Config) {
		c.TOTP.MaxAttemptsPerWindow = 3
	})

	email := "exhaustion@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	_, _ = enrollAndConfirmUser(t, app, user.ID.String())

	challengeToken := interceptLogin(t, app, email, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	for attempt := 1; attempt <= 3; attempt++ {
		rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
			"challenge_token": challengeToken,
			"code":            "000000",
		}, []*http.Cookie{csrfCookie}, map[string]string{
			"X-CSRF-Token": csrfToken,
		})
		if attempt < 3 {
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("attempt %d: expected 400, got %d", attempt, rec.Code)
			}
		} else {
			// On attempt 3 (exhaustion), token hard deleted and returns error
			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusBadRequest && rec.Code != http.StatusTooManyRequests {
				t.Fatalf("exhaustion attempt expected 401, 400, or 429, got %d: %s", rec.Code, rec.Body.String())
			}
		}
	}

	// Direct DB count asserts 0 lingering rows
	var count int64
	dbConn.Model(&db.TwoFactorToken{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 token rows after exhaustion, got %d", count)
	}

	// 4th attempt returns TWO_FACTOR_TOKEN_INVALID
	rec4 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": challengeToken,
		"code":            "000000",
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec4.Code != http.StatusUnauthorized && rec4.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 401 or 429 after exhaustion, got %d: %s", rec4.Code, rec4.Body.String())
	}
}

// 4. TestTwoFactorTokenHardDelete: token row is permanently hard-deleted upon successful verify.
func TestTwoFactorTokenHardDelete(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "hard_delete@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	secret, _ := enrollAndConfirmUser(t, app, user.ID.String())

	challengeToken := interceptLogin(t, app, email, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	validCode, _ := ptotp.GenerateCode(secret, time.Now().UTC())
	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": challengeToken,
		"code":            validCode,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify expected 200, got %d", rec.Code)
	}

	var count int64
	dbConn.Model(&db.TwoFactorToken{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 token rows after successful verify (hard-deleted), found %d", count)
	}
}

// 5. TestExpiredChallengeToken: validating past expires_at deletes token and returns 401 TWO_FACTOR_TOKEN_EXPIRED.
func TestExpiredChallengeToken(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "expired_token@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	secret, _ := enrollAndConfirmUser(t, app, user.ID.String())

	challengeToken := interceptLogin(t, app, email, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	// Set expires_at to 10 minutes in the past
	if err := dbConn.Model(&db.TwoFactorToken{}).Where("1=1").Update("expires_at", time.Now().Add(-10*time.Minute)).Error; err != nil {
		t.Fatalf("expire token: %v", err)
	}

	validCode, _ := ptotp.GenerateCode(secret, time.Now().UTC())
	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": challengeToken,
		"code":            validCode,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "TWO_FACTOR_TOKEN_EXPIRED") {
		t.Fatalf("expected 401 TWO_FACTOR_TOKEN_EXPIRED, got %d: %s", rec.Code, rec.Body.String())
	}

	var count int64
	dbConn.Model(&db.TwoFactorToken{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected expired token to be hard-deleted, got %d rows", count)
	}
}

// 6. TestReplayedTOTPCode: exact same code cannot be verified twice within window.
func TestReplayedTOTPCode(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "replay_code@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	secret, _ := enrollAndConfirmUser(t, app, user.ID.String())

	code, _ := ptotp.GenerateCode(secret, time.Now().UTC())

	// Session 1: Intercepted login -> verify code
	tok1 := interceptLogin(t, app, email, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
	rec1 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": tok1,
		"code":            code,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec1.Code != http.StatusOK {
		t.Fatalf("first verify expected 200, got %d", rec1.Code)
	}

	// Session 2: Intercept login again -> try submitting same code
	tok2 := interceptLogin(t, app, email, rawPass)
	rec2 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": tok2,
		"code":            code,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec2.Code != http.StatusBadRequest || !strings.Contains(rec2.Body.String(), "TOTP_CODE_REPLAYED") {
		t.Fatalf("expected 400 TOTP_CODE_REPLAYED on code reuse, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// 7. TestInvalidBackupCode: invalid/tampered 8-char backup code returns 400 TOTP_BACKUP_CODE_INVALID.
func TestInvalidBackupCode(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "invalid_backup@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	_, _ = enrollAndConfirmUser(t, app, user.ID.String())

	challengeToken := interceptLogin(t, app, email, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/backup", map[string]string{
		"challenge_token": challengeToken,
		"backup_code":     "BADCODE1",
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "BACKUP_CODE_INVALID") {
		t.Fatalf("expected 400 BACKUP_CODE_INVALID, got %d: %s", rec.Code, rec.Body.String())
	}

	// Token attempt counter increments
	var tok db.TwoFactorToken
	dbConn.First(&tok)
	if tok.Attempts != 1 {
		t.Fatalf("expected token attempts=1, got %d", tok.Attempts)
	}
}

// 8. TestBackupCodeSingleUse: valid backup code works once; second attempt is rejected and secret backup code array decrements.
func TestBackupCodeSingleUse(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "single_backup@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	_, backupCodes := enrollAndConfirmUser(t, app, user.ID.String())
	if len(backupCodes) != 10 {
		t.Fatalf("expected 10 backup codes, got %d", len(backupCodes))
	}
	targetCode := backupCodes[0]

	// First use -> succeeds
	tok1 := interceptLogin(t, app, email, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
	rec1 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/backup", map[string]string{
		"challenge_token": tok1,
		"backup_code":     targetCode,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec1.Code != http.StatusOK {
		t.Fatalf("backup code use expected 200, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Verify backup code array decrements to 9
	var secret db.TotpSecret
	if err := dbConn.Where("user_id = ?", user.ID).First(&secret).Error; err != nil {
		t.Fatalf("fetch secret: %v", err)
	}
	var storedCodes []string
	_ = json.Unmarshal([]byte(secret.BackupCodes), &storedCodes)
	if len(storedCodes) != 9 {
		t.Fatalf("expected 9 remaining backup codes, got %d", len(storedCodes))
	}

	// Second use of the same backup code -> rejected
	tok2 := interceptLogin(t, app, email, rawPass)
	rec2 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/backup", map[string]string{
		"challenge_token": tok2,
		"backup_code":     targetCode,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec2.Code != http.StatusBadRequest || !strings.Contains(rec2.Body.String(), "BACKUP_CODE_INVALID") {
		t.Fatalf("expected second use to return 400 BACKUP_CODE_INVALID, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// 9. TestDisableWithoutFreshAuth: DELETE /auth/totp with empty or invalid credentials returns 401.
func TestDisableWithoutFreshAuth(t *testing.T) {
	t.Parallel()
	app, dbConn, cfg := setupTotpSecurityApp(t)

	email := "disable_auth@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	_, _ = enrollAndConfirmUser(t, app, user.ID.String())

	// Create active session directly via Session service
	_, rawID, err := app.Session.CreateSession(context.Background(), user.ID, user.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sessionCookie := &http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: rawID,
		Path:  "/",
	}
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	// Case 1: Empty body
	rec1 := doSecRequest(app.Handler, http.MethodDelete, "/auth/totp", map[string]string{}, []*http.Cookie{csrfCookie, sessionCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("empty credentials expected 401, got %d", rec1.Code)
	}

	// Case 2: Wrong password, empty code
	rec2 := doSecRequest(app.Handler, http.MethodDelete, "/auth/totp", map[string]string{
		"password": "WrongPassword!",
	}, []*http.Cookie{csrfCookie, sessionCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password expected 401, got %d", rec2.Code)
	}

	// Case 3: Wrong code, empty password
	rec3 := doSecRequest(app.Handler, http.MethodDelete, "/auth/totp", map[string]string{
		"code": "000000",
	}, []*http.Cookie{csrfCookie, sessionCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec3.Code != http.StatusUnauthorized && rec3.Code != http.StatusBadRequest {
		t.Fatalf("wrong code expected 401 or 400, got %d", rec3.Code)
	}

	// 2FA remains active
	recStatus := doSecRequest(app.Handler, http.MethodGet, "/auth/totp/status", nil, []*http.Cookie{sessionCookie}, nil)
	if !strings.Contains(recStatus.Body.String(), `"enabled":true`) {
		t.Fatalf("expected 2FA to remain enabled, got: %s", recStatus.Body.String())
	}
}

// 10. TestDisableWithBothValidCredentials: BOTH valid password and valid code succeed (boolean OR).
func TestDisableWithBothValidCredentials(t *testing.T) {
	t.Parallel()
	app, dbConn, cfg := setupTotpSecurityApp(t)

	email := "disable_both@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	secret, _ := enrollAndConfirmUser(t, app, user.ID.String())

	_, rawID, err := app.Session.CreateSession(context.Background(), user.ID, user.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sessionCookie := &http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: rawID,
		Path:  "/",
	}
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	validCode, _ := ptotp.GenerateCode(secret, time.Now().UTC())
	rec := doSecRequest(app.Handler, http.MethodDelete, "/auth/totp", map[string]string{
		"password": rawPass,
		"code":     validCode,
	}, []*http.Cookie{csrfCookie, sessionCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"disabled":true`) {
		t.Fatalf("expected 200 with disabled:true, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 11. TestEnrollUnverifiedEmail: email_verified=false user cannot enroll in TOTP (400 or 403 EMAIL_NOT_VERIFIED).
func TestEnrollUnverifiedEmail(t *testing.T) {
	t.Parallel()
	app, dbConn, cfg := setupTotpSecurityApp(t)

	email := "unverified_totp@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, false) // unverified!

	_, rawID, err := app.Session.CreateSession(context.Background(), user.ID, user.CredentialVersion, db.SessionTypeCookie, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sessionCookie := &http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: rawID,
		Path:  "/",
	}
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/enroll", nil, []*http.Cookie{csrfCookie, sessionCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if (rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden) || !strings.Contains(rec.Body.String(), "EMAIL_NOT_VERIFIED") {
		t.Fatalf("expected 400 or 403 EMAIL_NOT_VERIFIED, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 12. TestUnenrolledUserVerify: verify attempt for non-enrolled user returns error.
func TestUnenrolledUserVerify(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "unenrolled@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)

	// User logs in without TOTP -> no interception, normal login
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: rawPass,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on login, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "challenge_token") {
		t.Fatalf("unenrolled user must not receive challenge token: %s", rec.Body.String())
	}

	// Calling verify directly on service for unenrolled user returns ErrTOTPNotEnrolled
	err := app.Totp().VerifyCode(context.Background(), user.ID.String(), "123456", "")
	if err == nil || (!errors.Is(err, apperrors.ErrTOTPNotEnrolled) && !strings.Contains(err.Error(), "no active totp enrollment")) {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
	}
}

// 13. TestLoginWith2FAEnabledNeverIssuesSession: intercepted login returns challenge token, never sets session cookie.
func TestLoginWith2FAEnabledNeverIssuesSession(t *testing.T) {
	t.Parallel()
	app, dbConn, cfg := setupTotpSecurityApp(t)

	email := "intercept_nosession@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	_, _ = enrollAndConfirmUser(t, app, user.ID.String())

	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: rawPass,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Explicitly assert absence of session cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.SessionCookieName && c.Value != "" {
			t.Fatalf("interception must NEVER issue session cookie, found %s=%s", c.Name, c.Value)
		}
	}

	// Assert no authorization token issued in body
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if _, ok := body["session_token"]; ok {
		t.Fatalf("interception body must not contain session_token: %v", body)
	}
	if _, ok := body["token"]; ok {
		t.Fatalf("interception body must not contain token: %v", body)
	}
}

// 14. TestDualKeyRateLimit_IP: IP limit exhaustion returns 429 with positive Retry-After before token lookup.
func TestDualKeyRateLimit_IP(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t, func(c *config.Config) {
		c.TOTP.MaxAttemptsPerWindow = 3
	})

	email := "ip_ratelimit@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)
	_, _ = enrollAndConfirmUser(t, app, user.ID.String())

	const clientIP = "203.0.113.50:12345"
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	// Consume IP rate limit with dummy requests from clientIP
	for i := 0; i < 3; i++ {
		_ = doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
			"challenge_token": "dummy-token",
			"code":            "000000",
		}, []*http.Cookie{csrfCookie}, map[string]string{
			"X-CSRF-Token": csrfToken,
			"Remote-Addr":  clientIP,
		})
	}

	// Now create a valid challenge token
	tok := interceptLogin(t, app, email, rawPass)

	// 4th request from clientIP must be rejected with 429 before token processing
	rec4 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": tok,
		"code":            "000000",
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
		"Remote-Addr":  clientIP,
	})

	if rec4.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec4.Code)
	}
	if rec4.Header().Get("Retry-After") == "" {
		t.Fatal("expected positive Retry-After header on 429 response")
	}

	// Verify token attempts remains 0 (token processing skipped due to IP rate limit)
	var token db.TwoFactorToken
	if err := dbConn.Where("user_id = ?", user.ID).First(&token).Error; err != nil {
		t.Fatalf("fetch token: %v", err)
	}
	if token.Attempts != 0 {
		t.Fatalf("expected token attempts=0, got %d", token.Attempts)
	}
}

// 15. TestDualKeyRateLimit_User: rotating IPs exhaust user-level rate limit without blocking other users.
func TestDualKeyRateLimit_User(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpSecurityApp(t, func(c *config.Config) {
		c.TOTP.MaxAttemptsPerWindow = 2
	})

	emailA := "user_ratelimit_a@example.com"
	emailB := "user_ratelimit_b@example.com"
	rawPass := "SecurePass#2026!"
	userA := createTotpSecUser(t, dbConn, emailA, rawPass, true)
	userB := createTotpSecUser(t, dbConn, emailB, rawPass, true)
	_, _ = enrollAndConfirmUser(t, app, userA.ID.String())
	_, _ = enrollAndConfirmUser(t, app, userB.ID.String())

	tokA := interceptLogin(t, app, emailA, rawPass)
	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)

	// User A attempt 1 on IP 1 -> allowed (fails code check)
	_ = doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": tokA,
		"code":            "000000",
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
		"Remote-Addr":  "198.51.100.1:12345",
	})

	// User A attempt 2 on IP 2 -> token exhausted and hard-deleted
	recA2 := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": tokA,
		"code":            "000000",
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
		"Remote-Addr":  "198.51.100.2:12345",
	})
	if recA2.Code != http.StatusUnauthorized && recA2.Code != http.StatusBadRequest && recA2.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 2 expected 401, 400, or 429, got %d", recA2.Code)
	}

	// User B from IP 1 (which User A used on attempt 1) is NOT blocked
	tokB := interceptLogin(t, app, emailB, rawPass)
	recB := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": tokB,
		"code":            "000000",
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
		"Remote-Addr":  "198.51.100.1:12345",
	})
	if recB.Code == http.StatusTooManyRequests {
		t.Fatalf("User B must NOT be blocked by User A's rate limit exhaustion")
	}
}

// 16. TestAESCiphertextTampering: bit-flip in nonce, ciphertext, or tag fails GCM tag check.
func TestAESCiphertextTampering(t *testing.T) {
	t.Parallel()
	c, err := totp.NewCrypto(secEncryptionKey)
	if err != nil {
		t.Fatalf("new crypto: %v", err)
	}

	secret := []byte("JBSWY3DPEHPK3PXP")
	encrypted, err := c.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	// 1. Bit flip in nonce (first 12 bytes)
	tamperedNonce := make([]byte, len(encrypted))
	copy(tamperedNonce, encrypted)
	tamperedNonce[2] ^= 0x01
	if _, err := c.Decrypt(tamperedNonce); err == nil {
		t.Fatal("expected decryption error with tampered nonce")
	}

	// 2. Bit flip in ciphertext / tag
	tamperedPayload := make([]byte, len(encrypted))
	copy(tamperedPayload, encrypted)
	tamperedPayload[len(tamperedPayload)-1] ^= 0x01
	if _, err := c.Decrypt(tamperedPayload); err == nil {
		t.Fatal("expected decryption error with tampered ciphertext/tag")
	}

	// 3. Truncated ciphertext (< 12 bytes)
	if _, err := c.Decrypt([]byte("short")); err == nil {
		t.Fatal("expected decryption error on truncated blob")
	}
}

// logSafeSink guards logs captured during testing.
type totpLogSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *totpLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *totpLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// 17. TestSlogZeroLeak_TOTPSecret: zero base32 secrets, raw 6-digit codes, or token hashes appear in logs.
func TestSlogZeroLeak_TOTPSecret(t *testing.T) {
	sink := &totpLogSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(sink, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "zeroleak_secret@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)

	// Enroll & confirm
	secret, _ := enrollAndConfirmUser(t, app, user.ID.String())
	challengeToken := interceptLogin(t, app, email, rawPass)
	validCode, _ := ptotp.GenerateCode(secret, time.Now().UTC())

	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/verify", map[string]string{
		"challenge_token": challengeToken,
		"code":            validCode,
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify failed: %d", rec.Code)
	}

	logs := sink.String()
	if strings.Contains(logs, secret) {
		t.Fatalf("log leak: base32 secret %q found in logs", secret)
	}
	if strings.Contains(logs, validCode) {
		t.Fatalf("log leak: 6-digit code %q found in logs", validCode)
	}
	if strings.Contains(logs, challengeToken) {
		t.Fatalf("log leak: challenge token %q found in logs", challengeToken)
	}
}

// 18. TestSlogZeroLeak_BackupCodes: zero plaintext backup codes appear in slog output.
func TestSlogZeroLeak_BackupCodes(t *testing.T) {
	sink := &totpLogSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(sink, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	app, dbConn, _ := setupTotpSecurityApp(t)

	email := "zeroleak_backup@example.com"
	rawPass := "SecurePass#2026!"
	user := createTotpSecUser(t, dbConn, email, rawPass, true)

	_, backupCodes := enrollAndConfirmUser(t, app, user.ID.String())
	challengeToken := interceptLogin(t, app, email, rawPass)

	csrfCookie, csrfToken := fetchTotpCSRFPair(t, app.Handler)
	rec := doSecRequest(app.Handler, http.MethodPost, "/auth/totp/backup", map[string]string{
		"challenge_token": challengeToken,
		"backup_code":     backupCodes[0],
	}, []*http.Cookie{csrfCookie}, map[string]string{
		"X-CSRF-Token": csrfToken,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("backup verify failed: %d", rec.Code)
	}

	logs := sink.String()
	for _, code := range backupCodes {
		if strings.Contains(logs, code) {
			t.Fatalf("log leak: plaintext backup code %q found in logs", code)
		}
	}
}
