package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
)

const testEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func setupTotpTestApp(t *testing.T, modifyCfg ...func(*config.Config)) (*goauth.Auth, *gorm.DB, config.Config) {
	t.Helper()

	dbName := fmt.Sprintf("file:totp_hdlr_%d_%s?mode=memory&cache=shared", time.Now().UnixNano(), uuid.New().String())
	database, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

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
	cfg.TOTP.EncryptionKey = testEncryptionKey
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

func createVerifiedUser(t *testing.T, dbConn *gorm.DB, email, rawPassword string) db.User {
	t.Helper()
	hash, err := crypto.HashPassword(rawPassword, crypto.DefaultHashParams())
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := db.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  hash,
		EmailVerified: true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := dbConn.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func doRequest(h http.Handler, method, path string, payload any, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
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
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loginForSession(t *testing.T, app *goauth.Auth, cfg config.Config, email, password string) (*http.Cookie, *http.Cookie, string) {
	t.Helper()
	csrfCookie, csrfToken := fetchCSRFPair(t, app.Handler)
	resp := postJSON(app.Handler, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: password,
	}, csrfCookie, csrfToken, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("login failed: code %d, body: %s", resp.Code, resp.Body.String())
	}
	var sidCookie *http.Cookie
	for _, c := range resp.Result().Cookies() {
		if c.Name == cfg.SessionCookieName {
			sidCookie = c
		}
		if c.Name == cfg.CSRFCookieName {
			csrfCookie = c
			csrfToken = c.Value
		}
	}
	if sidCookie == nil {
		t.Fatal("no session cookie found after login")
	}
	return sidCookie, csrfCookie, csrfToken
}

func TestTOTPHandler_EnrollAndConfirmFlow(t *testing.T) {
	t.Parallel()
	app, dbConn, cfg := setupTotpTestApp(t)

	email := "totp_enroll@example.com"
	rawPass := "SecurePass#2026!"
	createVerifiedUser(t, dbConn, email, rawPass)

	sidCookie, csrfCookie, csrfToken := loginForSession(t, app, cfg, email, rawPass)

	// 1. Unauthenticated request rejected
	unauthGet := doRequest(app.Handler, http.MethodGet, "/auth/totp/status", nil, nil, nil)
	if unauthGet.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session on status, got %d", unauthGet.Code)
	}

	unauthPost := postJSON(app.Handler, "/auth/totp/enroll", nil, csrfCookie, csrfToken, nil)
	if unauthPost.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session on enroll, got %d", unauthPost.Code)
	}

	// 2. Check initial status is false
	statusRec := doRequest(app.Handler, http.MethodGet, "/auth/totp/status", nil, []*http.Cookie{sidCookie}, nil)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on status, got %d", statusRec.Code)
	}
	var statusBody map[string]any
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if statusBody["enabled"] != false {
		t.Fatalf("expected enabled=false, got %v", statusBody["enabled"])
	}

	// 3. Authenticated enroll succeeds
	enrollRec := postJSON(app.Handler, "/auth/totp/enroll", nil, csrfCookie, csrfToken, map[string]string{
		"Cookie": sidCookie.String() + "; " + csrfCookie.String(),
	})
	if enrollRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on enroll, got %d: %s", enrollRec.Code, enrollRec.Body.String())
	}
	var enrollData struct {
		Secret string `json:"secret"`
		OTPURI string `json:"otp_uri"`
		QRCode string `json:"qr_code"`
	}
	if err := json.Unmarshal(enrollRec.Body.Bytes(), &enrollData); err != nil {
		t.Fatalf("unmarshal enroll response: %v", err)
	}
	if enrollData.Secret == "" || !strings.HasPrefix(enrollData.QRCode, "data:image/png;base64,") {
		t.Fatalf("invalid enroll payload: %+v", enrollData)
	}

	// 4. Confirm with invalid format
	badFormat := postJSON(app.Handler, "/auth/totp/confirm", map[string]string{"code": "123"}, csrfCookie, csrfToken, map[string]string{
		"Cookie": sidCookie.String() + "; " + csrfCookie.String(),
	})
	if badFormat.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on short code, got %d", badFormat.Code)
	}

	// 5. Confirm with wrong code
	wrongCode := postJSON(app.Handler, "/auth/totp/confirm", map[string]string{"code": "000000"}, csrfCookie, csrfToken, map[string]string{
		"Cookie": sidCookie.String() + "; " + csrfCookie.String(),
	})
	if wrongCode.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on wrong code, got %d", wrongCode.Code)
	}

	// 6. Confirm with valid code
	validCode, err := ptotp.GenerateCode(enrollData.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	confirmRec := postJSON(app.Handler, "/auth/totp/confirm", map[string]string{"code": validCode}, csrfCookie, csrfToken, map[string]string{
		"Cookie": sidCookie.String() + "; " + csrfCookie.String(),
	})
	if confirmRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on confirm, got %d: %s", confirmRec.Code, confirmRec.Body.String())
	}
	var confirmData struct {
		Confirmed   bool     `json:"confirmed"`
		BackupCodes []string `json:"backup_codes"`
	}
	if err := json.Unmarshal(confirmRec.Body.Bytes(), &confirmData); err != nil {
		t.Fatalf("unmarshal confirm data: %v", err)
	}
	if !confirmData.Confirmed || len(confirmData.BackupCodes) != 10 {
		t.Fatalf("expected confirmed=true and 10 backup codes, got %+v", confirmData)
	}

	// 7. Verify status is now enabled
	statusAfter := doRequest(app.Handler, http.MethodGet, "/auth/totp/status", nil, []*http.Cookie{sidCookie}, nil)
	if statusAfter.Code != http.StatusOK {
		t.Fatalf("expected 200 on status, got %d", statusAfter.Code)
	}
	var statusAfterBody map[string]any
	_ = json.Unmarshal(statusAfter.Body.Bytes(), &statusAfterBody)
	if statusAfterBody["enabled"] != true {
		t.Fatalf("expected enabled=true, got %v", statusAfterBody["enabled"])
	}

	// 8. Re-enrolling returns 409 conflict
	reEnroll := postJSON(app.Handler, "/auth/totp/enroll", nil, csrfCookie, csrfToken, map[string]string{
		"Cookie": sidCookie.String() + "; " + csrfCookie.String(),
	})
	if reEnroll.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate enroll, got %d", reEnroll.Code)
	}
}

func TestTOTPHandler_LoginInterceptionAndVerifyFlow(t *testing.T) {
	t.Parallel()
	app, dbConn, cfg := setupTotpTestApp(t)

	email := "totp_login@example.com"
	rawPass := "SecurePass#2026!"
	user := createVerifiedUser(t, dbConn, email, rawPass)

	// Enroll and enable TOTP directly
	enrollRes, err := app.Totp().Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code, err := ptotp.GenerateCode(enrollRes.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	backupCodes, err := app.Totp().ConfirmEnrollment(context.Background(), user.ID.String(), code)
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}

	// 1. Password login intercepted: returns 200 with challenge token, NO session cookie
	csrfCookie, csrfToken := fetchCSRFPair(t, app.Handler)
	loginRec := postJSON(app.Handler, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: rawPass,
	}, csrfCookie, csrfToken, nil)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 login interception, got %d: %s", loginRec.Code, loginRec.Body.String())
	}

	// Assert NO session cookie is set
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == cfg.SessionCookieName && c.Value != "" && c.MaxAge != -1 {
			t.Fatalf("session cookie %q must NOT be issued on login interception", c.Name)
		}
	}

	var interceptData struct {
		TwoFactorRequired bool   `json:"two_factor_required"`
		ChallengeToken    string `json:"challenge_token"`
		ExpiresIn         int    `json:"expires_in"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &interceptData); err != nil {
		t.Fatalf("unmarshal interception response: %v", err)
	}
	if !interceptData.TwoFactorRequired || interceptData.ChallengeToken == "" || interceptData.ExpiresIn <= 0 {
		t.Fatalf("expected two_factor_required=true and valid challenge token, got %+v", interceptData)
	}

	// 2. Verify with wrong challenge token -> 401
	csrfCookie, csrfToken = fetchCSRFPair(t, app.Handler)
	badTokenRec := postJSON(app.Handler, "/auth/totp/verify", map[string]string{
		"challenge_token": "nonexistent-token",
		"code":            "123456",
	}, csrfCookie, csrfToken, nil)
	if badTokenRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with bad challenge token, got %d", badTokenRec.Code)
	}

	// 3. Verify with invalid format -> 400
	badFormatRec := postJSON(app.Handler, "/auth/totp/verify", map[string]string{
		"challenge_token": interceptData.ChallengeToken,
		"code":            "abc",
	}, csrfCookie, csrfToken, nil)
	if badFormatRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with non-digit code, got %d", badFormatRec.Code)
	}

	// 4. Verify with incorrect code -> 400
	wrongCodeRec := postJSON(app.Handler, "/auth/totp/verify", map[string]string{
		"challenge_token": interceptData.ChallengeToken,
		"code":            "000000",
	}, csrfCookie, csrfToken, nil)
	if wrongCodeRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with incorrect code, got %d", wrongCodeRec.Code)
	}

	// 5. Verify token was NOT deleted on single failure: verify with valid drift code succeeds
	driftCode, err := ptotp.GenerateCode(enrollRes.Secret, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatalf("generate drift code: %v", err)
	}
	verifyRec := postJSON(app.Handler, "/auth/totp/verify", map[string]string{
		"challenge_token": interceptData.ChallengeToken,
		"code":            driftCode,
	}, csrfCookie, csrfToken, nil)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on verify with valid code, got %d: %s", verifyRec.Code, verifyRec.Body.String())
	}

	// Assert session cookie WAS set on success
	var sidCookie *http.Cookie
	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == cfg.SessionCookieName && c.Value != "" {
			sidCookie = c
		}
	}
	if sidCookie == nil {
		t.Fatal("session cookie must be set on successful TOTP verification")
	}

	// 6. Token is consumed: second attempt with same token fails
	reuseRec := postJSON(app.Handler, "/auth/totp/verify", map[string]string{
		"challenge_token": interceptData.ChallengeToken,
		"code":            driftCode,
	}, csrfCookie, csrfToken, nil)
	if reuseRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when re-using consumed token, got %d", reuseRec.Code)
	}

	// 7. Test issued session works
	sessRec := doRequest(app.Handler, http.MethodGet, "/auth/session", nil, []*http.Cookie{sidCookie}, nil)
	if sessRec.Code != http.StatusOK {
		t.Fatalf("expected 200 accessing session endpoint with issued cookie, got %d", sessRec.Code)
	}

	// 8. Test Bearer flow on Verify
	loginRec2 := postJSON(app.Handler, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: rawPass,
	}, csrfCookie, csrfToken, nil)
	var interceptData2 struct {
		ChallengeToken string `json:"challenge_token"`
	}
	_ = json.Unmarshal(loginRec2.Body.Bytes(), &interceptData2)

	// Verify using backup code and X-Auth-Type: bearer
	bearerVerifyRec := postJSON(app.Handler, "/auth/totp/backup-code", map[string]string{
		"challenge_token": interceptData2.ChallengeToken,
		"backup_code":     backupCodes[0],
	}, csrfCookie, csrfToken, map[string]string{
		"X-Auth-Type": "bearer",
	})
	if bearerVerifyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on backup code verify bearer, got %d: %s", bearerVerifyRec.Code, bearerVerifyRec.Body.String())
	}
	var bearerResp map[string]any
	_ = json.Unmarshal(bearerVerifyRec.Body.Bytes(), &bearerResp)
	if bearerResp["token"] == nil || bearerResp["token"] == "" {
		t.Fatalf("expected bearer token in response, got %+v", bearerResp)
	}
}

func TestTOTPHandler_DisableAndAliases(t *testing.T) {
	t.Parallel()
	app, dbConn, cfg := setupTotpTestApp(t)

	email := "totp_disable@example.com"
	rawPass := "SecurePass#2026!"
	user := createVerifiedUser(t, dbConn, email, rawPass)

	// Setup TOTP
	enrollRes, err := app.Totp().Enroll(context.Background(), user.ID.String())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code, _ := ptotp.GenerateCode(enrollRes.Secret, time.Now().UTC())
	_, _ = app.Totp().ConfirmEnrollment(context.Background(), user.ID.String(), code)

	csrfCookie, csrfToken := fetchCSRFPair(t, app.Handler)
	sess, rawID, err := app.Session.CreateSession(context.Background(), user.ID, 0, db.SessionTypeCookie, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	_ = sess
	sidCookie := &http.Cookie{Name: cfg.SessionCookieName, Value: rawID}

	// 1. Check alias /api/auth/totp/status
	aliasStatus := doRequest(app.Handler, http.MethodGet, "/api/auth/totp/status", nil, []*http.Cookie{sidCookie}, nil)
	if aliasStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 on alias status, got %d", aliasStatus.Code)
	}

	// 2. Disable with empty credentials -> 401
	emptyRec := postJSON(app.Handler, "/auth/totp/disable", map[string]string{}, csrfCookie, csrfToken, map[string]string{
		"Cookie": sidCookie.String() + "; " + csrfCookie.String(),
	})
	if emptyRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with empty credentials, got %d", emptyRec.Code)
	}

	// 3. Disable with wrong password and wrong code -> 401
	wrongCreds := postJSON(app.Handler, "/auth/totp/disable", map[string]string{
		"password": "wrongpassword",
		"code":     "000000",
	}, csrfCookie, csrfToken, map[string]string{
		"Cookie": sidCookie.String() + "; " + csrfCookie.String(),
	})
	if wrongCreds.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong credentials, got %d", wrongCreds.Code)
	}

	// 4. Disable with valid password via DELETE /auth/totp
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/totp", bytes.NewReader([]byte(fmt.Sprintf(`{"password": %q}`, rawPass))))
	delReq.Header.Set("Content-Type", "application/json")
	delReq.Header.Set("X-CSRF-Token", csrfToken)
	delReq.AddCookie(sidCookie)
	delReq.AddCookie(csrfCookie)
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on DELETE /auth/totp with password, got %d: %s", delRec.Code, delRec.Body.String())
	}

	// 5. Status is now false
	statusRec := doRequest(app.Handler, http.MethodGet, "/auth/totp/status", nil, []*http.Cookie{sidCookie}, nil)
	var statusBody map[string]any
	_ = json.Unmarshal(statusRec.Body.Bytes(), &statusBody)
	if statusBody["enabled"] != false {
		t.Fatalf("expected enabled=false after disable, got %v", statusBody["enabled"])
	}

	// 6. Normal password login now succeeds without 2FA interception
	normalLogin := postJSON(app.Handler, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: rawPass,
	}, csrfCookie, csrfToken, nil)
	if normalLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 on normal login after 2FA disabled, got %d", normalLogin.Code)
	}
	var loginResp map[string]any
	_ = json.Unmarshal(normalLogin.Body.Bytes(), &loginResp)
	if loginResp["two_factor_required"] == true {
		t.Fatal("two_factor_required must NOT be true after TOTP is disabled")
	}
}

func TestTOTPHandler_AttemptExhaustion(t *testing.T) {
	t.Parallel()
	app, dbConn, _ := setupTotpTestApp(t, func(c *config.Config) {
		c.TOTP.MaxAttemptsPerWindow = 3
	})

	email := "totp_attempts@example.com"
	rawPass := "SecurePass#2026!"
	user := createVerifiedUser(t, dbConn, email, rawPass)

	enrollRes, _ := app.Totp().Enroll(context.Background(), user.ID.String())
	code, _ := ptotp.GenerateCode(enrollRes.Secret, time.Now().UTC())
	_, _ = app.Totp().ConfirmEnrollment(context.Background(), user.ID.String(), code)

	// Intercept login to obtain challenge token
	csrfCookie, csrfToken := fetchCSRFPair(t, app.Handler)
	loginRec := postJSON(app.Handler, "/auth/login", db.LoginRequest{
		Email:    email,
		Password: rawPass,
	}, csrfCookie, csrfToken, nil)
	var interceptData struct {
		ChallengeToken string `json:"challenge_token"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &interceptData)

	// Submit invalid code 2 times (< maxAttempts 3) -> 400
	for i := 0; i < 2; i++ {
		rec := postJSON(app.Handler, "/auth/totp/verify", map[string]string{
			"challenge_token": interceptData.ChallengeToken,
			"code":            "000000",
		}, csrfCookie, csrfToken, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: expected 400, got %d", i+1, rec.Code)
		}
	}

	// 3rd attempt: reaches maxAttempts (3) -> max attempts exceeded (429)
	rec3 := postJSON(app.Handler, "/auth/totp/verify", map[string]string{
		"challenge_token": interceptData.ChallengeToken,
		"code":            "000000",
	}, csrfCookie, csrfToken, nil)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: expected 429, got %d", rec3.Code)
	}

	// 4th attempt from a different IP (to bypass IP rate limit): token was destroyed -> 401
	payloadBytes, _ := json.Marshal(map[string]string{
		"challenge_token": interceptData.ChallengeToken,
		"code":            "000000",
	})
	req4 := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", bytes.NewReader(payloadBytes))
	req4.Header.Set("Content-Type", "application/json")
	req4.Header.Set("X-CSRF-Token", csrfToken)
	req4.AddCookie(csrfCookie)
	req4.RemoteAddr = "192.0.2.2:1234"
	rec4 := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("attempt 4: expected 401 on destroyed token from fresh IP, got %d", rec4.Code)
	}

	// Direct DB check: challenge token record must be hard deleted
	var count int64
	dbConn.Model(&db.TwoFactorToken{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected challenge tokens table to have 0 records, got %d", count)
	}
}

func TestRootFacade_TotpWiring(t *testing.T) {
	t.Parallel()
	app, _, _ := setupTotpTestApp(t)

	if app.Totp() == nil {
		t.Fatal("expected app.Totp() to return non-nil service")
	}
	if app.TotpService() == nil {
		t.Fatal("expected app.TotpService() to return non-nil service")
	}
	if app.Totp() != app.TotpService() {
		t.Fatal("expected app.Totp() and app.TotpService() to be identical")
	}
}
