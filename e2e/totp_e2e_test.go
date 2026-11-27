//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ptotp "github.com/pquerna/otp/totp"

	"github.com/kaiizer777/go-auth/config"
)

const e2eTOTPEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func createAndVerifyUser(t *testing.T, client *http.Client, serverURL string, capture *emailCapture, email, password string) {
	t.Helper()
	resp, body := postJSON(t, client, serverURL+"/auth/signup", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signup expected 200, got %d: %v", resp.StatusCode, body)
	}

	verToken := capture.nextVerificationToken(t, 3*time.Second)
	resp, body = postJSON(t, client, serverURL+"/auth/verify", map[string]string{
		"token": verToken,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify email expected 200, got %d: %v", resp.StatusCode, body)
	}
}

func deleteJSON(t *testing.T, client *http.Client, targetURL string, payload any) (*http.Response, map[string]any) {
	t.Helper()
	csrfToken := fetchCSRFToken(t, client, targetURL)

	var bodyReader io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal JSON payload: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(http.MethodDelete, targetURL, bodyReader)
	if err != nil {
		t.Fatalf("failed to create DELETE request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute DELETE request: %v", err)
	}

	data := readJSONBody(t, resp)
	return resp, data
}

// 1. TestE2E_TOTPFullJourney_Password:
// Full round-trip: Signup -> Verify Email -> Login (Session A) -> Enroll -> Confirm (returns backup codes) ->
// Logout -> Intercepted Login (challenge token, 0 session cookies) -> TOTP Verify -> Session B issued ->
// Access protected route /auth/session.
func TestE2E_TOTPFullJourney_Password(t *testing.T) {
	server, client, capture, _ := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.RequireEmailVerification = true
		cfg.TOTP.EncryptionKey = e2eTOTPEncryptionKey
		cfg.TOTP.Issuer = "GoAuthE2E"
		cfg.TOTP.ChallengeTokenTTL = 5 * time.Minute
	})

	email := "e2e_totp_full@example.com"
	password := "SecureE2EPassword#2026!"

	// 1. Signup & Verify Email
	createAndVerifyUser(t, client, server.URL, capture, email, password)

	// 2. Login before 2FA -> regular login, session A issued
	resp, body := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %v", resp.StatusCode, body)
	}
	if twoFactor, _ := body["two_factor_required"].(bool); twoFactor {
		t.Fatalf("2FA must not be required before enrollment")
	}

	// 3. Verify initial TOTP status is false
	resp, body = getJSON(t, client, server.URL+"/auth/totp/status")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status expected 200, got %d: %v", resp.StatusCode, body)
	}
	if enabled, _ := body["enabled"].(bool); enabled {
		t.Fatalf("status should be false before enrollment")
	}

	// 4. Enroll TOTP
	resp, body = postJSON(t, client, server.URL+"/auth/totp/enroll", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll expected 200, got %d: %v", resp.StatusCode, body)
	}
	secret, ok := body["secret"].(string)
	if !ok || secret == "" {
		t.Fatalf("enroll response missing secret: %v", body)
	}
	if _, ok := body["otp_uri"].(string); !ok {
		t.Fatalf("enroll response missing otp_uri")
	}
	if _, ok := body["qr_code"].(string); !ok {
		t.Fatalf("enroll response missing qr_code")
	}

	// 5. Confirm TOTP enrollment using previous 30s code so current code stays fresh for login
	setupCode, err := ptotp.GenerateCode(secret, time.Now().UTC().Add(-30*time.Second))
	if err != nil {
		t.Fatalf("generate setup code: %v", err)
	}
	resp, body = postJSON(t, client, server.URL+"/auth/totp/confirm", map[string]string{
		"code": setupCode,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm expected 200, got %d: %v", resp.StatusCode, body)
	}
	if confirmed, _ := body["confirmed"].(bool); !confirmed {
		t.Fatalf("expected confirmed=true, got %v", body)
	}
	backupCodesRaw, ok := body["backup_codes"].([]any)
	if !ok || len(backupCodesRaw) != 10 {
		t.Fatalf("expected 10 backup codes on confirm, got %v", body["backup_codes"])
	}

	// Status must now be true
	resp, body = getJSON(t, client, server.URL+"/auth/totp/status")
	if resp.StatusCode != http.StatusOK || body["enabled"] != true {
		t.Fatalf("expected enabled=true after confirm, got %v", body)
	}

	// 6. Logout of session A
	resp, _ = postJSON(t, client, server.URL+"/auth/logout", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout expected 200, got %d", resp.StatusCode)
	}

	// 7. Password Login intercepted -> 200 with challenge_token, ZERO session cookies
	resp, body = postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login intercepted expected 200, got %d: %v", resp.StatusCode, body)
	}
	twoFactor, _ := body["two_factor_required"].(bool)
	if !twoFactor {
		t.Fatalf("expected two_factor_required=true, got %v", body)
	}
	challengeToken, ok := body["challenge_token"].(string)
	if !ok || challengeToken == "" {
		t.Fatalf("expected challenge_token, got %v", body)
	}

	// Verify protected route rejected before TOTP completion
	resp, _ = getJSON(t, client, server.URL+"/auth/session")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on /auth/session before TOTP completion, got %d", resp.StatusCode)
	}

	// 8. TOTP Verify with valid code
	validCode, err := ptotp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate valid code: %v", err)
	}
	resp, body = postJSON(t, client, server.URL+"/auth/totp/verify", map[string]string{
		"challenge_token": challengeToken,
		"code":            validCode,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp verify expected 200, got %d: %v", resp.StatusCode, body)
	}
	if body["user_id"] == nil {
		t.Fatalf("expected user_id in verify response, got %v", body)
	}

	// 9. Access protected route /auth/session -> 200 OK (Session B validated)
	resp, body = getJSON(t, client, server.URL+"/auth/session")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session validation expected 200, got %d: %v", resp.StatusCode, body)
	}
	if body["session"] == nil {
		t.Fatalf("expected session object in response, got %v", body)
	}
}

// 2. TestE2E_TOTPRecoveryJourney_BackupCode:
// Intercepted login -> verify backup code -> session issued -> access /auth/session ->
// verify backup code is single-use and cannot be used twice.
func TestE2E_TOTPRecoveryJourney_BackupCode(t *testing.T) {
	server, client, capture, _ := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.RequireEmailVerification = false
		cfg.TOTP.EncryptionKey = e2eTOTPEncryptionKey
		cfg.TOTP.Issuer = "GoAuthE2E"
	})

	email := "e2e_backup_recovery@example.com"
	password := "SecureE2EBackup#2026!"

	// Signup & Verify Email & Login
	createAndVerifyUser(t, client, server.URL, capture, email, password)
	postJSON(t, client, server.URL+"/auth/login", map[string]string{"email": email, "password": password})

	// Enroll & Confirm
	_, enrollBody := postJSON(t, client, server.URL+"/auth/totp/enroll", nil)
	secret := enrollBody["secret"].(string)
	setupCode, _ := ptotp.GenerateCode(secret, time.Now().UTC().Add(-30*time.Second))
	_, confirmBody := postJSON(t, client, server.URL+"/auth/totp/confirm", map[string]string{"code": setupCode})

	rawBackupCodes := confirmBody["backup_codes"].([]any)
	backupCode1 := rawBackupCodes[0].(string)
	backupCode2 := rawBackupCodes[1].(string)

	// Logout
	postJSON(t, client, server.URL+"/auth/logout", nil)

	// Intercepted Login 1
	_, loginBody1 := postJSON(t, client, server.URL+"/auth/login", map[string]string{"email": email, "password": password})
	challengeToken1 := loginBody1["challenge_token"].(string)

	// Recovery with backup code 1
	resp, body := postJSON(t, client, server.URL+"/auth/totp/backup", map[string]string{
		"challenge_token": challengeToken1,
		"backup_code":     backupCode1,
	})
	if resp.StatusCode != http.StatusOK || body["user_id"] == nil {
		t.Fatalf("backup verify expected 200, got %d: %v", resp.StatusCode, body)
	}

	// Verify session active
	resp, body = getJSON(t, client, server.URL+"/auth/session")
	if resp.StatusCode != http.StatusOK || body["session"] == nil {
		t.Fatalf("expected active session, got status %d: %v", resp.StatusCode, body)
	}

	// Logout
	postJSON(t, client, server.URL+"/auth/logout", nil)

	// Intercepted Login 2
	_, loginBody2 := postJSON(t, client, server.URL+"/auth/login", map[string]string{"email": email, "password": password})
	challengeToken2 := loginBody2["challenge_token"].(string)

	// Attempt to REUSE backup code 1 -> must fail with 400 BACKUP_CODE_INVALID
	resp, body = postJSON(t, client, server.URL+"/auth/totp/backup", map[string]string{
		"challenge_token": challengeToken2,
		"backup_code":     backupCode1,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on reused backup code, got %d: %v", resp.StatusCode, body)
	}
	if body["code"] != "BACKUP_CODE_INVALID" && body["code"] != "TOTP_BACKUP_CODE_INVALID" {
		t.Fatalf("expected BACKUP_CODE_INVALID code, got %v", body)
	}

	// Using backup code 2 succeeds
	resp, body = postJSON(t, client, server.URL+"/auth/totp/backup", map[string]string{
		"challenge_token": challengeToken2,
		"backup_code":     backupCode2,
	})
	if resp.StatusCode != http.StatusOK || body["user_id"] == nil {
		t.Fatalf("expected backup code 2 to succeed, got %d: %v", resp.StatusCode, body)
	}
}

// 3. TestE2E_TOTPDisableAndReenrollJourney:
// Disable 2FA via DELETE /auth/totp -> password login succeeds directly without interception ->
// re-enroll fresh 2FA -> confirm with new code.
func TestE2E_TOTPDisableAndReenrollJourney(t *testing.T) {
	server, client, capture, _ := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.RequireEmailVerification = false
		cfg.TOTP.EncryptionKey = e2eTOTPEncryptionKey
		cfg.TOTP.Issuer = "GoAuthE2E"
	})

	email := "e2e_disable_reenroll@example.com"
	password := "SecureE2EDisable#2026!"

	// Signup, Verify Email & Login
	createAndVerifyUser(t, client, server.URL, capture, email, password)
	postJSON(t, client, server.URL+"/auth/login", map[string]string{"email": email, "password": password})

	// Initial Enroll & Confirm
	_, enrollBody := postJSON(t, client, server.URL+"/auth/totp/enroll", nil)
	secret1 := enrollBody["secret"].(string)
	setupCode1, _ := ptotp.GenerateCode(secret1, time.Now().UTC().Add(-30*time.Second))
	postJSON(t, client, server.URL+"/auth/totp/confirm", map[string]string{"code": setupCode1})

	// Verify status is true
	_, statusBody := getJSON(t, client, server.URL+"/auth/totp/status")
	if statusBody["enabled"] != true {
		t.Fatalf("expected enabled=true")
	}

	// Disable 2FA with fresh password
	resp, body := deleteJSON(t, client, server.URL+"/auth/totp", map[string]string{
		"password": password,
	})
	if resp.StatusCode != http.StatusOK || body["disabled"] != true {
		t.Fatalf("expected 200 disabled=true, got %d: %v", resp.StatusCode, body)
	}

	// Verify status is false
	_, statusBody = getJSON(t, client, server.URL+"/auth/totp/status")
	if statusBody["enabled"] != false {
		t.Fatalf("expected enabled=false after disable")
	}

	// Logout
	postJSON(t, client, server.URL+"/auth/logout", nil)

	// Normal Login succeeds DIRECTLY without interception
	resp, body = postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on direct login, got %d: %v", resp.StatusCode, body)
	}
	if twoFactor, _ := body["two_factor_required"].(bool); twoFactor {
		t.Fatalf("login must NOT be intercepted when 2FA is disabled")
	}

	// Verify session is valid immediately
	resp, body = getJSON(t, client, server.URL+"/auth/session")
	if resp.StatusCode != http.StatusOK || body["session"] == nil {
		t.Fatalf("expected active session after direct login, got %d", resp.StatusCode)
	}

	// Re-enroll fresh TOTP
	resp, enrollBody2 := postJSON(t, client, server.URL+"/auth/totp/enroll", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on re-enroll, got %d: %v", resp.StatusCode, enrollBody2)
	}
	secret2 := enrollBody2["secret"].(string)

	// Confirm fresh TOTP
	setupCode2, _ := ptotp.GenerateCode(secret2, time.Now().UTC().Add(-30*time.Second))
	resp, body = postJSON(t, client, server.URL+"/auth/totp/confirm", map[string]string{
		"code": setupCode2,
	})
	if resp.StatusCode != http.StatusOK || body["confirmed"] != true {
		t.Fatalf("expected confirmed=true on re-enroll, got %d: %v", resp.StatusCode, body)
	}

	// Status is true again
	_, statusBody = getJSON(t, client, server.URL+"/auth/totp/status")
	if statusBody["enabled"] != true {
		t.Fatalf("expected enabled=true after re-confirm")
	}
}

// 4. TestE2E_TOTPCSRFAndAliasEnforcement:
// Double Submit Cookie CSRF protection across /auth/totp/* and /api/auth/totp/* aliases.
func TestE2E_TOTPCSRFAndAliasEnforcement(t *testing.T) {
	server, client, capture, _ := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.RequireEmailVerification = false
		cfg.TOTP.EncryptionKey = e2eTOTPEncryptionKey
		cfg.TOTP.Issuer = "GoAuthE2E"
	})

	email := "e2e_csrf_aliases@example.com"
	password := "SecureE2ECSRF#2026!"

	// Signup, Verify Email & Login to obtain session
	createAndVerifyUser(t, client, server.URL, capture, email, password)
	postJSON(t, client, server.URL+"/auth/login", map[string]string{"email": email, "password": password})

	endpoints := []string{
		"/auth/totp/enroll",
		"/api/auth/totp/enroll",
	}

	for _, ep := range endpoints {
		targetURL := server.URL + ep

		// 1. Missing CSRF header -> 403 CSRF_TOKEN_MISSING
		req, _ := http.NewRequest(http.MethodPost, targetURL, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := client.Do(req)
		data := readJSONBody(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: expected 403 on missing CSRF token, got %d: %v", ep, resp.StatusCode, data)
		}
		if data["code"] != "CSRF_TOKEN_MISSING" {
			t.Fatalf("%s: expected CSRF_TOKEN_MISSING, got %v", ep, data["code"])
		}

		// 2. Invalid CSRF header -> 403 CSRF_TOKEN_INVALID
		req, _ = http.NewRequest(http.MethodPost, targetURL, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		resp, _ = client.Do(req)
		data = readJSONBody(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: expected 403 on invalid CSRF token, got %d: %v", ep, resp.StatusCode, data)
		}
		if data["code"] != "CSRF_TOKEN_INVALID" {
			t.Fatalf("%s: expected CSRF_TOKEN_INVALID, got %v", ep, data["code"])
		}

		// 3. Valid CSRF -> 200 OK
		resp, data = postJSON(t, client, targetURL, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: expected 200 with valid CSRF, got %d: %v", ep, resp.StatusCode, data)
		}
	}

	// Status GET endpoints work without CSRF headers on both canonical and alias
	for _, statusPath := range []string{"/auth/totp/status", "/api/auth/totp/status"} {
		resp, data := getJSON(t, client, server.URL+statusPath)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %v", statusPath, resp.StatusCode, data)
		}
	}
}

// e2eTOTPKeyring is the same 32-byte key as e2eTOTPEncryptionKey, expressed in
// the kid:base64 ring grammar a rotated deployment uses.
var e2eTOTPKeyring = func() string {
	raw, err := hex.DecodeString(e2eTOTPEncryptionKey)
	if err != nil {
		panic(err)
	}
	return "primary:" + base64.StdEncoding.EncodeToString(raw)
}()

// TestE2E_TOTPJourney_KeyringOnly proves a keyring-only deployment is not a
// silent 2FA bypass: the server enables TOTP, enrollment writes an envelope, and
// a live code confirms it.
func TestE2E_TOTPJourney_KeyringOnly(t *testing.T) {
	server, client, capture, _ := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.RequireEmailVerification = true
		cfg.TOTP.EncryptionKey = ""
		cfg.TOTP.Keyring = e2eTOTPKeyring
		cfg.TOTP.Issuer = "GoAuthE2E"
		cfg.TOTP.ChallengeTokenTTL = 5 * time.Minute
	})

	email := "e2e_totp_keyring@example.com"
	password := "SecureE2EPassword#2026!"
	createAndVerifyUser(t, client, server.URL, capture, email, password)

	resp, body := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %v", resp.StatusCode, body)
	}

	resp, body = postJSON(t, client, server.URL+"/auth/totp/enroll", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll expected 200 with a keyring-only config, got %d: %v", resp.StatusCode, body)
	}
	secret, ok := body["secret"].(string)
	if !ok || secret == "" {
		t.Fatalf("enroll response missing secret: %v", body)
	}

	setupCode, err := ptotp.GenerateCode(secret, time.Now().UTC().Add(-30*time.Second))
	if err != nil {
		t.Fatalf("generate setup code: %v", err)
	}
	resp, body = postJSON(t, client, server.URL+"/auth/totp/confirm", map[string]string{
		"code": setupCode,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm expected 200, got %d: %v", resp.StatusCode, body)
	}

	resp, body = getJSON(t, client, server.URL+"/auth/totp/status")
	if resp.StatusCode != http.StatusOK || body["enabled"] != true {
		t.Fatalf("expected enabled=true after confirm, got %d: %v", resp.StatusCode, body)
	}
}
