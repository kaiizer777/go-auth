//go:build integration || e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
)

func TestAuthLifecycle_RegistrationAndVerificationJourney(t *testing.T) {
	server, client, capture, sqlDB := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.RequireEmailVerification = true
	})

	email := "e2e-user@example.com"
	password := "Correct-Horse-Battery-Staple-123!"

	// 1. Attempt login before registration -> 401 INVALID_CREDENTIALS
	loginPayload := map[string]string{
		"email":    email,
		"password": password,
	}
	resp, body := postJSON(t, client, server.URL+"/auth/login", loginPayload)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on login before registration, got %d", resp.StatusCode)
	}
	if body["code"] != "INVALID_CREDENTIALS" {
		t.Fatalf("expected INVALID_CREDENTIALS error code, got %v", body)
	}

	// 2. Signup with valid payload -> 200 OK
	signupPayload := map[string]string{
		"email":    email,
		"password": password,
	}
	resp, body = postJSON(t, client, server.URL+"/auth/signup", signupPayload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on signup, got %d: %v", resp.StatusCode, body)
	}
	if msg, ok := body["message"].(string); !ok || msg != "if this email is new, a verification link has been sent" {
		t.Fatalf("unexpected signup response message: %v", body)
	}

	// 3. Intercept verification token from email capture channel
	verificationToken := capture.nextVerificationToken(t, 2*time.Second)
	if len(verificationToken) != 64 {
		t.Fatalf("expected 64-char hex verification token, got %q (len %d)", verificationToken, len(verificationToken))
	}

	// 4. Attempt login before verification with RequireEmailVerification: true -> 403 EMAIL_NOT_VERIFIED
	resp, body = postJSON(t, client, server.URL+"/auth/login", loginPayload)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 before email verification, got %d", resp.StatusCode)
	}
	if body["code"] != "EMAIL_NOT_VERIFIED" {
		t.Fatalf("expected EMAIL_NOT_VERIFIED error code, got %v", body)
	}

	// 5. Verify email via POST /auth/verify -> 200 OK
	verifyPayload := map[string]string{
		"token": verificationToken,
	}
	resp, body = postJSON(t, client, server.URL+"/auth/verify", verifyPayload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on email verification, got %d: %v", resp.StatusCode, body)
	}
	if msg, ok := body["message"].(string); !ok || msg != "email verified" {
		t.Fatalf("unexpected verify response message: %v", body)
	}

	// 6. Verify single-use: replay verification token -> 400 INVALID_TOKEN or TOKEN_EXPIRED
	resp, body = postJSON(t, client, server.URL+"/auth/verify", verifyPayload)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on token replay, got %d: %v", resp.StatusCode, body)
	}
	if body["code"] != "INVALID_TOKEN" && body["code"] != "TOKEN_EXPIRED" {
		t.Fatalf("expected INVALID_TOKEN or TOKEN_EXPIRED on replay, got %v", body)
	}

	// 7. Verify email verified state in database
	var emailVerified bool
	if err := sqlDB.QueryRow("SELECT email_verified FROM users WHERE email = $1", email).Scan(&emailVerified); err != nil {
		t.Fatalf("failed to query user email_verified state: %v", err)
	}
	if !emailVerified {
		t.Fatalf("expected email_verified to be true in database")
	}

	// 8. Attempt login after verification -> 200 OK with user_id
	resp, body = postJSON(t, client, server.URL+"/auth/login", loginPayload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on login after verification, got %d: %v", resp.StatusCode, body)
	}
	userIDStr, ok := body["user_id"].(string)
	if !ok || userIDStr == "" {
		t.Fatalf("expected valid user_id in login response, got %v", body)
	}
}

func TestAuthLifecycle_VerificationAliasRoute(t *testing.T) {
	server, client, capture, _ := setupE2EServer(t)

	email := "alias-verify@example.com"
	password := "Password123-Safe-Phrase!"

	// Signup via /api/auth/signup alias
	resp, _ := postJSON(t, client, server.URL+"/api/auth/signup", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /api/auth/signup, got %d", resp.StatusCode)
	}

	token := capture.nextVerificationToken(t, 2*time.Second)

	// Verify via /api/auth/verify-email alias
	resp, body := postJSON(t, client, server.URL+"/api/auth/verify-email", map[string]string{
		"token": token,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /api/auth/verify-email alias, got %d: %v", resp.StatusCode, body)
	}
	if msg, ok := body["message"].(string); !ok || msg != "email verified" {
		t.Fatalf("expected 'email verified', got %v", body)
	}
}

func TestAuthLifecycle_LoginAndAntiEnumeration(t *testing.T) {
	server, client, capture, sqlDB := setupE2EServer(t)

	email := "anti-enumeration@example.com"
	password := "Secure-Password-987!"

	// First signup
	resp, body := postJSON(t, client, server.URL+"/auth/signup", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on first signup, got %d", resp.StatusCode)
	}
	genericMsg := body["message"]

	verificationToken := capture.nextVerificationToken(t, 2*time.Second)

	// Verify email so account is verified
	respVerify, _ := postJSON(t, client, server.URL+"/auth/verify", map[string]string{
		"token": verificationToken,
	})
	if respVerify.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on verify, got %d", respVerify.StatusCode)
	}

	// Duplicate signup with same email -> identical generic message (anti-enumeration parity)
	respDup, bodyDup := postJSON(t, client, server.URL+"/auth/signup", map[string]string{
		"email":    email,
		"password": "AttackerPassword-456!",
	})
	if respDup.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on duplicate signup, got %d", respDup.StatusCode)
	}
	if bodyDup["message"] != genericMsg {
		t.Fatalf("expected duplicate message parity %q, got %q", genericMsg, bodyDup["message"])
	}

	// Case-insensitive duplicate signup (e.g. UPPERCASE) -> identical generic response
	respUpper, bodyUpper := postJSON(t, client, server.URL+"/auth/signup", map[string]string{
		"email":    "ANTI-ENUMERATION@EXAMPLE.COM",
		"password": "YetAnotherPassword!",
	})
	if respUpper.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on uppercase duplicate signup, got %d", respUpper.StatusCode)
	}
	if bodyUpper["message"] != genericMsg {
		t.Fatalf("expected uppercase duplicate message parity, got %q", bodyUpper["message"])
	}

	// Verify only one user account exists in DB
	var userCount int
	if err := sqlDB.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1)", email).Scan(&userCount); err != nil {
		t.Fatalf("failed to query users count: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("expected exactly 1 user in DB, found %d", userCount)
	}

	// Login with original correct credentials -> 200 OK (password must NOT be overwritten by duplicate signups)
	respLogin, bodyLogin := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if respLogin.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on correct login, got %d: %v", respLogin.StatusCode, bodyLogin)
	}
	if bodyLogin["user_id"] == nil {
		t.Fatalf("expected user_id in login response, got %v", bodyLogin)
	}

	// Login with wrong password -> 401 INVALID_CREDENTIALS
	respWrongPass, bodyWrongPass := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": "WrongPassword-123!",
	})
	if respWrongPass.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong password, got %d", respWrongPass.StatusCode)
	}
	if bodyWrongPass["code"] != "INVALID_CREDENTIALS" {
		t.Fatalf("expected INVALID_CREDENTIALS on wrong password, got %v", bodyWrongPass)
	}

	// Login with unknown email -> identical 401 INVALID_CREDENTIALS
	respUnknown, bodyUnknown := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    "nonexistent-user@example.com",
		"password": password,
	})
	if respUnknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unknown user login, got %d", respUnknown.StatusCode)
	}
	if bodyUnknown["code"] != "INVALID_CREDENTIALS" {
		t.Fatalf("expected INVALID_CREDENTIALS on unknown user, got %v", bodyUnknown)
	}
	if bodyUnknown["message"] != bodyWrongPass["message"] {
		t.Fatalf("expected identical error message for wrong password and unknown email: %q vs %q",
			bodyWrongPass["message"], bodyUnknown["message"])
	}
}

func TestAuthLifecycle_InputValidationRejections(t *testing.T) {
	server, client, _, _ := setupE2EServer(t)

	tests := []struct {
		name       string
		path       string
		payload    map[string]string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "signup empty email",
			path:       "/auth/signup",
			payload:    map[string]string{"email": "", "password": "ValidPassword123!"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_EMAIL",
		},
		{
			name:       "signup invalid email format",
			path:       "/auth/signup",
			payload:    map[string]string{"email": "not-an-email", "password": "ValidPassword123!"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_EMAIL",
		},
		{
			name:       "signup empty password",
			path:       "/auth/signup",
			payload:    map[string]string{"email": "valid@example.com", "password": ""},
			wantStatus: http.StatusBadRequest,
			wantCode:   "VALIDATION_ERROR",
		},
		{
			name:       "login invalid email",
			path:       "/auth/login",
			payload:    map[string]string{"email": "not-an-email", "password": "ValidPassword123!"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_EMAIL",
		},
		{
			name:       "login empty password",
			path:       "/auth/login",
			payload:    map[string]string{"email": "valid@example.com", "password": ""},
			wantStatus: http.StatusBadRequest,
			wantCode:   "VALIDATION_ERROR",
		},
		{
			name:       "verify invalid token format",
			path:       "/auth/verify",
			payload:    map[string]string{"token": "not-a-64-char-hex-token"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_TOKEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, body := postJSON(t, client, server.URL+tt.path, tt.payload)
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %v", tt.wantStatus, resp.StatusCode, body)
			}
			if body["code"] != tt.wantCode {
				t.Fatalf("expected code %q, got %q", tt.wantCode, body["code"])
			}
		})
	}
}


