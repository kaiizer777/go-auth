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

