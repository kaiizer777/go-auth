//go:build integration || e2e

package e2e

import (
	"net/http"
	"testing"
	"time"
)

func TestPasswordReset_FullLifecycle(t *testing.T) {
	server, client, capture, _ := setupE2EServer(t)

	email := "reset-user@example.com"
	oldPassword := "OldPassword123-Alpha!"
	newPassword := "NewPassword456-Bravo!"

	// 1. Register and verify user
	resp, _ := postJSON(t, client, server.URL+"/auth/signup", map[string]string{
		"email":    email,
		"password": oldPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on signup, got %d", resp.StatusCode)
	}
	verifyTok := capture.nextVerificationToken(t, 2*time.Second)

	respVerify, _ := postJSON(t, client, server.URL+"/auth/verify", map[string]string{
		"token": verifyTok,
	})
	if respVerify.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on verify, got %d", respVerify.StatusCode)
	}

	// 2. Request password reset via POST /auth/password/reset-request
	respResetReq, bodyResetReq := postJSON(t, client, server.URL+"/auth/password/reset-request", map[string]string{
		"email": email,
	})
	if respResetReq.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on reset request, got %d: %v", respResetReq.StatusCode, bodyResetReq)
	}
	expectedMsg := "if an account with that email exists, a password reset link has been sent"
	if bodyResetReq["message"] != expectedMsg {
		t.Fatalf("expected message %q, got %q", expectedMsg, bodyResetReq["message"])
	}

	// 3. Intercept reset token from email capture channel
	resetToken := capture.nextResetToken(t, 2*time.Second)
	if len(resetToken) != 64 {
		t.Fatalf("expected 64-char hex reset token, got %q (len %d)", resetToken, len(resetToken))
	}

	// 4. Confirm password reset via POST /auth/password/reset
	respConfirm, bodyConfirm := postJSON(t, client, server.URL+"/auth/password/reset", map[string]string{
		"token":        resetToken,
		"new_password": newPassword,
	})
	if respConfirm.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on password reset confirm, got %d: %v", respConfirm.StatusCode, bodyConfirm)
	}
	if bodyConfirm["message"] != "password reset successful" {
		t.Fatalf("expected 'password reset successful', got %v", bodyConfirm)
	}

	// 5. Login with old password must fail (401 INVALID_CREDENTIALS)
	respOldLogin, bodyOldLogin := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": oldPassword,
	})
	if respOldLogin.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when logging in with old password, got %d", respOldLogin.StatusCode)
	}
	if bodyOldLogin["code"] != "INVALID_CREDENTIALS" {
		t.Fatalf("expected INVALID_CREDENTIALS with old password, got %v", bodyOldLogin)
	}

	// 6. Login with new password must succeed (200 OK)
	respNewLogin, bodyNewLogin := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": newPassword,
	})
	if respNewLogin.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 when logging in with new password, got %d: %v", respNewLogin.StatusCode, bodyNewLogin)
	}
	if bodyNewLogin["user_id"] == nil {
		t.Fatalf("expected user_id in login response, got %v", bodyNewLogin)
	}

	// 7. Replay attack: reusing same reset token must fail (400 INVALID_TOKEN or TOKEN_EXPIRED)
	respReplay, bodyReplay := postJSON(t, client, server.URL+"/auth/password/reset", map[string]string{
		"token":        resetToken,
		"new_password": "YetAnotherPassword-789!",
	})
	if respReplay.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on token replay, got %d: %v", respReplay.StatusCode, bodyReplay)
	}
	if bodyReplay["code"] != "INVALID_TOKEN" && bodyReplay["code"] != "TOKEN_EXPIRED" {
		t.Fatalf("expected INVALID_TOKEN or TOKEN_EXPIRED on replay, got %v", bodyReplay)
	}
}

func TestPasswordReset_AntiEnumerationUnknownEmail(t *testing.T) {
	server, client, capture, _ := setupE2EServer(t)

	// Password reset request for non-existent email
	resp, body := postJSON(t, client, server.URL+"/auth/password/reset-request", map[string]string{
		"email": "completely-unknown-user@example.com",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on reset request for unknown email, got %d: %v", resp.StatusCode, body)
	}

	expectedMsg := "if an account with that email exists, a password reset link has been sent"
	if body["message"] != expectedMsg {
		t.Fatalf("expected generic parity message %q, got %q", expectedMsg, body["message"])
	}

	// Assert no reset token was emitted
	select {
	case tok := <-capture.passwordResetTokens:
		t.Fatalf("unexpected reset token generated for unknown email: %q", tok)
	case <-time.After(200 * time.Millisecond):
		// No token emitted as expected
	}
}

func TestPasswordReset_AliasRoutesAndValidation(t *testing.T) {
	server, client, capture, _ := setupE2EServer(t)

	email := "alias-reset@example.com"
	password := "InitialPass123!"
	newPassword := "ChangedPass456!"

	resp, _ := postJSON(t, client, server.URL+"/api/auth/signup", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on signup, got %d", resp.StatusCode)
	}
	verifyTok := capture.nextVerificationToken(t, 2*time.Second)

	_, _ = postJSON(t, client, server.URL+"/api/auth/verify-email", map[string]string{
		"token": verifyTok,
	})

	// Reset request via alias route /api/auth/request-password-reset
	respReq, bodyReq := postJSON(t, client, server.URL+"/api/auth/request-password-reset", map[string]string{
		"email": email,
	})
	if respReq.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on alias reset request, got %d: %v", respReq.StatusCode, bodyReq)
	}

	resetTok := capture.nextResetToken(t, 2*time.Second)

	// Validation: Empty new password -> 400 VALIDATION_ERROR
	respEmptyPass, bodyEmptyPass := postJSON(t, client, server.URL+"/api/auth/reset-password", map[string]string{
		"token":        resetTok,
		"new_password": "",
	})
	if respEmptyPass.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty new password, got %d", respEmptyPass.StatusCode)
	}
	if bodyEmptyPass["code"] != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %v", bodyEmptyPass)
	}

	// Validation: Invalid token format -> 400 INVALID_TOKEN
	respBadTok, bodyBadTok := postJSON(t, client, server.URL+"/api/auth/reset-password", map[string]string{
		"token":        "invalid-hex-token",
		"new_password": newPassword,
	})
	if respBadTok.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad token format, got %d", respBadTok.StatusCode)
	}
	if bodyBadTok["code"] != "INVALID_TOKEN" {
		t.Fatalf("expected INVALID_TOKEN, got %v", bodyBadTok)
	}

	// Confirm via alias route /api/auth/reset-password with valid token
	respConfirm, bodyConfirm := postJSON(t, client, server.URL+"/api/auth/reset-password", map[string]string{
		"token":        resetTok,
		"new_password": newPassword,
	})
	if respConfirm.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on alias reset confirm, got %d: %v", respConfirm.StatusCode, bodyConfirm)
	}
	if bodyConfirm["message"] != "password reset successful" {
		t.Fatalf("expected 'password reset successful', got %v", bodyConfirm)
	}
}
