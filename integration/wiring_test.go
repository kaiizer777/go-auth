//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/config"
)

type capturedEmail struct {
	to    string
	token string
	url   string
}

func TestWiring_EndToEndEmailDispatchAndClose(t *testing.T) {
	_, baseCfg := setupDB(t)

	var emailMu sync.Mutex
	verificationEmails := make([]capturedEmail, 0)
	passwordResetEmails := make([]capturedEmail, 0)

	cfg := baseCfg
	cfg.DisableAsyncEmailDispatch = true // synchronous execution for deterministic end-to-end assertions
	cfg.SendVerificationEmail = func(ctx context.Context, p config.VerificationEmailPayload) error {
		emailMu.Lock()
		defer emailMu.Unlock()
		verificationEmails = append(verificationEmails, capturedEmail{
			to:    p.To,
			token: p.Token,
			url:   p.URL,
		})
		return nil
	}
	cfg.SendPasswordResetEmail = func(ctx context.Context, p config.PasswordResetEmailPayload) error {
		emailMu.Lock()
		defer emailMu.Unlock()
		passwordResetEmails = append(passwordResetEmails, capturedEmail{
			to:    p.To,
			token: p.Token,
			url:   p.URL,
		})
		return nil
	}

	authInst, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("goauth.New failed: %v", err)
	}

	server := httptest.NewServer(authInst.Handler)
	defer server.Close()

	// 1. POST /auth/signup via HTTP
	signupBody, _ := json.Marshal(map[string]string{
		"email":    "wiring@example.com",
		"password": "CorrectHorseBatteryStaple123!",
	})
	resp, err := http.Post(server.URL+"/auth/signup", "application/json", bytes.NewReader(signupBody))
	if err != nil {
		t.Fatalf("signup HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on signup, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Verify verification email dispatched
	emailMu.Lock()
	if len(verificationEmails) != 1 {
		t.Fatalf("expected 1 verification email, found %d", len(verificationEmails))
	}
	vEmail := verificationEmails[0]
	emailMu.Unlock()

	if vEmail.to != "wiring@example.com" {
		t.Fatalf("expected email recipient wiring@example.com, got %s", vEmail.to)
	}
	if vEmail.token == "" {
		t.Fatal("expected non-empty verification token in email payload")
	}
	expectedVerifyURL := fmt.Sprintf("%s/auth/verify/email?token=%s", cfg.BaseURL, vEmail.token)
	if vEmail.url != expectedVerifyURL {
		t.Fatalf("expected verification URL %s, got %s", expectedVerifyURL, vEmail.url)
	}

	// 2. POST /auth/verify via HTTP using token from dispatched email
	verifyBody, _ := json.Marshal(map[string]string{
		"token": vEmail.token,
	})
	resp, err = http.Post(server.URL+"/auth/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("verify HTTP request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on verify, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. POST /auth/password/reset-request via HTTP
	resetReqBody, _ := json.Marshal(map[string]string{
		"email": "wiring@example.com",
	})
	resp, err = http.Post(server.URL+"/auth/password/reset-request", "application/json", bytes.NewReader(resetReqBody))
	if err != nil {
		t.Fatalf("password reset request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on reset request, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Verify reset email dispatched
	emailMu.Lock()
	if len(passwordResetEmails) != 1 {
		t.Fatalf("expected 1 password reset email, found %d", len(passwordResetEmails))
	}
	prEmail := passwordResetEmails[0]
	emailMu.Unlock()

	if prEmail.to != "wiring@example.com" {
		t.Fatalf("expected reset recipient wiring@example.com, got %s", prEmail.to)
	}
	if prEmail.token == "" {
		t.Fatal("expected non-empty reset token in email payload")
	}

	// 4. POST /auth/password/reset via HTTP using token from dispatched reset email
	resetConfirmBody, _ := json.Marshal(map[string]string{
		"token":        prEmail.token,
		"new_password": "NewWiredPassword123!",
	})
	resp, err = http.Post(server.URL+"/auth/password/reset", "application/json", bytes.NewReader(resetConfirmBody))
	if err != nil {
		t.Fatalf("password reset confirmation failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on reset confirm, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 5. POST /auth/login with new password
	loginBody, _ := json.Marshal(map[string]string{
		"email":    "wiring@example.com",
		"password": "NewWiredPassword123!",
	})
	resp, err = http.Post(server.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on login, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 6. Close() functionality
	if err := authInst.Close(); err != nil {
		t.Fatalf("auth.Close() failed: %v", err)
	}

	// Double close should succeed idempotently or return closed
	_ = authInst.Close()
}
