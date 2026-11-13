//go:build integration || e2e

package e2e

import (
	"net/http"
	"testing"
)

// TestSessionLifecycle_CookiePropagation documents expected cookie issuance upon login.
// In Phase 4, login must set a secure, HttpOnly session cookie that automatically propagates
// across subsequent requests via http.Client's cookiejar.
func TestSessionLifecycle_CookiePropagation(t *testing.T) {
	t.Skip("Session cookie propagation and logout invalidation pending Phase 4")

	server, client, _, _ := setupE2EServer(t)

	// Placeholder flow for Phase 4:
	// 1. POST /auth/signup & verify
	// 2. POST /auth/login -> verify Set-Cookie: session=...; HttpOnly; SameSite=Lax
	// 3. GET /auth/me or protected endpoint -> verify 200 OK with authenticated session
	resp, body := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    "session-user@example.com",
		"password": "Password123!",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %v", resp.StatusCode, body)
	}
}

// TestSessionLifecycle_LogoutInvalidation documents expected session termination on logout.
// In Phase 4, POST /auth/logout must revoke the active session in the database and clear
// the session cookie on the client.
func TestSessionLifecycle_LogoutInvalidation(t *testing.T) {
	t.Skip("Session cookie propagation and logout invalidation pending Phase 4")

	server, client, _, _ := setupE2EServer(t)

	// Placeholder flow for Phase 4:
	// 1. Authenticate to establish session
	// 2. POST /auth/logout -> verify 204 No Content and clearing cookie (Max-Age=0)
	// 3. GET /auth/me or protected endpoint -> verify 401 Unauthorized
	req, err := http.NewRequest(http.MethodPost, server.URL+"/auth/logout", nil)
	if err != nil {
		t.Fatalf("failed to create logout request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute logout request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 No Content on logout, got %d", resp.StatusCode)
	}
}

// TestSessionLifecycle_ConcurrentSessionsAndRevocation documents multi-device session management.
// In Phase 4, multiple logins create distinct active sessions; revoking one does not invalidate others.
func TestSessionLifecycle_ConcurrentSessionsAndRevocation(t *testing.T) {
	t.Skip("Session cookie propagation and logout invalidation pending Phase 4")
}
