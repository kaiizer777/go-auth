//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/kaiizer777/go-auth/config"
)

// Matches config.DefaultConfig().SessionCookieName.
const sessionCookieName = "sid"

// TestSessionLifecycle_CookiePropagation proves login issues an HttpOnly session
// cookie carrying the configured attributes, and that the client's cookie jar
// replays it on the next authenticated request.
func TestSessionLifecycle_CookiePropagation(t *testing.T) {
	server, client, capture, _ := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.SessionCookieSecure = false
	})

	const (
		email    = "session-cookie@example.com"
		password = "Password123-Secure!"
	)
	createAndVerifyUser(t, client, server.URL, capture, email, password)

	resp, body := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %v", resp.StatusCode, body)
	}

	sid := findCookie(resp, sessionCookieName)
	if sid == nil {
		t.Fatalf("login response did not set the %q cookie", sessionCookieName)
	}
	if len(sid.Value) != 32 {
		t.Fatalf("expected 32-char raw session id in cookie, got length %d", len(sid.Value))
	}
	if !sid.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if sid.Secure {
		t.Fatal("session cookie must mirror SessionCookieSecure=false over plain http")
	}
	if sid.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax session cookie, got %v", sid.SameSite)
	}
	if sid.Path != "/" {
		t.Fatalf("expected session cookie path %q, got %q", "/", sid.Path)
	}
	if sid.MaxAge <= 0 {
		t.Fatalf("expected positive Max-Age on session cookie, got %d", sid.MaxAge)
	}

	sessResp, sessBody := getJSON(t, client, server.URL+"/auth/session")
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/session: expected 200, got %d: %v", sessResp.StatusCode, sessBody)
	}
	session, ok := sessBody["session"].(map[string]any)
	if !ok {
		t.Fatalf("GET /auth/session: expected session object, got %v", sessBody)
	}
	sessionID, _ := session["session_id"].(string)
	if len(sessionID) != 64 {
		t.Fatalf("expected 64-char session digest, got length %d", len(sessionID))
	}
	if sessionID == sid.Value {
		t.Fatal("session_id must be a digest, never the raw cookie value")
	}
	if session["session_type"] != "cookie" {
		t.Fatalf("expected session_type cookie, got %v", session["session_type"])
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
	// 2. POST /auth/logout -> verify 200 OK and clearing cookie (Max-Age=-1)
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

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on logout, got %d", resp.StatusCode)
	}
}

// TestSessionLifecycle_ConcurrentSessionsAndRevocation documents multi-device session management.
// In Phase 4, multiple logins create distinct active sessions; revoking one does not invalidate others.
func TestSessionLifecycle_ConcurrentSessionsAndRevocation(t *testing.T) {
	t.Skip("Session cookie propagation and logout invalidation pending Phase 4")
}
