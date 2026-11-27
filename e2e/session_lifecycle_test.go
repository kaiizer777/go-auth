//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
)

// Matches config.DefaultConfig().SessionCookieName.
const sessionCookieName = "sid"

// newJarlessClient returns a client with no cookie jar, so a captured raw
// session ID can be replayed explicitly instead of relying on cookie storage.
func newJarlessClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// replaySessionCookie sends GET /auth/session with the given raw session ID as
// the only credential, bypassing any jar-managed cookie lifecycle.
func replaySessionCookie(t *testing.T, client *http.Client, serverURL, rawID string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, serverURL+"/auth/session", nil)
	if err != nil {
		t.Fatalf("failed to create replay request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: rawID})

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute replay request: %v", err)
	}
	return resp, readJSONBody(t, resp)
}

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

// TestSessionLifecycle_LogoutInvalidation proves logout deletes the session row
// server-side and clears the cookie: the jar drops it, and the captured
// pre-logout value replayed from a jar-less client is rejected.
func TestSessionLifecycle_LogoutInvalidation(t *testing.T) {
	server, client, capture, sqlDB := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.SessionCookieSecure = false
	})

	const (
		email    = "session-logout@example.com"
		password = "Password123-Secure!"
	)
	createAndVerifyUser(t, client, server.URL, capture, email, password)

	loginResp, loginBody := postJSON(t, client, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %v", loginResp.StatusCode, loginBody)
	}
	userID, ok := loginBody["user_id"].(string)
	if !ok || userID == "" {
		t.Fatalf("login: expected user_id string, got %v", loginBody)
	}

	sid := findCookie(loginResp, sessionCookieName)
	if sid == nil {
		t.Fatalf("login response did not set the %q cookie", sessionCookieName)
	}
	if len(sid.Value) != 32 {
		t.Fatalf("expected 32-char raw session id in cookie, got length %d", len(sid.Value))
	}

	logoutResp, logoutBody := postJSON(t, client, server.URL+"/auth/logout", nil)
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout: expected 200, got %d: %v", logoutResp.StatusCode, logoutBody)
	}
	if logoutBody["message"] != "Logged out successfully" {
		t.Fatalf("logout: unexpected message %v", logoutBody)
	}

	cleared := findCookie(logoutResp, sessionCookieName)
	if cleared == nil {
		t.Fatalf("logout response did not clear the %q cookie", sessionCookieName)
	}
	if cleared.Value != "" {
		t.Fatal("logout must clear the session cookie value")
	}
	if cleared.MaxAge != -1 {
		t.Fatalf("logout must expire the session cookie, got Max-Age %d", cleared.MaxAge)
	}

	probeReq, err := http.NewRequest(http.MethodGet, server.URL+"/auth/session", nil)
	if err != nil {
		t.Fatalf("failed to create probe request: %v", err)
	}
	for _, c := range client.Jar.Cookies(probeReq.URL) {
		if c.Name == sessionCookieName {
			t.Fatal("cookie jar still holds the session cookie after logout")
		}
	}

	replayResp, replayBody := replaySessionCookie(t, newJarlessClient(), server.URL, sid.Value)
	if replayResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay of logged-out session: expected 401, got %d: %v", replayResp.StatusCode, replayBody)
	}
	if replayBody["code"] != "SESSION_INVALID" {
		t.Fatalf("replay of logged-out session: expected SESSION_INVALID, got %v", replayBody)
	}

	anonResp, anonBody := getJSON(t, newJarlessClient(), server.URL+"/auth/session")
	if anonResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request without credentials: expected 401, got %d: %v", anonResp.StatusCode, anonBody)
	}
	if anonBody["code"] != "SESSION_INVALID" {
		t.Fatalf("request without credentials: expected SESSION_INVALID, got %v", anonBody)
	}

	var sessionCount int
	if err := sqlDB.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = $1", userID).Scan(&sessionCount); err != nil {
		t.Fatalf("failed to count sessions: %v", err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected 0 session rows after logout, found %d", sessionCount)
	}
}

// TestSessionLifecycle_ConcurrentSessionsAndRevocation documents multi-device session management.
// In Phase 4, multiple logins create distinct active sessions; revoking one does not invalidate others.
func TestSessionLifecycle_ConcurrentSessionsAndRevocation(t *testing.T) {
	t.Skip("Session cookie propagation and logout invalidation pending Phase 4")
}
