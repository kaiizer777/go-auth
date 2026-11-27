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

// TestSessionLifecycle_ConcurrentSessionsAndRevocation proves two logins for the
// same account hold independent sessions: logging one device out leaves the other
// valid, and revoking all sessions rejects the remaining captured cookie.
func TestSessionLifecycle_ConcurrentSessionsAndRevocation(t *testing.T) {
	server, clientA, capture, sqlDB := setupE2EServerWithConfig(t, func(cfg *config.Config) {
		cfg.SessionCookieSecure = false
	})
	clientB := newCookieJarClient(t)

	const (
		email    = "session-multi@example.com"
		password = "Password123-Secure!"
	)
	createAndVerifyUser(t, clientA, server.URL, capture, email, password)

	loginA, bodyA := postJSON(t, clientA, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if loginA.StatusCode != http.StatusOK {
		t.Fatalf("login A: expected 200, got %d: %v", loginA.StatusCode, bodyA)
	}
	userID, ok := bodyA["user_id"].(string)
	if !ok || userID == "" {
		t.Fatalf("login A: expected user_id string, got %v", bodyA)
	}
	sidA := findCookie(loginA, sessionCookieName)
	if sidA == nil {
		t.Fatalf("login A did not set the %q cookie", sessionCookieName)
	}
	if len(sidA.Value) != 32 {
		t.Fatalf("login A: expected 32-char raw session id, got length %d", len(sidA.Value))
	}

	loginB, bodyB := postJSON(t, clientB, server.URL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if loginB.StatusCode != http.StatusOK {
		t.Fatalf("login B: expected 200, got %d: %v", loginB.StatusCode, bodyB)
	}
	sidB := findCookie(loginB, sessionCookieName)
	if sidB == nil {
		t.Fatalf("login B did not set the %q cookie", sessionCookieName)
	}
	if len(sidB.Value) != 32 {
		t.Fatalf("login B: expected 32-char raw session id, got length %d", len(sidB.Value))
	}
	if sidA.Value == sidB.Value {
		t.Fatal("each login must mint a distinct raw session id")
	}

	sessionIDA := currentSessionID(t, clientA, server.URL)
	sessionIDB := currentSessionID(t, clientB, server.URL)
	if len(sessionIDA) != 64 || len(sessionIDB) != 64 {
		t.Fatalf("expected 64-char session digests, got lengths %d and %d", len(sessionIDA), len(sessionIDB))
	}
	if sessionIDA == sessionIDB {
		t.Fatal("each device must hold its own session")
	}

	listResp, listBody := getJSON(t, clientA, server.URL+"/auth/sessions")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list sessions: expected 200, got %d: %v", listResp.StatusCode, listBody)
	}
	rawSessions, ok := listBody["sessions"].([]any)
	if !ok {
		t.Fatalf("list sessions: expected sessions array, got %v", listBody)
	}
	if len(rawSessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(rawSessions))
	}
	currentCount := 0
	for _, raw := range rawSessions {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("list sessions: expected session object, got %v", raw)
		}
		isCurrent, _ := item["is_current"].(bool)
		if !isCurrent {
			continue
		}
		currentCount++
		if item["session_id"] != sessionIDA {
			t.Fatal("device A must be the current session in its own listing")
		}
	}
	if currentCount != 1 {
		t.Fatalf("expected exactly 1 current session, got %d", currentCount)
	}

	logoutResp, logoutBody := postJSON(t, clientA, server.URL+"/auth/logout", nil)
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout A: expected 200, got %d: %v", logoutResp.StatusCode, logoutBody)
	}
	if cleared := findCookie(logoutResp, sessionCookieName); cleared == nil {
		t.Fatalf("logout A did not clear the %q cookie", sessionCookieName)
	}

	if respA, bodyRespA := getJSON(t, clientA, server.URL+"/auth/session"); respA.StatusCode != http.StatusUnauthorized {
		t.Fatalf("device A after logout: expected 401, got %d: %v", respA.StatusCode, bodyRespA)
	}
	replayA, replayBodyA := replaySessionCookie(t, newJarlessClient(), server.URL, sidA.Value)
	if replayA.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay of device A session: expected 401, got %d: %v", replayA.StatusCode, replayBodyA)
	}
	if replayBodyA["code"] != "SESSION_INVALID" {
		t.Fatalf("replay of device A session: expected SESSION_INVALID, got %v", replayBodyA)
	}

	if sessionIDB != currentSessionID(t, clientB, server.URL) {
		t.Fatal("logging device A out must not invalidate device B's session")
	}

	var sessionCount int
	if err := sqlDB.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = $1", userID).Scan(&sessionCount); err != nil {
		t.Fatalf("failed to count sessions: %v", err)
	}
	if sessionCount != 1 {
		t.Fatalf("expected 1 session row after per-device logout, found %d", sessionCount)
	}

	revokeResp, revokeBody := deleteJSON(t, clientB, server.URL+"/auth/sessions", nil)
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke all: expected 200, got %d: %v", revokeResp.StatusCode, revokeBody)
	}
	if revokeBody["message"] != "All sessions invalidated" {
		t.Fatalf("revoke all: unexpected message %v", revokeBody)
	}
	clearedB := findCookie(revokeResp, sessionCookieName)
	if clearedB == nil {
		t.Fatalf("revoke all did not clear the %q cookie", sessionCookieName)
	}
	if clearedB.MaxAge != -1 {
		t.Fatalf("revoke all must expire the session cookie, got Max-Age %d", clearedB.MaxAge)
	}

	replayB, replayBodyB := replaySessionCookie(t, newJarlessClient(), server.URL, sidB.Value)
	if replayB.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay of revoked session: expected 401, got %d: %v", replayB.StatusCode, replayBodyB)
	}
	if replayBodyB["code"] != "SESSION_INVALID" {
		t.Fatalf("replay of revoked session: expected SESSION_INVALID, got %v", replayBodyB)
	}

	if err := sqlDB.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = $1", userID).Scan(&sessionCount); err != nil {
		t.Fatalf("failed to count sessions after revoke all: %v", err)
	}
	if sessionCount != 0 {
		t.Fatalf("expected 0 session rows after revoke all, found %d", sessionCount)
	}
}

// currentSessionID returns the authenticated session digest, failing on any
// non-200 response.
func currentSessionID(t *testing.T, client *http.Client, serverURL string) string {
	t.Helper()
	resp, body := getJSON(t, client, serverURL+"/auth/session")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/session: expected 200, got %d: %v", resp.StatusCode, body)
	}
	session, ok := body["session"].(map[string]any)
	if !ok {
		t.Fatalf("GET /auth/session: expected session object, got %v", body)
	}
	sessionID, _ := session["session_id"].(string)
	if len(sessionID) != 64 {
		t.Fatalf("expected 64-char session digest, got length %d", len(sessionID))
	}
	return sessionID
}
