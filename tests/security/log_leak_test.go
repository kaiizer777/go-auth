package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
)

// logSink is a mutex-guarded writer so captured slog output stays race-clean.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// postAuditJSON sends a CSRF-paired POST through the app handler.
func postAuditJSON(t *testing.T, h http.Handler, cfg config.Config, path string, payload any, cookie *http.Cookie, token string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
		req.Header.Set(cfg.CSRFHeaderName, token)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// auditLines returns captured log lines carrying the given event message.
func auditLines(logs, event string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `"msg":"`+event+`"`) {
			out = append(out, line)
		}
	}
	return out
}

func requireAuditAttrs(t *testing.T, logs, event string, attrs ...string) {
	t.Helper()
	lines := auditLines(logs, event)
	if len(lines) == 0 {
		t.Fatalf("expected audit event %q, none emitted", event)
	}
	for _, attr := range attrs {
		found := false
		for _, line := range lines {
			if strings.Contains(line, attr) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("event %q missing attribute %q (lines: %v)", event, attr, lines)
		}
	}
}

// TestSecurityAuditLogZeroLeak drives the full auth lifecycle and asserts both
// zero sensitive-material leakage and positive emission of every audit event.
func TestSecurityAuditLogZeroLeak(t *testing.T) {
	sink := &logSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(sink, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	app, database, cfg := setupSecurityApp(t, func(c *config.Config) {
		c.RateLimitLoginIPMax = 4
	})

	emailA := "auditleak_a@example.com"
	passA := "AuditLeakPass123!"
	emailB := "auditleak_b@example.com"
	passB := "AuditLeakPass456!"

	csrfCookie, csrfToken := csrfPairForLogin(t, app)

	// Signup user A over HTTP: signup_attempt + signup_success.
	rec := postAuditJSON(t, app.Handler, cfg, "/auth/signup", db.SignupRequest{Email: emailA, Password: passA}, csrfCookie, csrfToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("signup A: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Colliding signup: anti-enumeration 200, attempt only (nil-user guard).
	// Same password: the unverified-recovery path re-binds an identical hash.
	rec = postAuditJSON(t, app.Handler, cfg, "/auth/signup", db.SignupRequest{Email: emailA, Password: passA}, csrfCookie, csrfToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("colliding signup: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Login failure then success.
	rec = postAuditJSON(t, app.Handler, cfg, "/auth/login", db.LoginRequest{Email: emailA, Password: "WrongPass000!"}, csrfCookie, csrfToken, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = postAuditJSON(t, app.Handler, cfg, "/auth/login", db.LoginRequest{Email: emailA, Password: passA}, csrfCookie, csrfToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("good login: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var sessionID string
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.SessionCookieName {
			sessionID = c.Value
		}
	}
	if sessionID == "" {
		t.Fatal("no session cookie in login response")
	}

	// Verify user B: service signup yields the raw token, HTTP verify consumes it.
	_, verifyToken, err := app.Auth.Signup(context.Background(), db.SignupRequest{Email: emailB, Password: passB})
	if err != nil {
		t.Fatalf("service signup B failed: %v", err)
	}
	rec = postAuditJSON(t, app.Handler, cfg, "/auth/verify", db.VerifyEmailRequest{Token: verifyToken}, csrfCookie, csrfToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// Invalid token still logs the attempt.
	rec = postAuditJSON(t, app.Handler, cfg, "/auth/verify", db.VerifyEmailRequest{Token: strings.Repeat("0", 64)}, csrfCookie, csrfToken, nil)
	if rec.Code == http.StatusOK {
		t.Fatal("invalid verify token unexpectedly accepted")
	}

	// Password reset request over HTTP, token via service, confirm over HTTP.
	rec = postAuditJSON(t, app.Handler, cfg, "/auth/password/reset-request", db.PasswordResetRequest{Email: emailA}, csrfCookie, csrfToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset-request: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	resetToken, err := app.Auth.RequestPasswordReset(context.Background(), db.PasswordResetRequest{Email: emailA})
	if err != nil {
		t.Fatalf("service reset request failed: %v", err)
	}
	newPass := "AuditLeakNewPass789!"
	rec = postAuditJSON(t, app.Handler, cfg, "/auth/password/reset", db.PasswordResetConfirmRequest{Token: resetToken, NewPassword: newPass}, csrfCookie, csrfToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset confirm: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// CSRF violation: state-changing POST without a pair.
	raw := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(`{}`)))
	raw.Header.Set("Content-Type", "application/json")
	rawRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rawRec, raw)
	if rawRec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF pair: expected 403, got %d", rawRec.Code)
	}

	// Rate limit: hammer bad logins until the IP limiter trips.
	got429 := false
	for i := 0; i < 10 && !got429; i++ {
		rec = postAuditJSON(t, app.Handler, cfg, "/auth/login", db.LoginRequest{Email: emailA, Password: "WrongPass000!"}, csrfCookie, csrfToken, nil)
		got429 = rec.Code == http.StatusTooManyRequests
	}
	if !got429 {
		t.Fatal("expected 429 rate_limit_exceeded, never tripped")
	}

	// Secrets under test: nothing below may appear in captured logs.
	var userA db.User
	if err := database.Where("LOWER(email) = LOWER(?)", emailA).First(&userA).Error; err != nil {
		t.Fatalf("query user A: %v", err)
	}
	secrets := map[string]string{
		"raw password":     passA,
		"new raw password": newPass,
		"password hash":    userA.PasswordHash,
		"argon2id marker":  "$argon2id$",
		"verify token":     verifyToken,
		"reset token":      resetToken,
		"raw session id":   sessionID,
		"csrf token":       csrfToken,
	}
	logs := sink.String()
	for name, secret := range secrets {
		if secret != "" && strings.Contains(logs, secret) {
			t.Errorf("log leaked %s", name)
		}
	}
	for _, hdr := range []string{"Authorization", "Cookie", "Set-Cookie"} {
		if strings.Contains(logs, hdr) {
			t.Errorf("log leaked sensitive header %q", hdr)
		}
	}

	// Positive emission with required metadata.
	requireAuditAttrs(t, logs, "signup_attempt", `"ip":`, `"user_agent":`, `"account":"`+emailA+`"`)
	requireAuditAttrs(t, logs, "signup_success", `"user_id":`, `"ip":`, `"user_agent":`, `"account":"`+emailA+`"`)
	requireAuditAttrs(t, logs, "login_failure", `"ip":`, `"user_agent":`, `"account":`, `"reason":`)
	requireAuditAttrs(t, logs, "login_success", `"user_id":`, `"ip":`, `"user_agent":`, `"session_type":`)
	requireAuditAttrs(t, logs, "email_verification_attempt", `"ip":`, `"user_agent":`)
	requireAuditAttrs(t, logs, "email_verified", `"user_id":`, `"ip":`)
	requireAuditAttrs(t, logs, "password_reset_request", `"ip":`, `"user_agent":`, `"account":"`+emailA+`"`)
	requireAuditAttrs(t, logs, "password_changed", `"user_id":`, `"ip":`, `"user_agent":`)
	requireAuditAttrs(t, logs, "csrf_violation", `"ip":`, `"user_agent":`, `"path":`, `"reason":`)
	requireAuditAttrs(t, logs, "rate_limit_exceeded", `"ip":`, `"endpoint":`)
}
