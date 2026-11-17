package security_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
)

// asvsRequest sends one request through the app handler with optional CSRF
// pair, remote address, and extra headers.
func asvsRequest(t *testing.T, h http.Handler, cfg config.Config, method, path, remoteAddr string, payload any, cookie *http.Cookie, token string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
	} else if method == http.MethodPost {
		body = []byte(`{}`)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if payload != nil || method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if cookie != nil {
		req.AddCookie(cookie)
		req.Header.Set(cfg.CSRFHeaderName, token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// requireBaselineHeaders asserts the ASVS V14.4 header baseline. hsts selects
// whether Strict-Transport-Security must be present (secure transport only,
// per RFC 6797 it must never appear over cleartext HTTP).
func requireBaselineHeaders(t *testing.T, h http.Header, hsts bool) {
	t.Helper()
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("header %s: got %q, want %q", k, got, v)
		}
	}
	got := h.Get("Strict-Transport-Security")
	if hsts {
		if !strings.Contains(got, "max-age=31536000") || !strings.Contains(got, "includeSubDomains") {
			t.Errorf("HSTS malformed: %q", got)
		}
		if strings.Contains(got, "preload") {
			t.Errorf("HSTS must not include preload by default: %q", got)
		}
	} else if got != "" {
		t.Errorf("HSTS must be absent over cleartext HTTP, got %q", got)
	}
}

// V14.4: baseline headers on standard routes, 404/405 static errors, and
// CORS preflight; HSTS only over secure transport.
func TestASVS_Headers_AllRoutes(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)

	for _, tc := range []struct {
		name, method, path string
		code               int
	}{
		{"health", http.MethodGet, "/health", http.StatusOK},
		{"not found", http.MethodGet, "/no-such-route", http.StatusNotFound},
		{"method not allowed", http.MethodGet, "/auth/login", http.StatusMethodNotAllowed},
		{"token endpoint method guard", http.MethodPost, "/auth/csrf", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := asvsRequest(t, app.Handler, cfg, tc.method, tc.path, "", nil, nil, "", nil)
			if rec.Code != tc.code {
				t.Fatalf("%s %s: expected %d, got %d", tc.method, tc.path, tc.code, rec.Code)
			}
			requireBaselineHeaders(t, rec.Header(), false)
		})
	}

	t.Run("preflight", func(t *testing.T) {
		rec := asvsRequest(t, app.Handler, cfg, http.MethodOptions, "/auth/login", "", nil, nil, "", map[string]string{
			"Origin":                        "http://localhost:3000",
			"Access-Control-Request-Method": "POST",
		})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("preflight: expected 204, got %d", rec.Code)
		}
		requireBaselineHeaders(t, rec.Header(), false)
	})

	t.Run("hsts via proxy header", func(t *testing.T) {
		rec := asvsRequest(t, app.Handler, cfg, http.MethodGet, "/health", "", nil, nil, "", map[string]string{
			"X-Forwarded-Proto": "https",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("health: expected 200, got %d", rec.Code)
		}
		requireBaselineHeaders(t, rec.Header(), true)
	})
}

// V4.2: Double Submit Cookie enforced on all canonical + alias routes,
// token endpoint issuance/reuse, bearer exemption, ambiguous-transport
// rejection, and CSRF cookie clearing on logout.
func TestASVS_CSRF_Boundary(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)

	routes := []string{
		"/auth/signup", "/auth/login", "/auth/verify",
		"/auth/password/reset-request", "/auth/password/reset",
		"/api/auth/signup", "/api/auth/login", "/api/auth/verify-email",
		"/api/auth/request-password-reset", "/api/auth/reset-password",
	}
	for _, route := range routes {
		t.Run("403 without pair "+route, func(t *testing.T) {
			rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, route, "", nil, nil, "", nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "CSRF_TOKEN_MISSING") {
				t.Fatalf("expected CSRF_TOKEN_MISSING, got %s", rec.Body.String())
			}
			requireBaselineHeaders(t, rec.Header(), false)
		})
	}

	t.Run("mismatch rejected", func(t *testing.T) {
		cookie, _ := csrfPairForLogin(t, app)
		for _, route := range []string{"/auth/login", "/api/auth/login"} {
			rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, route, "",
				db.LoginRequest{Email: "ghost@example.com", Password: "WrongPass000!"},
				cookie, strings.Repeat("0", 64), nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: expected 403, got %d", route, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "CSRF_TOKEN_INVALID") {
				t.Fatalf("expected CSRF_TOKEN_INVALID, got %s", rec.Body.String())
			}
		}
	})

	t.Run("pair succeeds", func(t *testing.T) {
		cookie, token := csrfPairForLogin(t, app)
		rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/signup", "",
			db.SignupRequest{Email: "asvs_csrf@example.com", Password: "AsvsCsrfPass123!"},
			cookie, token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 with CSRF pair, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("token endpoint issuance and reuse", func(t *testing.T) {
		for _, path := range []string{"/auth/csrf", "/api/auth/csrf"} {
			rec := asvsRequest(t, app.Handler, cfg, http.MethodGet, path, "", nil, nil, "", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d", path, rec.Code)
			}
			var body struct {
				CSRFToken string `json:"csrf_token"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.CSRFToken) != 64 {
				t.Fatalf("GET %s: bad token response %q err=%v", path, rec.Body.String(), err)
			}
			var found *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Value == body.CSRFToken {
					found = c
				}
			}
			if found == nil {
				t.Fatalf("GET %s: no CSRF cookie matching JSON token", path)
			}
			if found.MaxAge <= 0 {
				t.Fatalf("GET %s: CSRF cookie MaxAge must be positive, got %d", path, found.MaxAge)
			}
			reuse := httptest.NewRequest(http.MethodGet, path, nil)
			reuse.AddCookie(found)
			reuseRec := httptest.NewRecorder()
			app.Handler.ServeHTTP(reuseRec, reuse)
			var reuseBody struct {
				CSRFToken string `json:"csrf_token"`
			}
			if err := json.Unmarshal(reuseRec.Body.Bytes(), &reuseBody); err != nil {
				t.Fatalf("reuse: %v", err)
			}
			if reuseBody.CSRFToken != body.CSRFToken {
				t.Fatal("valid cookie must be reused, not overwritten (multi-tab race)")
			}
		}
	})

	email, pass := "asvs_bearer@example.com", "AsvsBearerPass123!"
	signupSecurityUser(t, app, email, pass)

	t.Run("bearer exempt", func(t *testing.T) {
		rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login", "",
			db.LoginRequest{Email: email, Password: pass}, nil, "", map[string]string{
				"X-Auth-Type": "bearer",
			})
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 bearer-exempt, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("query param never exempt", func(t *testing.T) {
		rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login?type=bearer", "",
			db.LoginRequest{Email: email, Password: pass}, nil, "", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("ambiguous transport rejected", func(t *testing.T) {
		sid := loginCookieSession(t, app, cfg, email, pass)
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(
			`{"email":"`+email+`","password":"`+pass+`"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(sid)
		req.Header.Set("X-Auth-Type", "bearer")
		rec := httptest.NewRecorder()
		app.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 ambiguous transport, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "CSRF_TOKEN_INVALID") {
			t.Fatalf("expected CSRF_TOKEN_INVALID, got %s", rec.Body.String())
		}
	})

	t.Run("logout clears csrf cookie", func(t *testing.T) {
		sid := loginCookieSession(t, app, cfg, email, pass)
		cookie, token := csrfPairForLogin(t, app)
		req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
		req.AddCookie(sid)
		attachCSRF(req, cfg, cookie, token)
		rec := httptest.NewRecorder()
		app.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("logout: expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		cleared := false
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.CSRFCookieName && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("logout must clear the CSRF cookie")
		}
	})
}

// V2.2/V2.3: exact threshold boundary (N ok, N+1 429 with Retry-After) plus
// IP/account dimension isolation.
func TestASVS_RateLimit_ThresholdAndIsolation(t *testing.T) {
	t.Run("signup ip threshold", func(t *testing.T) {
		app, _, cfg := setupSecurityApp(t, func(c *config.Config) {
			c.RateLimitSignupMax = 100
			c.RateLimitSignupIPMax = 3
		})
		cookie, token := csrfPairForLogin(t, app)
		for i := 0; i < 3; i++ {
			rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/signup", "10.9.0.1:1234",
				db.SignupRequest{Email: fmt.Sprintf("asvs-signup-%d@example.com", i), Password: "AsvsRatePass123!"},
				cookie, token, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("attempt %d: expected 200, got %d: %s", i+1, rec.Code, rec.Body.String())
			}
		}
		rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/signup", "10.9.0.1:1234",
			db.SignupRequest{Email: "asvs-signup-over@example.com", Password: "AsvsRatePass123!"},
			cookie, token, nil)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Error("expected Retry-After header on 429")
		}
		if !strings.Contains(rec.Body.String(), "RATE_LIMIT_EXCEEDED") {
			t.Fatalf("expected RATE_LIMIT_EXCEEDED, got %s", rec.Body.String())
		}
		requireBaselineHeaders(t, rec.Header(), false)
	})

	t.Run("login account isolation", func(t *testing.T) {
		app, _, cfg := setupSecurityApp(t, func(c *config.Config) {
			c.RateLimitLoginMax = 2
			c.RateLimitLoginIPMax = 100
		})
		cookie, token := csrfPairForLogin(t, app)
		bad := db.LoginRequest{Email: "asvs-acct-a@example.com", Password: "WrongPass000!"}
		for i := 0; i < 2; i++ {
			rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login", "10.9.1.1:1234", bad, cookie, token, nil)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
			}
		}
		// Same account from a fresh IP still trips the account bucket.
		rec := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login", "10.9.1.2:1234", bad, cookie, token, nil)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 account-exhausted, got %d", rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Error("expected Retry-After header on 429")
		}
		// A different account from that IP is unaffected.
		other := db.LoginRequest{Email: "asvs-acct-b@example.com", Password: "WrongPass000!"}
		rec = asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login", "10.9.1.2:1234", other, cookie, token, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("isolated account: expected 401, got %d", rec.Code)
		}
	})

	t.Run("login ip isolation", func(t *testing.T) {
		app, _, cfg := setupSecurityApp(t, func(c *config.Config) {
			c.RateLimitLoginMax = 100
			c.RateLimitLoginIPMax = 2
		})
		cookie, token := csrfPairForLogin(t, app)
		login := func(email, ip string) int {
			return asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login", ip,
				db.LoginRequest{Email: email, Password: "WrongPass000!"}, cookie, token, nil).Code
		}
		if code := login("asvs-ip-c@example.com", "10.9.2.9:1234"); code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", code)
		}
		if code := login("asvs-ip-d@example.com", "10.9.2.9:1234"); code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", code)
		}
		// Same IP with a fresh account trips the IP bucket.
		if code := login("asvs-ip-e@example.com", "10.9.2.9:1234"); code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 ip-exhausted, got %d", code)
		}
		// That account from a fresh IP is unaffected.
		if code := login("asvs-ip-e@example.com", "10.9.2.10:1234"); code != http.StatusUnauthorized {
			t.Fatalf("isolated ip: expected 401, got %d", code)
		}
	})
}

// V2.1 plus timing-parity contract: identical responses for colliding signup,
// unknown reset target, and missing vs wrong-password login (the observable
// invariant preserved by the dummy Argon2id verification in auth.Login).
func TestASVS_AntiEnumeration(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	cookie, token := csrfPairForLogin(t, app)

	email, pass := "asvs_enum@example.com", "AsvsEnumPass123!"
	first := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/signup", "",
		db.SignupRequest{Email: email, Password: pass}, cookie, token, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("signup: expected 200, got %d: %s", first.Code, first.Body.String())
	}
	second := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/signup", "",
		db.SignupRequest{Email: email, Password: pass}, cookie, token, nil)
	if second.Code != http.StatusOK {
		t.Fatalf("colliding signup: expected 200, got %d: %s", second.Code, second.Body.String())
	}
	if first.Body.String() != second.Body.String() {
		t.Fatal("colliding signup must return an identical response body")
	}

	reset := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/password/reset-request", "",
		db.PasswordResetRequest{Email: "asvs-ghost@example.com"}, cookie, token, nil)
	if reset.Code != http.StatusOK {
		t.Fatalf("unknown reset target: expected 200, got %d: %s", reset.Code, reset.Body.String())
	}

	missing := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login", "",
		db.LoginRequest{Email: "asvs-ghost@example.com", Password: pass}, cookie, token, nil)
	wrongPass := asvsRequest(t, app.Handler, cfg, http.MethodPost, "/auth/login", "",
		db.LoginRequest{Email: email, Password: "WrongPass000!"}, cookie, token, nil)
	for name, rec := range map[string]*httptest.ResponseRecorder{"missing": missing, "wrong password": wrongPass} {
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s login: expected 401, got %d", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "INVALID_CREDENTIALS") {
			t.Fatalf("%s login: expected INVALID_CREDENTIALS, got %s", name, rec.Body.String())
		}
	}
}

// V3.2: session cookie flags on cookie-transport login.
func TestASVS_SessionCookieFlags(t *testing.T) {
	app, _, cfg := setupSecurityApp(t)
	email, pass := "asvs_cookie@example.com", "AsvsCookiePass123!"
	signupSecurityUser(t, app, email, pass)
	sid := loginCookieSession(t, app, cfg, email, pass)
	if !sid.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if !sid.Secure {
		t.Error("session cookie must be Secure")
	}
	if sid.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite: got %v, want Lax", sid.SameSite)
	}
	if sid.Path != "/" {
		t.Errorf("session cookie Path: got %q, want \"/\"", sid.Path)
	}
}

// V7.1: focused zero-leak and positive-emission assertions on the core loop.
// Full-lifecycle coverage lives in TestSecurityAuditLogZeroLeak.
func TestASVS_AuditLog_NoLeakAndEmits(t *testing.T) {
	sink := &logSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(sink, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	app, database, cfg := setupSecurityApp(t)
	email, pass := "asvs_audit@example.com", "AsvsAuditPass123!"
	cookie, token := csrfPairForLogin(t, app)

	if rec := postAuditJSON(t, app.Handler, cfg, "/auth/signup",
		db.SignupRequest{Email: email, Password: pass}, cookie, token, nil); rec.Code != http.StatusOK {
		t.Fatalf("signup: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := postAuditJSON(t, app.Handler, cfg, "/auth/login",
		db.LoginRequest{Email: email, Password: "WrongPass000!"}, cookie, token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: expected 401, got %d", rec.Code)
	}
	rec := postAuditJSON(t, app.Handler, cfg, "/auth/login",
		db.LoginRequest{Email: email, Password: pass}, cookie, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("good login: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.SessionCookieName {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie in login response")
	}
	raw := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(`{}`)))
	raw.Header.Set("Content-Type", "application/json")
	rawRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rawRec, raw)
	if rawRec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF pair: expected 403, got %d", rawRec.Code)
	}

	var user db.User
	if err := database.Where("LOWER(email) = LOWER(?)", email).First(&user).Error; err != nil {
		t.Fatalf("query user: %v", err)
	}
	logs := sink.String()
	for name, secret := range map[string]string{
		"raw password":    pass,
		"password hash":   user.PasswordHash,
		"argon2id marker": "$argon2id$",
		"csrf token":      token,
		"raw session id":  sid,
	} {
		if secret != "" && strings.Contains(logs, secret) {
			t.Errorf("log leaked %s", name)
		}
	}
	for _, hdr := range []string{"Authorization", "Cookie", "Set-Cookie"} {
		if strings.Contains(logs, hdr) {
			t.Errorf("log leaked sensitive header %q", hdr)
		}
	}

	requireAuditAttrs(t, logs, "signup_attempt", `"ip":`, `"user_agent":`, `"account":"`+email+`"`)
	requireAuditAttrs(t, logs, "signup_success", `"user_id":`, `"account":"`+email+`"`)
	requireAuditAttrs(t, logs, "login_failure", `"account":`, `"reason":`)
	requireAuditAttrs(t, logs, "login_success", `"user_id":`, `"session_type":`)
	requireAuditAttrs(t, logs, "csrf_violation", `"path":`, `"reason":`)
}
