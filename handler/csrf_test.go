package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

// csrfPair fetches a valid CSRF cookie+token via GET /auth/csrf.
func csrfPair(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/csrf", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/csrf: expected 200, got %d", rec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode csrf token: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Value == body.CSRFToken {
			return c, body.CSRFToken
		}
	}
	t.Fatal("no CSRF cookie matching JSON token")
	return nil, ""
}

func decodeErrCode(t *testing.T, rec *httptest.ResponseRecorder) errors.Code {
	t.Helper()
	var resp errors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return resp.Code
}

func TestGetCSRFToken_IssuesMatchingPair(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	cookie, token := csrfPair(t, h)

	if len(token) != 64 {
		t.Fatalf("expected 64-char token, got %d", len(token))
	}
	if cookie.HttpOnly {
		t.Error("CSRF cookie must be readable by JS (HttpOnly=false)")
	}
	if cookie.Path != "/" {
		t.Errorf("expected Path /, got %q", cookie.Path)
	}
	if cookie.MaxAge <= 0 {
		t.Errorf("expected positive MaxAge, got %d", cookie.MaxAge)
	}
	if cookie.Expires.IsZero() {
		t.Error("expected Expires to be set")
	}
}

func TestGetCSRFToken_AliasMatches(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/csrf", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	matched := false
	for _, c := range rec.Result().Cookies() {
		if c.Value == body.CSRFToken {
			matched = true
		}
	}
	if !matched || len(body.CSRFToken) != 64 {
		t.Fatal("alias did not issue matching 64-char pair")
	}
}

func TestGetCSRFToken_ReusesValidCookie(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	cookie, token := csrfPair(t, h)

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.CSRFToken != token {
		t.Fatal("valid cookie was overwritten instead of reused")
	}
}

func TestGetCSRFToken_InvalidCookieIssuesFresh(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "not-a-valid-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.CSRFToken) != 64 || body.CSRFToken == "not-a-valid-token" {
		t.Fatalf("expected fresh 64-char token, got %q", body.CSRFToken)
	}
}

func TestStateChangingRoutes_RejectMissingCSRF(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	routes := []string{
		"/auth/signup", "/auth/login", "/auth/verify",
		"/auth/password/reset-request", "/auth/password/reset",
		"/api/auth/signup", "/api/auth/login", "/api/auth/verify-email",
		"/api/auth/request-password-reset", "/api/auth/reset-password",
	}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, route, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
			if code := decodeErrCode(t, rec); code != errors.CodeCSRFTokenMissing {
				t.Fatalf("expected CSRF_TOKEN_MISSING, got %s", code)
			}
		})
	}
}

func TestStateChangingRoutes_RejectMismatch(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	for _, route := range []string{"/auth/verify", "/api/auth/verify-email"} {
		t.Run(route, func(t *testing.T) {
			cookie, _ := csrfPair(t, h)
			req := httptest.NewRequest(http.MethodPost, route, nil)
			req.AddCookie(cookie)
			req.Header.Set("X-CSRF-Token", strings.Repeat("0", 64))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
			if code := decodeErrCode(t, rec); code != errors.CodeCSRFTokenInvalid {
				t.Fatalf("expected CSRF_TOKEN_INVALID, got %s", code)
			}
		})
	}
}

func TestLogin_XAuthTypeBearerExempt(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	body, _ := json.Marshal(db.LoginRequest{Email: "nobody@example.com", Password: "ValidPassword123#"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Type", "bearer")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("bearer-declared request must not be CSRF-gated: %s", rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != errors.CodeInvalidCredentials {
		t.Fatalf("expected INVALID_CREDENTIALS (proof CSRF passed), got %d %s", rec.Code, code)
	}
}

func TestLogin_XAuthTypeBearerWithSessionCookieRejected(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	body, _ := json.Marshal(db.LoginRequest{Email: "nobody@example.com", Password: "ValidPassword123#"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Type", "bearer")
	req.AddCookie(&http.Cookie{Name: "sid", Value: "0123456789abcdef0123456789abcdef"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 ambiguous transport, got %d", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != errors.CodeCSRFTokenInvalid {
		t.Fatalf("expected CSRF_TOKEN_INVALID, got %s", code)
	}
}

func TestLogin_QueryTypeBearerNotExempt(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	body, _ := json.Marshal(db.LoginRequest{Email: "nobody@example.com", Password: "ValidPassword123#"})
	req := httptest.NewRequest(http.MethodPost, "/auth/login?type=bearer", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("query param must never exempt CSRF, got %d", rec.Code)
	}
}

func TestCSRF_EdgeCases(t *testing.T) {
	_, _, h, _ := setupTestEnv(t)
	validCookie, validToken := csrfPair(t, h)

	cases := []struct {
		name      string
		cookieVal string
		headerVal string
		wantCode  errors.Code
	}{
		{"empty header", validCookie.Value, "", errors.CodeCSRFTokenMissing},
		{"empty cookie", "", validToken, errors.CodeCSRFTokenMissing},
		{"short cookie and header", strings.Repeat("a", 63), strings.Repeat("a", 63), errors.CodeCSRFTokenInvalid},
		{"non-hex cookie and header", strings.Repeat("z", 64), strings.Repeat("z", 64), errors.CodeCSRFTokenInvalid},
		{"oversized header", validCookie.Value, strings.Repeat("a", 8192), errors.CodeCSRFTokenInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(db.LoginRequest{Email: "nobody@example.com", Password: "ValidPassword123#"})
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: tc.cookieVal})
			req.Header.Set("X-CSRF-Token", tc.headerVal)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
			if code := decodeErrCode(t, rec); code != tc.wantCode {
				t.Fatalf("expected %s, got %s", tc.wantCode, code)
			}
		})
	}
}
