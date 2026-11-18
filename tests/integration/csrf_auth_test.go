package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaiizer777/go-auth/db"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

// fetchCSRFPair returns a valid CSRF cookie+token via GET /auth/csrf.
func fetchCSRFPair(t *testing.T, h http.Handler) (*http.Cookie, string) {
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
	if len(body.CSRFToken) != 64 {
		t.Fatalf("expected 64-char token, got %q", body.CSRFToken)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Value == body.CSRFToken {
			return c, body.CSRFToken
		}
	}
	t.Fatal("no CSRF cookie matching JSON token")
	return nil, ""
}

// postJSON sends a POST with an optional CSRF pair attached.
func postJSON(h http.Handler, path string, payload any, cookie *http.Cookie, token string, setHeader map[string]string) *httptest.ResponseRecorder {
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
		req.Header.Set("X-CSRF-Token", token)
	}
	for k, v := range setHeader {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) apperrors.Code {
	t.Helper()
	var resp apperrors.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return resp.Code
}

func TestCSRFAuth_SignupEnforcedThenSucceeds(t *testing.T) {
	app, _, _ := setupIntegrationApp(t)

	bare := postJSON(app.Handler, "/auth/signup",
		db.SignupRequest{Email: "csrf1@example.com", Password: "SecurePassword123!"}, nil, "", nil)
	if bare.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF, got %d", bare.Code)
	}
	if c := errCode(t, bare); c != apperrors.CodeCSRFTokenMissing {
		t.Fatalf("expected CSRF_TOKEN_MISSING, got %s", c)
	}

	cookie, token := fetchCSRFPair(t, app.Handler)
	ok := postJSON(app.Handler, "/auth/signup",
		db.SignupRequest{Email: "csrf1@example.com", Password: "SecurePassword123!"}, cookie, token, nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("expected 200 with CSRF pair, got %d: %s", ok.Code, ok.Body.String())
	}
}

func TestCSRFAuth_AllRoutesAndAliasesEnforce(t *testing.T) {
	app, _, _ := setupIntegrationApp(t)
	routes := []string{
		"/auth/signup", "/auth/login", "/auth/verify",
		"/auth/password/reset-request", "/auth/password/reset",
		"/api/auth/signup", "/api/auth/login", "/api/auth/verify-email",
		"/api/auth/request-password-reset", "/api/auth/reset-password",
	}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			rec := postJSON(app.Handler, route, nil, nil, "", nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
		})
	}

	// Mismatched pair on canonical + alias.
	cookie, _ := fetchCSRFPair(t, app.Handler)
	for _, route := range []string{"/auth/password/reset-request", "/api/auth/request-password-reset"} {
		t.Run(route+" mismatch", func(t *testing.T) {
			rec := postJSON(app.Handler, route,
				db.PasswordResetRequest{Email: "nobody@example.com"}, cookie, "z", nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
			if c := errCode(t, rec); c != apperrors.CodeCSRFTokenInvalid {
				t.Fatalf("expected CSRF_TOKEN_INVALID, got %s", c)
			}
		})
	}
}

func TestCSRFAuth_LoginBearerExemptAndAmbiguous(t *testing.T) {
	app, _, _ := setupIntegrationApp(t)
	email := "csrfbearer@example.com"
	signupUser(t, app, email, "SecurePassword123!")

	login := db.LoginRequest{Email: email, Password: "SecurePassword123!"}

	exempt := postJSON(app.Handler, "/auth/login", login, nil, "",
		map[string]string{"X-Auth-Type": "bearer"})
	if exempt.Code != http.StatusOK {
		t.Fatalf("expected 200 bearer login without CSRF, got %d: %s", exempt.Code, exempt.Body.String())
	}
	var bearerResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(exempt.Body.Bytes(), &bearerResp); err != nil || len(bearerResp.Token) != 32 {
		t.Fatalf("expected 32-char bearer token, got %q err=%v", bearerResp.Token, err)
	}

	// Rebuild with a session cookie present alongside the bearer declaration.
	var body []byte
	body, _ = json.Marshal(login)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Type", "bearer")
	req.AddCookie(&http.Cookie{Name: "sid", Value: "0123456789abcdef0123456789abcdef"})
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 ambiguous transport, got %d", rec.Code)
	}
	if c := errCode(t, rec); c != apperrors.CodeCSRFTokenInvalid {
		t.Fatalf("expected CSRF_TOKEN_INVALID, got %s", c)
	}
}

func TestCSRFAuth_TokenEndpointReuseAndAlias(t *testing.T) {
	app, _, _ := setupIntegrationApp(t)
	cookie, token := fetchCSRFPair(t, app.Handler)

	// Reuse: same token returned, expiry refreshed.
	req := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler.ServeHTTP(rec, req)
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.CSRFToken != token {
		t.Fatalf("expected reused token %q, got %q err=%v", token, body.CSRFToken, err)
	}

	// Alias issues a valid pair.
	aliasRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(aliasRec, httptest.NewRequest(http.MethodGet, "/api/auth/csrf", nil))
	if aliasRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on alias, got %d", aliasRec.Code)
	}
}

func TestCSRFAuth_VerifyAndResetFlows(t *testing.T) {
	app, _, _ := setupIntegrationApp(t)
	email := "csrfverify@example.com"
	pass := "SecurePassword123!"

	_, verifyToken, err := app.Auth.Signup(context.Background(), db.SignupRequest{Email: email, Password: pass})
	if err != nil {
		t.Fatalf("direct signup failed: %v", err)
	}

	cookie, token := fetchCSRFPair(t, app.Handler)
	verify := postJSON(app.Handler, "/auth/verify",
		db.VerifyEmailRequest{Token: verifyToken}, cookie, token, nil)
	if verify.Code != http.StatusOK {
		t.Fatalf("expected 200 verify, got %d: %s", verify.Code, verify.Body.String())
	}

	resetReq := postJSON(app.Handler, "/auth/password/reset-request",
		db.PasswordResetRequest{Email: email}, cookie, token, nil)
	if resetReq.Code != http.StatusOK {
		t.Fatalf("expected 200 reset-request, got %d: %s", resetReq.Code, resetReq.Body.String())
	}

	resetToken, err := app.Auth.RequestPasswordReset(context.Background(), db.PasswordResetRequest{Email: email})
	if err != nil {
		t.Fatalf("direct reset-request failed: %v", err)
	}
	cookie2, token2 := fetchCSRFPair(t, app.Handler)
	confirm := postJSON(app.Handler, "/auth/password/reset",
		db.PasswordResetConfirmRequest{Token: resetToken, NewPassword: "NewSecurePassword456!"}, cookie2, token2, nil)
	if confirm.Code != http.StatusOK {
		t.Fatalf("expected 200 reset confirm, got %d: %s", confirm.Code, confirm.Body.String())
	}

	// New password works over the CSRF-protected login.
	cookie3, token3 := fetchCSRFPair(t, app.Handler)
	login := postJSON(app.Handler, "/auth/login",
		db.LoginRequest{Email: email, Password: "NewSecurePassword456!"}, cookie3, token3, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("expected 200 login with new password, got %d: %s", login.Code, login.Body.String())
	}
}

func TestCSRFAuth_LogoutClearsCSRFCookie(t *testing.T) {
	app, _, cfg := setupIntegrationApp(t)
	email := "csrflogout@example.com"
	signupUser(t, app, email, "SecurePassword123!")

	cookie, token := fetchCSRFPair(t, app.Handler)
	login := postJSON(app.Handler, "/auth/login",
		db.LoginRequest{Email: email, Password: "SecurePassword123!"}, cookie, token, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("expected 200 login, got %d: %s", login.Code, login.Body.String())
	}
	var sidCookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == cfg.SessionCookieName {
			sidCookie = c
		}
	}
	if sidCookie == nil {
		t.Fatal("no session cookie in login response")
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	delReq.AddCookie(sidCookie)
	delReq.AddCookie(cookie)
	delReq.Header.Set(cfg.CSRFHeaderName, token)
	delRec := httptest.NewRecorder()
	app.Handler.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 logout, got %d: %s", delRec.Code, delRec.Body.String())
	}
	cleared := false
	for _, c := range delRec.Result().Cookies() {
		if c.Name == cfg.CSRFCookieName && c.MaxAge == -1 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected CSRF cookie cleared with MaxAge -1 on logout")
	}
}
