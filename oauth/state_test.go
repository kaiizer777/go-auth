package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
	apperrors "github.com/kaiizer777/go-auth/errors"
)

func testStateConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionCookieSecure = false
	cfg.OAuth.StateSecret = "test-state-secret-at-least-32-bytes!"
	return &cfg
}

func issueStateCookie(t *testing.T, cfg *config.Config) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	state, err := SetStateCookie(rec, cfg, "google", "test-code-verifier", "https://app.example.com/post-login")
	if err != nil {
		t.Fatalf("SetStateCookie = %v", err)
	}
	if state == "" {
		t.Fatal("SetStateCookie returned empty state")
	}
	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.OAuth.StateCookieName {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("no %q cookie issued", cfg.OAuth.StateCookieName)
	}
	return state, found
}

func stateRequest(cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://example.com/auth/oauth/google/callback", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func assertStateInvalid(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected OAUTH_STATE_INVALID; got nil")
	}
	var appErr *apperrors.Error
	if !apperrors.As(err, &appErr) {
		t.Fatalf("error is not a domain error: %v", err)
	}
	if appErr.Code() != apperrors.CodeOAuthStateInvalid {
		t.Errorf("code = %q; want %q", appErr.Code(), apperrors.CodeOAuthStateInvalid)
	}
	if appErr.HTTPStatus() != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d; want 403", appErr.HTTPStatus())
	}
}

func TestSetStateCookie(t *testing.T) {
	t.Run("issues HttpOnly Lax cookie with TTL", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		_, cookie := issueStateCookie(t, cfg)
		if !cookie.HttpOnly {
			t.Error("cookie HttpOnly = false; want true")
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie SameSite = %v; want Lax", cookie.SameSite)
		}
		if cookie.Path != "/" {
			t.Errorf("cookie Path = %q; want /", cookie.Path)
		}
		if want := int(cfg.OAuth.StateTTL.Seconds()); cookie.MaxAge != want {
			t.Errorf("cookie MaxAge = %d; want %d", cookie.MaxAge, want)
		}
		if parts := strings.Split(cookie.Value, "."); len(parts) != 2 {
			t.Errorf("cookie value is not payload.signature: %q", cookie.Value)
		}
	})

	t.Run("state value unique per issuance", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		rec := httptest.NewRecorder()
		a, err := SetStateCookie(rec, cfg, "google", "v", "")
		if err != nil {
			t.Fatalf("SetStateCookie = %v", err)
		}
		b, err := SetStateCookie(rec, cfg, "google", "v", "")
		if err != nil {
			t.Fatalf("SetStateCookie = %v", err)
		}
		if a == b {
			t.Error("duplicate state values across issuances")
		}
	})

	t.Run("nil config uses defaults without panic", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		state, err := SetStateCookie(rec, nil, "github", "v", "")
		if err != nil {
			t.Fatalf("SetStateCookie(nil) = %v", err)
		}
		if state == "" {
			t.Error("empty state with nil config")
		}
		found := false
		for _, c := range rec.Result().Cookies() {
			if c.Name == "oauth_state" {
				found = true
			}
		}
		if !found {
			t.Error("default oauth_state cookie not issued for nil config")
		}
	})
}

func TestValidateState(t *testing.T) {
	t.Run("round-trip preserves payload", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		state, cookie := issueStateCookie(t, cfg)
		rec := httptest.NewRecorder()
		payload, err := ValidateState(rec, stateRequest(cookie), cfg, "google", state)
		if err != nil {
			t.Fatalf("ValidateState = %v", err)
		}
		if payload.ProviderID != "google" {
			t.Errorf("provider = %q; want google", payload.ProviderID)
		}
		if payload.CodeVerifier != "test-code-verifier" {
			t.Errorf("verifier = %q; want test-code-verifier", payload.CodeVerifier)
		}
		if payload.RedirectURL != "https://app.example.com/post-login" {
			t.Errorf("redirect = %q", payload.RedirectURL)
		}
	})

	t.Run("single-use clears cookie on success", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		state, cookie := issueStateCookie(t, cfg)
		rec := httptest.NewRecorder()
		if _, err := ValidateState(rec, stateRequest(cookie), cfg, "google", state); err != nil {
			t.Fatalf("ValidateState = %v", err)
		}
		cleared := false
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName && c.MaxAge == -1 {
				cleared = true
			}
		}
		if !cleared {
			t.Error("success did not clear state cookie with MaxAge=-1")
		}
		// Replay without cookie fails.
		assertStateInvalid(t, func() error {
			_, err := ValidateState(httptest.NewRecorder(), stateRequest(nil), cfg, "google", state)
			return err
		}())
	})

	t.Run("missing cookie rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		_, err := ValidateState(httptest.NewRecorder(), stateRequest(nil), cfg, "google", "anything")
		assertStateInvalid(t, err)
	})

	t.Run("mismatched state param rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		for _, param := range []string{"AAAA-wrong-state", "", "abc"} {
			_, cookie := issueStateCookie(t, cfg)
			_, err := ValidateState(httptest.NewRecorder(), stateRequest(cookie), cfg, "google", param)
			assertStateInvalid(t, err)
		}
	})

	t.Run("provider mismatch rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		state, cookie := issueStateCookie(t, cfg)
		_, err := ValidateState(httptest.NewRecorder(), stateRequest(cookie), cfg, "github", state)
		assertStateInvalid(t, err)
	})

	t.Run("tampered payload rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		_, cookie := issueStateCookie(t, cfg)
		parts := strings.Split(cookie.Value, ".")
		tampered := "A" + parts[0][1:] + "." + parts[1]
		cookie.Value = tampered
		_, err := ValidateState(httptest.NewRecorder(), stateRequest(cookie), cfg, "google", "whatever")
		assertStateInvalid(t, err)
	})

	t.Run("tampered signature rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		_, cookie := issueStateCookie(t, cfg)
		parts := strings.Split(cookie.Value, ".")
		tampered := parts[0] + "." + "A" + parts[1][1:]
		cookie.Value = tampered
		_, err := ValidateState(httptest.NewRecorder(), stateRequest(cookie), cfg, "google", "whatever")
		assertStateInvalid(t, err)
	})

	t.Run("wrong HMAC secret rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		state, cookie := issueStateCookie(t, cfg)
		other := testStateConfig()
		other.OAuth.StateSecret = "a-different-secret-at-least-32-bytes"
		_, err := ValidateState(httptest.NewRecorder(), stateRequest(cookie), other, "google", state)
		assertStateInvalid(t, err)
	})

	t.Run("expired payload rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		key, err := stateSigningKey(cfg.OAuth.StateSecret)
		if err != nil {
			t.Fatalf("stateSigningKey = %v", err)
		}
		signed, err := signStatePayload(OAuthStatePayload{
			Token:        "expired-token",
			ProviderID:   "google",
			CodeVerifier: "v",
			ExpiresAt:    time.Now().Add(-time.Minute),
		}, key)
		if err != nil {
			t.Fatalf("signStatePayload = %v", err)
		}
		r := stateRequest(&http.Cookie{Name: cfg.OAuth.StateCookieName, Value: signed})
		_, err = ValidateState(httptest.NewRecorder(), r, cfg, "google", "expired-token")
		assertStateInvalid(t, err)
	})

	t.Run("failure still clears cookie", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		_, cookie := issueStateCookie(t, cfg)
		rec := httptest.NewRecorder()
		_, _ = ValidateState(rec, stateRequest(cookie), cfg, "google", "wrong-param")
		cleared := false
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName && c.MaxAge == -1 {
				cleared = true
			}
		}
		if !cleared {
			t.Error("failed validation did not clear state cookie")
		}
	})
}

func TestClearStateCookie(t *testing.T) {
	t.Run("emits deletion cookie", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		rec := httptest.NewRecorder()
		ClearStateCookie(rec, cfg)
		var found *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == cfg.OAuth.StateCookieName {
				found = c
			}
		}
		if found == nil {
			t.Fatalf("no %q cookie cleared", cfg.OAuth.StateCookieName)
		}
		if found.MaxAge != -1 {
			t.Errorf("MaxAge = %d; want -1", found.MaxAge)
		}
		if !found.HttpOnly {
			t.Error("HttpOnly = false; want true")
		}
		if found.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v; want Lax", found.SameSite)
		}
		if found.Path != cfg.OAuth.StateCookiePath {
			t.Errorf("Path = %q; want %q", found.Path, cfg.OAuth.StateCookiePath)
		}
	})
}
