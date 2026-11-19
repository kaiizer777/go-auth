package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	return issueStateCookieFor(t, cfg, "google")
}

func issueStateCookieFor(t *testing.T, cfg *config.Config, providerID string) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	state, err := SetStateCookie(rec, cfg, providerID, "test-code-verifier", "https://app.example.com/post-login")
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

// clearedStateCookie reports whether rec carries the state deletion cookie.
func clearedStateCookie(rec *httptest.ResponseRecorder, name string) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.MaxAge == -1 {
			return true
		}
	}
	return false
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

	t.Run("form_post provider gets None plus forced Secure", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig() // SessionCookieSecure=false on purpose
		_, cookie := issueStateCookieFor(t, cfg, "apple")
		if cookie.SameSite != http.SameSiteNoneMode {
			t.Errorf("cookie SameSite = %v; want None", cookie.SameSite)
		}
		if !cookie.Secure {
			t.Error("cookie Secure = false; want true (None requires Secure)")
		}
		if !cookie.HttpOnly {
			t.Error("cookie HttpOnly = false; want true")
		}
	})

	t.Run("nil config without secret fails closed", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		// DefaultConfig ships no StateSecret: issuance must refuse rather
		// than sign with a key no other process can reproduce.
		_, err := SetStateCookie(rec, nil, "github", "v", "")
		if !apperrors.Is(err, apperrors.ErrOAuthStateSecretRequired) {
			t.Fatalf("SetStateCookie(nil) = %v; want ErrOAuthStateSecretRequired", err)
		}
	})

	t.Run("token length matches stateTokenLen", func(t *testing.T) {
		t.Parallel()
		if stateTokenLen != 43 {
			t.Fatalf("stateTokenLen = %d; want 43", stateTokenLen)
		}
		cfg := testStateConfig()
		state, _ := issueStateCookie(t, cfg)
		if len(state) != stateTokenLen {
			t.Fatalf("len(state) = %d; want %d", len(state), stateTokenLen)
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
		// Replay with the identical cookie still present fails: single-use is
		// enforced by a server-side consumed-state record, not by the browser
		// deletion alone. The missing-cookie case stays a separate subtest.
		_, err := ValidateState(httptest.NewRecorder(), stateRequest(cookie), cfg, "google", state)
		assertStateInvalid(t, err)
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
		state, cookie := issueStateCookie(t, cfg)
		parts := strings.Split(cookie.Value, ".")
		raw, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		var decoded OAuthStatePayload
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		decoded.CodeVerifier = "tampered-verifier"
		raw, err = json.Marshal(decoded)
		if err != nil {
			t.Fatalf("remarshal payload: %v", err)
		}
		cookie.Value = base64.RawURLEncoding.EncodeToString(raw) + "." + parts[1]
		// Issued token: failure can only come from HMAC verification.
		_, err = ValidateState(httptest.NewRecorder(), stateRequest(cookie), cfg, "google", state)
		assertStateInvalid(t, err)
	})

	t.Run("tampered signature rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		state, cookie := issueStateCookie(t, cfg)
		parts := strings.Split(cookie.Value, ".")
		sig, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		sig[0] ^= 0xFF
		cookie.Value = parts[0] + "." + base64.RawURLEncoding.EncodeToString(sig)
		// Issued token: failure can only come from HMAC verification.
		_, err = ValidateState(httptest.NewRecorder(), stateRequest(cookie), cfg, "google", state)
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

	t.Run("stale callback preserves newer login cookie", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		_, _ = issueStateCookie(t, cfg)                 // tab 1 login, superseded below
		newState, newCookie := issueStateCookie(t, cfg) // tab 2 overwrites same-name cookie
		rec := httptest.NewRecorder()
		_, err := ValidateState(rec, stateRequest(newCookie), cfg, "google", "stale-tab-1-state")
		assertStateInvalid(t, err)
		if clearedStateCookie(rec, cfg.OAuth.StateCookieName) {
			t.Error("stale callback cleared the newer login cookie")
		}
		// Newer login still completes afterwards.
		if _, err := ValidateState(httptest.NewRecorder(), stateRequest(newCookie), cfg, "google", newState); err != nil {
			t.Fatalf("newer login ValidateState = %v", err)
		}
	})

	t.Run("oversized state param rejected", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		_, cookie := issueStateCookie(t, cfg)
		rec := httptest.NewRecorder()
		_, err := ValidateState(rec, stateRequest(cookie), cfg, "google", strings.Repeat("a", 1<<20))
		assertStateInvalid(t, err)
		if clearedStateCookie(rec, cfg.OAuth.StateCookieName) {
			t.Error("oversized state param cleared the state cookie; want preserved")
		}
	})

	t.Run("clear scoped to owning callback", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		key, err := stateSigningKey(cfg.OAuth.StateSecret)
		if err != nil {
			t.Fatalf("stateSigningKey = %v", err)
		}
		mustSign := func(p OAuthStatePayload) string {
			s, err := signStatePayload(p, key)
			if err != nil {
				t.Fatalf("signStatePayload = %v", err)
			}
			return s
		}
		fresh := func(token, provider string, exp time.Time) *http.Cookie {
			return &http.Cookie{Name: cfg.OAuth.StateCookieName,
				Value: mustSign(OAuthStatePayload{Token: token, ProviderID: provider, ExpiresAt: exp})}
		}
		future := time.Now().Add(time.Hour)
		for _, tc := range []struct {
			name     string
			cookie   *http.Cookie
			provider string
			param    string
			cleared  bool
		}{
			{"tampered signature swept", &http.Cookie{Name: cfg.OAuth.StateCookieName, Value: "bad.payload"}, "google", "whatever", true},
			{"expired owned payload swept", fresh("tok", "google", time.Now().Add(-time.Minute)), "google", "tok", true},
			{"mismatched token preserved", fresh("tok", "google", future), "google", "other", false},
			{"foreign provider preserved", fresh("tok", "google", future), "github", "tok", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				rec := httptest.NewRecorder()
				_, err := ValidateState(rec, stateRequest(tc.cookie), cfg, tc.provider, tc.param)
				assertStateInvalid(t, err)
				if got := clearedStateCookie(rec, cfg.OAuth.StateCookieName); got != tc.cleared {
					t.Errorf("cleared = %v; want %v", got, tc.cleared)
				}
			})
		}
	})
}

func TestClearStateCookie(t *testing.T) {
	t.Run("deletion matches issued policy per provider", func(t *testing.T) {
		t.Parallel()
		cfg := testStateConfig()
		for _, tc := range []struct {
			provider string
			sameSite http.SameSite
			secure   bool
		}{
			{"google", http.SameSiteLaxMode, false},
			{"apple", http.SameSiteNoneMode, true},
		} {
			rec := httptest.NewRecorder()
			ClearStateCookie(rec, cfg, tc.provider)
			var found *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == cfg.OAuth.StateCookieName {
					found = c
				}
			}
			if found == nil {
				t.Fatalf("%s: no %q cookie cleared", tc.provider, cfg.OAuth.StateCookieName)
			}
			if found.MaxAge != -1 {
				t.Errorf("%s: MaxAge = %d; want -1", tc.provider, found.MaxAge)
			}
			if !found.HttpOnly {
				t.Errorf("%s: HttpOnly = false; want true", tc.provider)
			}
			if found.SameSite != tc.sameSite {
				t.Errorf("%s: SameSite = %v; want %v", tc.provider, found.SameSite, tc.sameSite)
			}
			if found.Secure != tc.secure {
				t.Errorf("%s: Secure = %v; want %v", tc.provider, found.Secure, tc.secure)
			}
			if found.Path != cfg.OAuth.StateCookiePath {
				t.Errorf("%s: Path = %q; want %q", tc.provider, found.Path, cfg.OAuth.StateCookiePath)
			}
		}
	})
}

func TestConsumeStateTokenSweep(t *testing.T) {
	// Direct map access needs the package lock, so no t.Parallel here.
	resetSeen := func() {
		consumedStates.Lock()
		consumedStates.seen = map[string]time.Time{}
		consumedStates.Unlock()
	}
	resetSeen()
	t.Cleanup(resetSeen)

	t.Run("expired entry below threshold is not a replay", func(t *testing.T) {
		resetSeen()
		consumedStates.Lock()
		consumedStates.seen["stale-token"] = time.Now().Add(-time.Minute)
		size := len(consumedStates.seen)
		consumedStates.Unlock()
		if size >= consumedStateSweepThreshold {
			t.Fatalf("len(seen) = %d; want below the %d threshold", size, consumedStateSweepThreshold)
		}
		if !consumeStateToken("stale-token", time.Now().Add(time.Hour)) {
			t.Fatal("expired entry treated as a replay")
		}
	})

	t.Run("sweep fires at the threshold", func(t *testing.T) {
		resetSeen()
		past := time.Now().Add(-time.Minute)
		consumedStates.Lock()
		for i := 0; i < consumedStateSweepThreshold; i++ {
			consumedStates.seen[fmt.Sprintf("stale-%d", i)] = past
		}
		consumedStates.Unlock()
		if !consumeStateToken("fresh-token", time.Now().Add(time.Hour)) {
			t.Fatal("fresh token rejected")
		}
		consumedStates.Lock()
		defer consumedStates.Unlock()
		if len(consumedStates.seen) != 1 {
			t.Fatalf("len(seen) = %d; want 1 (stale swept, fresh kept)", len(consumedStates.seen))
		}
		if _, ok := consumedStates.seen["fresh-token"]; !ok {
			t.Fatal("fresh token missing after sweep")
		}
	})

	t.Run("replay within TTL rejected", func(t *testing.T) {
		resetSeen()
		exp := time.Now().Add(time.Hour)
		if !consumeStateToken("replay-token", exp) {
			t.Fatal("first consume rejected")
		}
		if consumeStateToken("replay-token", exp) {
			t.Fatal("replay within TTL accepted")
		}
	})
}
