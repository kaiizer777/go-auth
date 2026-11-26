package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

func TestXProvider_AuthCodeURL(t *testing.T) {
	t.Parallel()

	cfg := config.XConfig{
		ClientID:     "x-test-client-id",
		ClientSecret: "x-test-client-secret",
		RedirectURI:  "https://myapp.com/callback",
		Scopes:       []string{"tweet.read", "users.read", "offline.access"},
	}

	p := NewXProvider(cfg)

	if p.ID() != "x" {
		t.Fatalf("ID() = %q; want %q", p.ID(), "x")
	}

	rawURL := p.AuthCodeURL("test-state-nonce", "test-code-challenge", AuthCodeOption{Key: "code_challenge_method", Value: "S256"})
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse AuthCodeURL: %v", err)
	}

	if parsed.Scheme != "https" || parsed.Host != "twitter.com" || parsed.Path != "/i/oauth2/authorize" {
		t.Fatalf("unexpected endpoint: %s", parsed.String())
	}

	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q; want code", q.Get("response_type"))
	}
	if q.Get("client_id") != "x-test-client-id" {
		t.Errorf("client_id = %q; want x-test-client-id", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://myapp.com/callback" {
		t.Errorf("redirect_uri = %q; want https://myapp.com/callback", q.Get("redirect_uri"))
	}
	if q.Get("scope") != "tweet.read users.read offline.access" {
		t.Errorf("scope = %q; want 'tweet.read users.read offline.access'", q.Get("scope"))
	}
	if q.Get("state") != "test-state-nonce" {
		t.Errorf("state = %q; want test-state-nonce", q.Get("state"))
	}
	if q.Get("code_challenge") != "test-code-challenge" {
		t.Errorf("code_challenge = %q; want test-code-challenge", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q; want S256", q.Get("code_challenge_method"))
	}

	// Test default scope injection when empty in cfg
	emptyScopeProvider := NewXProvider(config.XConfig{
		ClientID:     "id",
		ClientSecret: "sec",
		RedirectURI:  "https://myapp.com/cb",
	})
	u2, _ := url.Parse(emptyScopeProvider.AuthURL("st", "ch"))
	if u2.Query().Get("scope") != "users.read" {
		t.Errorf("default scope = %q; want 'users.read'", u2.Query().Get("scope"))
	}
}

// xRetryAfterFor asserts code maps to a *RateLimitError carrying a usable retry hint and returns it.
func xRetryAfterFor(t *testing.T, p *XProvider, code string) int {
	t.Helper()
	_, err := p.ExchangeCode(context.Background(), code, "test-code-verifier")
	if err == nil {
		t.Fatalf("ExchangeCode(%q) error = nil; want rate limit", code)
	}
	if !errors.Is(err, errors.ErrOAuthRateLimitExceeded) {
		t.Fatalf("ExchangeCode(%q) error = %v; want ErrOAuthRateLimitExceeded", code, err)
	}
	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("ExchangeCode(%q) error type = %T; want *RateLimitError", code, err)
	}
	retryAfter, ok := RetryAfterFromError(err)
	if !ok {
		t.Fatalf("ExchangeCode(%q) retry hint missing in %v", code, err)
	}
	if retryAfter != rle.RetryAfter {
		t.Fatalf("RetryAfterFromError = %d; RateLimitError.RetryAfter = %d", retryAfter, rle.RetryAfter)
	}
	return retryAfter
}

// xRetryAfterMissing asserts code maps to a *RateLimitError without a usable retry hint.
func xRetryAfterMissing(t *testing.T, p *XProvider, code string) {
	t.Helper()
	_, err := p.ExchangeCode(context.Background(), code, "test-code-verifier")
	if err == nil || !errors.Is(err, errors.ErrOAuthRateLimitExceeded) {
		t.Fatalf("ExchangeCode(%q) error = %v; want ErrOAuthRateLimitExceeded", code, err)
	}
	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("ExchangeCode(%q) error type = %T; want *RateLimitError", code, err)
	}
	if retryAfter, ok := RetryAfterFromError(err); ok {
		t.Fatalf("ExchangeCode(%q) RetryAfterFromError = (%d, true); want (0, false)", code, retryAfter)
	}
}

// xProviderError asserts err is a provider error and returns it.
func xProviderError(t *testing.T, err error) *errors.Error {
	t.Helper()
	var appErr *errors.Error
	if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
		t.Fatalf("error = %v; want CodeOAuthProviderError", err)
	}
	return appErr
}

func TestXProvider_ExchangeCode(t *testing.T) {
	t.Parallel()

	clientID := "client:id@test"
	clientSecret := "secret:key#123"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		// RFC 6749 §2.3.1 Client Authentication verification
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Basic ") {
			http.Error(w, "missing or invalid basic auth", http.StatusUnauthorized)
			return
		}
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			http.Error(w, "invalid base64 in basic auth", http.StatusBadRequest)
			return
		}
		expectedAuth := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
		if string(decoded) != expectedAuth {
			http.Error(w, "unauthorized credentials mismatch", http.StatusUnauthorized)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		// INVARIANT: client_id MUST NOT be in the body
		if r.Form.Has("client_id") {
			http.Error(w, "client_id forbidden in body per RFC 6749", http.StatusBadRequest)
			return
		}
		if r.Form.Has("client_secret") {
			http.Error(w, "client_secret forbidden in body", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		writeProblem := func(w http.ResponseWriter, status int, body any) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
		}
		if code == "rate-limited-code" {
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(90*time.Second).Unix(), 10))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  "Too Many Requests",
				"detail": "Too Many Requests",
				"type":   "about:blank",
				"status": 429,
			})
			return
		}
		if code == "rate-limited-retry-after-code" {
			w.Header().Set("Retry-After", "45")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  "Too Many Requests",
				"detail": "Too Many Requests",
				"type":   "about:blank",
				"status": 429,
			})
			return
		}
		if code == "rate-limited-past-code" {
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(-60*time.Second).Unix(), 10))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  "Too Many Requests",
				"detail": "Too Many Requests",
				"type":   "about:blank",
				"status": 429,
			})
			return
		}
		if code == "rate-limited-http-date-code" {
			w.Header().Set("Retry-After", time.Now().Add(90*time.Second).UTC().Format(http.TimeFormat))
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(600*time.Second).Unix(), 10))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-http-date-past-code" {
			w.Header().Set("Retry-After", time.Now().Add(-60*time.Second).UTC().Format(http.TimeFormat))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-http-date-far-code" {
			w.Header().Set("Retry-After", time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-garbage-code" {
			w.Header().Set("Retry-After", "soon")
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(75*time.Second).Unix(), 10))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-garbage-no-fallback-code" {
			w.Header().Set("Retry-After", "soon")
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-zero-code" {
			w.Header().Set("Retry-After", "0")
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(600*time.Second).Unix(), 10))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-negative-code" {
			w.Header().Set("Retry-After", "-5")
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(600*time.Second).Unix(), 10))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-negative-no-fallback-code" {
			w.Header().Set("Retry-After", "-5")
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-negative-overflow-code" {
			w.Header().Set("Retry-After", "-99999999999999999999")
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(300*time.Second).Unix(), 10))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-oversized-code" {
			w.Header().Set("Retry-After", "1000000000")
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-overflow-code" {
			w.Header().Set("Retry-After", "99999999999999999999")
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-reset-far-code" {
			w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(1000*time.Hour).Unix(), 10))
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "rate-limited-headerless-code" {
			writeProblem(w, http.StatusTooManyRequests, map[string]any{"status": 429})
			return
		}
		if code == "problem-multiple-errors-code" {
			writeProblem(w, http.StatusBadRequest, map[string]any{
				"type":   "https://api.twitter.com/2/problems/bad-request",
				"title":  "Invalid Request",
				"detail": "top-level detail",
				"status": 400,
				"errors": []map[string]any{
					{
						"type":    "https://api.twitter.com/2/problems/first",
						"title":   "First Title",
						"message": "first message",
						"status":  400,
					},
					{
						"type":   "https://api.twitter.com/2/problems/second",
						"title":  "Second Title",
						"detail": "second detail",
						"status": 400,
					},
				},
			})
			return
		}
		if code == "problem-type-only-code" {
			writeProblem(w, http.StatusBadRequest, map[string]any{
				"type": "https://api.twitter.com/2/problems/type-only",
			})
			return
		}
		if code == "problem-nested-title-code" {
			writeProblem(w, http.StatusBadRequest, map[string]any{
				"errors": []map[string]any{{
					"type":  "https://api.twitter.com/2/problems/nested",
					"title": "Nested Title",
				}},
			})
			return
		}
		if code == "problem-array-body-code" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`[{"detail":"array shaped"}]`))
			return
		}
		if code == "rfc7807-error" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  "Invalid Request",
				"detail": "Value passed for authorization code was invalid",
				"type":   "https://api.twitter.com/2/problems/invalid-request",
				"status": 400,
			})
			return
		}
		if code == "error-body-code" {
			// X sometimes reports a failed exchange as a 200 with an error
			// field. The text must not reach the client-facing message.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "Value passed for authorization code was invalid",
			})
			return
		}
		if code == "nested-error-code" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errors": []map[string]any{{
					"message": "nested upstream diagnostic",
					"status":  400,
				}},
			})
			return
		}
		if code == "server-error" {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if code == "bad-json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{invalid-json"))
			return
		}

		if r.FormValue("grant_type") != "authorization_code" ||
			r.FormValue("redirect_uri") != "https://myapp.com/callback" ||
			r.FormValue("code_verifier") != "test-code-verifier" {
			http.Error(w, "invalid form parameters", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":    "bearer",
			"expires_in":    7200,
			"access_token":  "mock-x-access-token",
			"scope":         "tweet.read users.read offline.access",
			"refresh_token": "mock-x-refresh-token",
		})
	}))
	t.Cleanup(ts.Close)

	p := NewXProvider(config.XConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  "https://myapp.com/callback",
	})
	p.tokenURL = ts.URL

	t.Run("successful exchange with basic auth", func(t *testing.T) {
		tok, err := p.ExchangeCode(context.Background(), "valid-code", "test-code-verifier")
		if err != nil {
			t.Fatalf("unexpected ExchangeCode error: %v", err)
		}
		if tok.AccessToken != "mock-x-access-token" {
			t.Errorf("AccessToken = %q; want mock-x-access-token", tok.AccessToken)
		}
		if tok.RefreshToken != "mock-x-refresh-token" {
			t.Errorf("RefreshToken = %q; want mock-x-refresh-token", tok.RefreshToken)
		}
		if tok.ExpiresIn != 7200 {
			t.Errorf("ExpiresIn = %d; want 7200", tok.ExpiresIn)
		}
	})

	t.Run("429 rate limit error mapped", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "rate-limited-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthRateLimitExceeded) {
			t.Fatalf("expected ErrOAuthRateLimitExceeded, got %v", err)
		}
		retryAfter, ok := RetryAfterFromError(err)
		if !ok {
			t.Fatalf("expected RetryAfter value, got none in %v", err)
		}
		if retryAfter < 85 || retryAfter > 90 {
			t.Fatalf("RetryAfter = %d; want within [85, 90] (90s future reset)", retryAfter)
		}
	})

	t.Run("429 Retry-After header takes precedence", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "rate-limited-retry-after-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthRateLimitExceeded) {
			t.Fatalf("expected ErrOAuthRateLimitExceeded, got %v", err)
		}
		retryAfter, ok := RetryAfterFromError(err)
		if !ok || retryAfter != 45 {
			t.Fatalf("RetryAfter = %d, ok = %v; want 45, true", retryAfter, ok)
		}
	})

	t.Run("429 past reset clamps to one second", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "rate-limited-past-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthRateLimitExceeded) {
			t.Fatalf("expected ErrOAuthRateLimitExceeded, got %v", err)
		}
		retryAfter, ok := RetryAfterFromError(err)
		if !ok || retryAfter != 1 {
			t.Fatalf("RetryAfter = %d, ok = %v; want 1, true", retryAfter, ok)
		}
	})

	t.Run("429 HTTP-date Retry-After wins over reset epoch", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-http-date-code"); got < 88 || got > 90 {
			t.Fatalf("RetryAfter = %d; want ~90 for a 90s future HTTP-date", got)
		}
	})

	t.Run("429 past HTTP-date Retry-After clamps to one second", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-http-date-past-code"); got != 1 {
			t.Fatalf("RetryAfter = %d; want 1", got)
		}
	})

	t.Run("429 far-future HTTP-date Retry-After caps at 24h", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-http-date-far-code"); got != 86400 {
			t.Fatalf("RetryAfter = %d; want 86400", got)
		}
	})

	t.Run("429 garbage Retry-After falls back to reset epoch", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-garbage-code"); got < 73 || got > 75 {
			t.Fatalf("RetryAfter = %d; want ~75 from the reset epoch", got)
		}
	})

	t.Run("429 garbage Retry-After without reset yields no retry hint", func(t *testing.T) {
		xRetryAfterMissing(t, p, "rate-limited-garbage-no-fallback-code")
	})

	t.Run("429 headerless response yields no retry hint", func(t *testing.T) {
		xRetryAfterMissing(t, p, "rate-limited-headerless-code")
	})

	t.Run("429 zero Retry-After clamps to one second", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-zero-code"); got != 1 {
			t.Fatalf("RetryAfter = %d; want 1", got)
		}
	})

	t.Run("429 negative Retry-After falls back to reset epoch", func(t *testing.T) {
		// RFC 9110 delay-seconds = 1*DIGIT: a negative value is invalid input and
		// must not outrank the valid 600s reset epoch.
		if got := xRetryAfterFor(t, p, "rate-limited-negative-code"); got < 598 || got > 600 {
			t.Fatalf("RetryAfter = %d; want ~600 from the reset epoch", got)
		}
	})

	t.Run("429 negative Retry-After without reset yields no retry hint", func(t *testing.T) {
		xRetryAfterMissing(t, p, "rate-limited-negative-no-fallback-code")
	})

	t.Run("429 negative Retry-After beyond int64 falls back to reset epoch", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-negative-overflow-code"); got < 298 || got > 300 {
			t.Fatalf("RetryAfter = %d; want ~300 from the reset epoch", got)
		}
	})

	t.Run("429 oversized Retry-After caps at 24h", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-oversized-code"); got != 86400 {
			t.Fatalf("RetryAfter = %d; want 86400", got)
		}
	})

	t.Run("429 Retry-After beyond int64 caps at 24h", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-overflow-code"); got != 86400 {
			t.Fatalf("RetryAfter = %d; want 86400", got)
		}
	})

	t.Run("429 far-future reset epoch caps at 24h", func(t *testing.T) {
		if got := xRetryAfterFor(t, p, "rate-limited-reset-far-code"); got != 86400 {
			t.Fatalf("RetryAfter = %d; want 86400", got)
		}
	})

	t.Run("problem+json maps every field and error entry", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "problem-multiple-errors-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		appErr := xProviderError(t, err)
		if appErr.Message() != "oauth provider request failed" {
			t.Fatalf("message = %q; want the generic message", appErr.Message())
		}
		for _, want := range []string{
			"upstream type: https://api.twitter.com/2/problems/bad-request",
			"upstream title: Invalid Request",
			"upstream detail: top-level detail",
			"upstream error type: https://api.twitter.com/2/problems/first",
			"upstream error title: First Title",
			"upstream error message: first message",
			"upstream error type: https://api.twitter.com/2/problems/second",
			"upstream error title: Second Title",
			"upstream error detail: second detail",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("cause missing %q in %v", want, err)
			}
		}
		for _, leak := range []string{"top-level detail", "first message", "second detail", "problems/bad-request"} {
			if strings.Contains(appErr.Message(), leak) {
				t.Errorf("upstream text %q reflected in wire message %q", leak, appErr.Message())
			}
		}
	})

	t.Run("problem+json type-only body maps the type", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "problem-type-only-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		appErr := xProviderError(t, err)
		if appErr.Message() != "oauth provider request failed" {
			t.Fatalf("message = %q; want the generic message", appErr.Message())
		}
		if want := "upstream type: https://api.twitter.com/2/problems/type-only"; !strings.Contains(err.Error(), want) {
			t.Errorf("cause missing %q in %v", want, err)
		}
	})

	t.Run("problem+json nested title and type preserved", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "problem-nested-title-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		appErr := xProviderError(t, err)
		if appErr.Message() != "oauth provider request failed" {
			t.Fatalf("message = %q; want the generic message", appErr.Message())
		}
		for _, want := range []string{
			"upstream error type: https://api.twitter.com/2/problems/nested",
			"upstream error title: Nested Title",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("cause missing %q in %v", want, err)
			}
		}
	})

	t.Run("problem+json non-object body degrades to status message", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "problem-array-body-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		appErr := xProviderError(t, err)
		if want := "oauth provider responded with status 400"; appErr.Message() != want {
			t.Fatalf("message = %q; want %q", appErr.Message(), want)
		}
		if strings.Contains(err.Error(), "array shaped") {
			t.Errorf("unparsed body leaked into the cause: %v", err)
		}
	})

	t.Run("200 problem-shaped body maps fields without leaking", func(t *testing.T) {
		body := []byte(`{"type":"https://api.twitter.com/2/problems/invalid-request","title":"Invalid Request","detail":"code already used","status":400}`)
		appErr := xProviderError(t, parseXErrorWithHeader(http.StatusOK, body, nil))
		if appErr.Message() != "oauth provider request failed" {
			t.Fatalf("message = %q; want the generic message", appErr.Message())
		}
		for _, want := range []string{"upstream detail: code already used", "upstream type: https://api.twitter.com/2/problems/invalid-request"} {
			if !strings.Contains(appErr.Error(), want) {
				t.Errorf("cause missing %q in %v", want, appErr)
			}
		}
	})

	t.Run("RFC 7807 error parsed", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "rfc7807-error", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got %v", err)
		}
		if appErr.Message() != "oauth provider request failed" {
			t.Fatalf("expected generic wire message, got %q", appErr.Message())
		}
		if strings.Contains(appErr.Message(), "Value passed for authorization code was invalid") {
			t.Fatalf("upstream detail reflected in wire message: %q", appErr.Message())
		}
		if !strings.Contains(err.Error(), "Value passed for authorization code was invalid") {
			t.Fatalf("expected upstream detail preserved in cause chain, got %v", err)
		}
	})

	t.Run("200 error field keeps provider text out of the message", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "error-body-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got %v", err)
		}
		if appErr.Message() != "oauth token exchange failed" {
			t.Fatalf("message = %q; want the generic message", appErr.Message())
		}
		if !strings.Contains(err.Error(), "Value passed for authorization code was invalid") {
			t.Fatalf("expected the provider text preserved in the cause chain, got %v", err)
		}
	})

	t.Run("nested error array keeps provider text out of the message", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "nested-error-code", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got %v", err)
		}
		if appErr.Message() != "oauth provider request failed" {
			t.Fatalf("message = %q; want the generic message", appErr.Message())
		}
		if !strings.Contains(err.Error(), "nested upstream diagnostic") {
			t.Fatalf("expected the nested diagnostic in the cause chain, got %v", err)
		}
	})

	t.Run("server 500 error mapped", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "server-error", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got %v", err)
		}
	})

	t.Run("malformed json response handled", func(t *testing.T) {
		_, err := p.ExchangeCode(context.Background(), "bad-json", "test-code-verifier")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got %v", err)
		}
	})
}

func TestXProvider_FetchUserInfo(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer valid-token" && authHeader != "Bearer username-fallback-token" {
			if authHeader == "Bearer rate-limited-token" {
				w.Header().Set("x-rate-limit-reset", strconv.FormatInt(time.Now().Add(120*time.Second).Unix(), 10))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"title":  "Too Many Requests",
					"detail": "Too Many Requests",
					"status": 429,
				})
				return
			}
			if authHeader == "Bearer missing-id-token" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"name":     "No ID User",
						"username": "noid",
					},
				})
				return
			}
			if authHeader == "Bearer server-error-token" {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.URL.Query().Get("user.fields") != "id,name,username,profile_image_url,verified" {
			http.Error(w, "missing expected user.fields query", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if authHeader == "Bearer username-fallback-token" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":                "987654321",
					"name":              "",
					"username":          "twitterdev",
					"profile_image_url": "https://pbs.twimg.com/avatar_dev.jpg",
					"verified":          true,
				},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":                "2244994945",
				"name":              "Twitter Dev",
				"username":          "TwitterDev",
				"profile_image_url": "https://pbs.twimg.com/avatar.jpg",
				"verified":          true,
			},
		})
	}))
	t.Cleanup(ts.Close)

	p := NewXProvider(config.XConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://myapp.com/callback",
	})
	p.userInfoURL = ts.URL

	t.Run("missing access token rejected", func(t *testing.T) {
		_, err := p.FetchUserInfo(context.Background(), nil)
		if err == nil {
			t.Fatal("expected error for nil token, got nil")
		}
		_, err = p.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: ""})
		if err == nil {
			t.Fatal("expected error for empty token, got nil")
		}
	})

	t.Run("successful profile fetch and missing email invariants", func(t *testing.T) {
		user, err := p.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "valid-token"})
		if err != nil {
			t.Fatalf("unexpected FetchUserInfo error: %v", err)
		}
		if user.ProviderID != "x" {
			t.Errorf("ProviderID = %q; want x", user.ProviderID)
		}
		if user.ProviderUserID != "2244994945" {
			t.Errorf("ProviderUserID = %q; want 2244994945", user.ProviderUserID)
		}
		if user.Name != "Twitter Dev" {
			t.Errorf("Name = %q; want Twitter Dev", user.Name)
		}
		if user.AvatarURL != "https://pbs.twimg.com/avatar.jpg" {
			t.Errorf("AvatarURL = %q; want https://pbs.twimg.com/avatar.jpg", user.AvatarURL)
		}
		// INVARIANTS: Email = "" and EmailVerified = false
		if user.Email != "" {
			t.Errorf("Email = %q; want empty string", user.Email)
		}
		if user.EmailVerified {
			t.Errorf("EmailVerified = true; want false")
		}
	})

	t.Run("username fallback when name is empty", func(t *testing.T) {
		user, err := p.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "username-fallback-token"})
		if err != nil {
			t.Fatalf("unexpected FetchUserInfo error: %v", err)
		}
		if user.Name != "twitterdev" {
			t.Errorf("Name = %q; want twitterdev (username fallback)", user.Name)
		}
	})

	t.Run("missing id error", func(t *testing.T) {
		_, err := p.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "missing-id-token"})
		if err == nil {
			t.Fatal("expected error for missing id, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got %v", err)
		}
	})

	t.Run("429 rate limit error mapped", func(t *testing.T) {
		_, err := p.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "rate-limited-token"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, errors.ErrOAuthRateLimitExceeded) {
			t.Fatalf("expected ErrOAuthRateLimitExceeded, got %v", err)
		}
		retryAfter, ok := RetryAfterFromError(err)
		if !ok {
			t.Fatalf("expected RetryAfter value, got none in %v", err)
		}
		if retryAfter < 115 || retryAfter > 120 {
			t.Fatalf("RetryAfter = %d; want within [115, 120] (120s future reset)", retryAfter)
		}
	})

	t.Run("server error mapped", func(t *testing.T) {
		_, err := p.FetchUserInfo(context.Background(), &OAuthToken{AccessToken: "server-error-token"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var appErr *errors.Error
		if !errors.As(err, &appErr) || appErr.Code() != errors.CodeOAuthProviderError {
			t.Fatalf("expected CodeOAuthProviderError, got %v", err)
		}
	})
}
