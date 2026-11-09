package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaiizer777/go-auth/config"
)

func TestIsAllowedOrigin(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		allowed []string
		want    bool
	}{
		{
			name:    "empty origin",
			origin:  "",
			allowed: []string{"https://example.com"},
			want:    false,
		},
		{
			name:    "exact match",
			origin:  "https://app.example.com",
			allowed: []string{"https://app.example.com", "https://api.example.com"},
			want:    true,
		},
		{
			name:    "no match",
			origin:  "https://malicious.com",
			allowed: []string{"https://app.example.com"},
			want:    false,
		},
		{
			name:    "wildcard match",
			origin:  "https://any-domain.org",
			allowed: []string{"*"},
			want:    true,
		},
		{
			name:    "empty allowed list",
			origin:  "https://app.example.com",
			allowed: []string{},
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isAllowedOrigin(tc.origin, tc.allowed)
			if got != tc.want {
				t.Fatalf("isAllowedOrigin(%q, %v) = %v; want %v", tc.origin, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestCheckOrigin(t *testing.T) {
	tests := []struct {
		name                 string
		origin               string
		allowed              []string
		wantOrigin           string
		wantAllowCredentials bool
	}{
		{
			name:                 "explicit match allows credentials",
			origin:               "https://app.example.com",
			allowed:              []string{"https://app.example.com"},
			wantOrigin:           "https://app.example.com",
			wantAllowCredentials: true,
		},
		{
			name:                 "wildcard match forbids credentials",
			origin:               "https://sub.example.com",
			allowed:              []string{"*"},
			wantOrigin:           "*",
			wantAllowCredentials: false,
		},
		{
			name:                 "disallowed origin",
			origin:               "https://untrusted.com",
			allowed:              []string{"https://app.example.com"},
			wantOrigin:           "",
			wantAllowCredentials: false,
		},
		{
			name:                 "empty origin",
			origin:               "",
			allowed:              []string{"*"},
			wantOrigin:           "",
			wantAllowCredentials: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOrigin, gotCreds := checkOrigin(tc.origin, tc.allowed)
			if gotOrigin != tc.wantOrigin || gotCreds != tc.wantAllowCredentials {
				t.Fatalf("checkOrigin(%q, %v) = (%q, %v); want (%q, %v)",
					tc.origin, tc.allowed, gotOrigin, gotCreds, tc.wantOrigin, tc.wantAllowCredentials)
			}
		})
	}
}

func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"https://app.example.com"}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CORS(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q; want Origin", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q; want https://app.example.com", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q; want true", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PUT, DELETE, OPTIONS" {
		t.Fatalf("Access-Control-Allow-Methods = %q; unexpected value", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type" {
		t.Fatalf("Access-Control-Allow-Headers = %q; unexpected value", got)
	}
}

func TestCORSMiddleware_DisallowedOrigin(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"https://app.example.com"}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CORS(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://untrusted.com")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q; want Origin", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q; want empty", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q; want empty", got)
	}
}

func TestCORSMiddleware_WildcardOrigin(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"*"}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := CORS(cfg)(next)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://client.acme.org")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q; want Origin", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q; want *", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q; want empty for wildcard origin", got)
	}
}

func TestCORSMiddleware_PreflightAllowed(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"https://app.example.com"}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	mw := CORS(cfg)(next)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("preflight OPTIONS should short-circuit and not call next handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q; want Origin", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Fatalf("Access-Control-Max-Age = %q; want 86400", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q; want https://app.example.com", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q; want true", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PUT, DELETE, OPTIONS" {
		t.Fatalf("Access-Control-Allow-Methods = %q; unexpected value", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type" {
		t.Fatalf("Access-Control-Allow-Headers = %q; unexpected value", got)
	}
}

func TestCORSMiddleware_PreflightDisallowed(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"https://app.example.com"}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	mw := CORS(cfg)(next)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://untrusted.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("preflight OPTIONS should short-circuit and not call next handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q; want Origin", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Fatalf("Access-Control-Max-Age = %q; want 86400", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q; want empty for disallowed origin", got)
	}
}

func TestCORSMiddleware_PlainOptionsPassThrough(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"https://app.example.com"}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := CORS(cfg)(next)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected plain OPTIONS request to pass through to next handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q; want Origin", got)
	}
}
