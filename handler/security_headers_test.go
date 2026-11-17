package handler

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaiizer777/go-auth/config"
)

func testSecurityApp(cfg config.Config) http.Handler {
	return New(nil, cfg, nil)
}

func TestSecurityHeaders_StandardResponse(t *testing.T) {
	h := testSecurityApp(config.DefaultConfig())
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "default-src 'self'; frame-ancestors 'none'" {
		t.Errorf("Content-Security-Policy = %q", got)
	}
}

func TestSecurityHeaders_NotFoundAndMethodNotAllowed(t *testing.T) {
	h := testSecurityApp(config.DefaultConfig())
	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{"404", http.MethodGet, "/no-such-route"},
		{"405", http.MethodPost, "/health"},
	} {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
			if rec.Header().Get(hdr) == "" {
				t.Errorf("%s: missing %s", tc.name, hdr)
			}
		}
	}
}

func TestSecurityHeaders_Preflight(t *testing.T) {
	h := testSecurityApp(config.DefaultConfig())
	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("preflight missing %s", hdr)
		}
	}
}

func TestSecurityHeaders_HSTSCleartextOmitted(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SessionCookieSecure = true
	mw := SecurityHeaders(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS on cleartext = %q, want empty", got)
	}
}

func TestSecurityHeaders_HSTSDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SecurityHeaders.EnableHSTS = false
	mw := SecurityHeaders(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS when disabled = %q, want empty", got)
	}
}

func TestSecurityHeaders_HSTSFormat(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sub     bool
		preload bool
		forward string
		want    string
	}{
		{"tls defaults", true, false, "", "max-age=31536000; includeSubDomains"},
		{"preload", true, true, "", "max-age=31536000; includeSubDomains; preload"},
		{"no subdomains", false, false, "", "max-age=31536000"},
		{"forwarded proto", true, false, "https", "max-age=31536000; includeSubDomains"},
	} {
		cfg := config.DefaultConfig()
		cfg.SecurityHeaders.HSTSIncludeSubdomains = tc.sub
		cfg.SecurityHeaders.HSTSPreload = tc.preload
		mw := SecurityHeaders(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if tc.forward == "" {
			req.TLS = &tls.ConnectionState{}
		} else {
			req.Header.Set("X-Forwarded-Proto", tc.forward)
		}
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if got := rec.Header().Get("Strict-Transport-Security"); got != tc.want {
			t.Errorf("%s: HSTS = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSecurityHeaders_CustomCSPAndFrameOptions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SecurityHeaders.ContentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; script-src 'self'"
	cfg.SecurityHeaders.FrameOptions = "SAMEORIGIN"
	mw := SecurityHeaders(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("Content-Security-Policy"); got != cfg.SecurityHeaders.ContentSecurityPolicy {
		t.Errorf("CSP = %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q", got)
	}
}

func TestSecurityHeaders_LocksBaselineAgainstMutation(t *testing.T) {
	cfg := config.DefaultConfig()
	mw := SecurityHeaders(&cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "text/plain")
		w.Header().Del("X-Frame-Options")
		_, _ = w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}
