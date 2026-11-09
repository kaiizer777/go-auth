package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaiizer777/go-auth/config"
)

func TestNewHandler_HealthEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	h := New(nil, cfg)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestNewHandler_NotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	h := New(nil, cfg)

	req := httptest.NewRequest(http.MethodGet, "/non-existent-endpoint", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
}

func TestNewHandler_WrapsCORSMiddleware(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AllowedOrigins = []string{"https://dashboard.example.com"}

	h := New(nil, cfg)

	// Test GET with Origin
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://dashboard.example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q; want https://dashboard.example.com", got)
	}

	// Test OPTIONS preflight short-circuit
	optReq := httptest.NewRequest(http.MethodOptions, "/health", nil)
	optReq.Header.Set("Origin", "https://dashboard.example.com")
	optReq.Header.Set("Access-Control-Request-Method", "GET")
	optRec := httptest.NewRecorder()

	h.ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, optRec.Code)
	}
	if got := optRec.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Fatalf("Access-Control-Max-Age = %q; want 86400", got)
	}
}
