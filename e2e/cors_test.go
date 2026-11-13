//go:build e2e

package e2e

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestCORS_PreflightOptions(t *testing.T) {
	server, client, _, _ := setupE2EServer(t)

	// Preflight OPTIONS request for trusted origin
	resp := requestOPTIONS(t, client, server.URL+"/auth/signup", "http://example.com", http.MethodPost)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for preflight OPTIONS, got %d", resp.StatusCode)
	}

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://example.com" {
		t.Fatalf("expected Access-Control-Allow-Origin 'http://example.com', got %q", got)
	}

	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected Access-Control-Allow-Credentials 'true', got %q", got)
	}

	if got := resp.Header.Get("Access-Control-Max-Age"); got != "86400" {
		t.Fatalf("expected Access-Control-Max-Age '86400', got %q", got)
	}

	methods := resp.Header.Get("Access-Control-Allow-Methods")
	if !strings.Contains(methods, "POST") {
		t.Fatalf("expected Access-Control-Allow-Methods to include POST, got %q", methods)
	}

	vary := resp.Header.Get("Vary")
	if !strings.Contains(vary, "Origin") {
		t.Fatalf("expected Vary header to contain Origin, got %q", vary)
	}
}

func TestCORS_CredentialedCrossOriginRequest(t *testing.T) {
	server, client, _, _ := setupE2EServer(t)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/auth/login", bytes.NewReader([]byte(`{"email":"nonexistent@example.com","password":"Password123!"}`)))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:3000")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("expected Access-Control-Allow-Origin 'http://localhost:3000', got %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected Access-Control-Allow-Credentials 'true', got %q", got)
	}
}

func TestCORS_UntrustedOriginOmitted(t *testing.T) {
	server, client, _, _ := setupE2EServer(t)

	resp := requestOPTIONS(t, client, server.URL+"/auth/signup", "http://malicious.evil.com", http.MethodPost)
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected empty Access-Control-Allow-Origin for untrusted origin, got %q", got)
	}
}

func TestRouting_StandardizedNotFoundAndMethodNotAllowed(t *testing.T) {
	server, client, _, _ := setupE2EServer(t)

	// 1. Non-existent route -> 404 NOT_FOUND JSON
	resp404, body404 := getJSON(t, client, server.URL+"/auth/does-not-exist")
	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown route, got %d", resp404.StatusCode)
	}
	if body404["code"] != "NOT_FOUND" {
		t.Fatalf("expected NOT_FOUND code, got %v", body404)
	}

	// 2. Method not allowed (GET on POST /auth/signup) -> 405 METHOD_NOT_ALLOWED JSON
	resp405, body405 := getJSON(t, client, server.URL+"/auth/signup")
	if resp405.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET on signup, got %d", resp405.StatusCode)
	}
	if body405["code"] != "METHOD_NOT_ALLOWED" {
		t.Fatalf("expected METHOD_NOT_ALLOWED code, got %v", body405)
	}
}
