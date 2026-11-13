//go:build integration || e2e

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kaiizer777/go-auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/email"
)

const defaultTestDBURL = "postgres://postgres:postgres@localhost:5432/goauth_test?sslmode=disable"

func resolveDatabaseURL() string {
	if u := os.Getenv("TEST_DATABASE_URL"); u != "" {
		return u
	}
	if u := os.Getenv("GOAUTH_TEST_DATABASE_URL"); u != "" {
		return u
	}
	return defaultTestDBURL
}

func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "REDACTED")
	}
	return strings.ReplaceAll(u.String(), "%3A", ":")
}

type emailCapture struct {
	verificationTokens  chan string
	passwordResetTokens chan string
}

func newEmailCapture() *emailCapture {
	return &emailCapture{
		verificationTokens:  make(chan string, 100),
		passwordResetTokens: make(chan string, 100),
	}
}

func (c *emailCapture) nextVerificationToken(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case tok := <-c.verificationTokens:
		return tok
	case <-time.After(timeout):
		t.Fatalf("timed out after %v waiting for verification email token", timeout)
		return ""
	}
}

func (c *emailCapture) nextResetToken(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case tok := <-c.passwordResetTokens:
		return tok
	case <-time.After(timeout):
		t.Fatalf("timed out after %v waiting for password reset email token", timeout)
		return ""
	}
}

func truncateTables(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec("TRUNCATE TABLE users, sessions, verification_tokens, password_reset_tokens CASCADE")
	if err != nil {
		t.Fatalf("failed to truncate tables: %v", err)
	}
}

func setupE2EServer(t *testing.T) (*httptest.Server, *http.Client, *emailCapture, *sql.DB) {
	return setupE2EServerWithConfig(t, nil)
}

func setupE2EServerWithConfig(t *testing.T, mutate func(*config.Config)) (*httptest.Server, *http.Client, *emailCapture, *sql.DB) {
	t.Helper()

	dbURL := resolveDatabaseURL()

	// Connectivity check
	probeDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: failed to open postgres at %s: %v", sanitizeURL(dbURL), err)
		}
		t.Skipf("Postgres not available, skipping e2e: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := probeDB.PingContext(ctx); err != nil {
		_ = probeDB.Close()
		if os.Getenv("CI") != "" {
			t.Fatalf("CI: Postgres ping failed at %s: %v", sanitizeURL(dbURL), err)
		}
		t.Skipf("Postgres not available at %s, skipping e2e: %v", sanitizeURL(dbURL), err)
	}
	_ = probeDB.Close()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("failed to open sql.DB: %v", err)
	}

	truncateTables(t, sqlDB)

	capture := newEmailCapture()

	cfg := config.DefaultConfig()
	cfg.DatabaseURL = dbURL
	cfg.BaseURL = "http://127.0.0.1:8080"
	cfg.AllowedOrigins = []string{"http://example.com", "http://localhost:3000"}
	cfg.Argon2 = config.Argon2Config{
		Memory:      19456,
		Time:        2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	cfg.EmailHooks.SendVerificationEmail = func(ctx context.Context, recipient, token string) error {
		select {
		case capture.verificationTokens <- token:
		default:
		}
		return nil
	}
	cfg.EmailHooks.SendPasswordResetEmail = func(ctx context.Context, recipient, token string) error {
		select {
		case capture.passwordResetTokens <- token:
		default:
		}
		return nil
	}

	cfg.SendVerificationEmail = func(ctx context.Context, payload email.VerificationEmailPayload) error {
		select {
		case capture.verificationTokens <- payload.Token:
		default:
		}
		return nil
	}
	cfg.SendPasswordResetEmail = func(ctx context.Context, payload email.PasswordResetEmailPayload) error {
		select {
		case capture.passwordResetTokens <- payload.Token:
		default:
		}
		return nil
	}

	if mutate != nil {
		mutate(&cfg)
	}

	app, err := goauth.New(cfg)
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("failed to initialize goauth: %v", err)
	}

	server := httptest.NewServer(app.Handler)

	jar, err := cookiejar.New(nil)
	if err != nil {
		server.Close()
		_ = app.Close()
		_ = sqlDB.Close()
		t.Fatalf("failed to initialize cookiejar: %v", err)
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 5 * time.Second,
	}

	t.Cleanup(func() {
		server.Close()
		_ = app.Close()
		_ = sqlDB.Close()
	})

	return server, client, capture, sqlDB
}

func postJSON(t *testing.T, client *http.Client, targetURL string, payload any) (*http.Response, map[string]any) {
	t.Helper()
	var bodyReader io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal JSON payload: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(http.MethodPost, targetURL, bodyReader)
	if err != nil {
		t.Fatalf("failed to create POST request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute POST request: %v", err)
	}

	data := readJSONBody(t, resp)
	return resp, data
}

func getJSON(t *testing.T, client *http.Client, targetURL string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("failed to create GET request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute GET request: %v", err)
	}

	data := readJSONBody(t, resp)
	return resp, data
}

func requestOPTIONS(t *testing.T, client *http.Client, targetURL, origin, method string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodOptions, targetURL, nil)
	if err != nil {
		t.Fatalf("failed to create OPTIONS request: %v", err)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if method != "" {
		req.Header.Set("Access-Control-Request-Method", method)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute OPTIONS request: %v", err)
	}
	return resp
}

func readJSONBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if len(bodyBytes) == 0 {
		return nil
	}

	var result map[string]any
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		t.Fatalf("failed to parse JSON response (%s): %v", string(bodyBytes), err)
	}
	return result
}

func TestHarness_Smoke(t *testing.T) {
	server, client, _, _ := setupE2EServer(t)

	resp, body := getJSON(t, client, server.URL+"/health")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 from /health, got %d", resp.StatusCode)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status 'ok', got %v", body["status"])
	}
}

func TestHarness_EmailCaptureAndDBIsolation(t *testing.T) {
	_, _, capture, sqlDB := setupE2EServer(t)

	// Verify DB isolation helper truncates cleanly
	truncateTables(t, sqlDB)

	var count int
	if err := sqlDB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatalf("failed to query users count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 users after truncate, got %d", count)
	}

	// Verify email token capture buffering
	testVerificationToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	capture.verificationTokens <- testVerificationToken
	gotVerification := capture.nextVerificationToken(t, time.Second)
	if gotVerification != testVerificationToken {
		t.Fatalf("expected verification token %q, got %q", testVerificationToken, gotVerification)
	}

	testResetToken := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	capture.passwordResetTokens <- testResetToken
	gotReset := capture.nextResetToken(t, time.Second)
	if gotReset != testResetToken {
		t.Fatalf("expected reset token %q, got %q", testResetToken, gotReset)
	}
}
