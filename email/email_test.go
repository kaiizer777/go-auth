package email

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestBuildVerificationURL(t *testing.T) {
	got := buildVerificationURL("https://example.com", "tok123")
	want := "https://example.com/auth/verify/email?token=tok123"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildVerificationURL_EscapesToken(t *testing.T) {
	got := buildVerificationURL("https://example.com", "a b&c=d")
	want := "https://example.com/auth/verify/email?token=a+b%26c%3Dd"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildResetURL(t *testing.T) {
	got := buildResetURL("https://example.com", "tok123")
	want := "https://example.com/auth/password/reset?token=tok123"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildResetURL_EscapesToken(t *testing.T) {
	got := buildResetURL("https://example.com", "a b&c=d")
	want := "https://example.com/auth/password/reset?token=a+b%26c%3Dd"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDispatchVerification_PayloadCaptured(t *testing.T) {
	called := make(chan struct{})
	var got VerificationEmailPayload
	var mu sync.Mutex
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		mu.Lock()
		got = p
		mu.Unlock()
		close(called)
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		BaseURL:               "https://example.com",
		SendVerificationEmail: hook,
		EmailDispatchTimeout:  time.Second,
	}, captureLogger(&bytes.Buffer{}))

	expires := time.Now().Add(time.Hour)
	payload := VerificationEmailPayload{
		UserID:    "user-1",
		To:        "user@example.com",
		Token:     "tok-123",
		URL:       buildVerificationURL("https://example.com", "tok-123"),
		ExpiresAt: expires,
	}
	d.DispatchVerification(context.Background(), payload)

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("hook not called")
	}

	mu.Lock()
	defer mu.Unlock()
	if got.UserID != payload.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, payload.UserID)
	}
	if got.To != payload.To {
		t.Errorf("To = %q, want %q", got.To, payload.To)
	}
	if got.Token != payload.Token {
		t.Errorf("Token = %q, want %q", got.Token, payload.Token)
	}
	if got.URL != payload.URL {
		t.Errorf("URL = %q, want %q", got.URL, payload.URL)
	}
	if !got.ExpiresAt.Equal(payload.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, payload.ExpiresAt)
	}
}

func TestDispatchPasswordReset_PayloadCaptured(t *testing.T) {
	called := make(chan struct{})
	var got PasswordResetEmailPayload
	var mu sync.Mutex
	hook := func(ctx context.Context, p PasswordResetEmailPayload) error {
		mu.Lock()
		got = p
		mu.Unlock()
		close(called)
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		BaseURL:                "https://example.com",
		SendPasswordResetEmail: hook,
		EmailDispatchTimeout:   time.Second,
	}, captureLogger(&bytes.Buffer{}))

	expires := time.Now().Add(30 * time.Minute)
	payload := PasswordResetEmailPayload{
		UserID:    "user-2",
		To:        "user2@example.com",
		Token:     "reset-456",
		URL:       buildResetURL("https://example.com", "reset-456"),
		ExpiresAt: expires,
	}
	d.DispatchPasswordReset(context.Background(), payload)

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("hook not called")
	}

	mu.Lock()
	defer mu.Unlock()
	if got.UserID != payload.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, payload.UserID)
	}
	if got.Token != payload.Token {
		t.Errorf("Token = %q, want %q", got.Token, payload.Token)
	}
	if got.URL != payload.URL {
		t.Errorf("URL = %q, want %q", got.URL, payload.URL)
	}
	if !got.ExpiresAt.Equal(payload.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, payload.ExpiresAt)
	}
}

func TestDispatch_NilHookSync(t *testing.T) {
	var buf bytes.Buffer
	logger := captureLogger(&buf)
	d := NewAsyncDispatcher(DispatcherConfig{DisableAsyncEmailDispatch: true}, logger)
	d.DispatchVerification(context.Background(), VerificationEmailPayload{})

	if !strings.Contains(buf.String(), "EMAIL_HOOK_NIL") {
		t.Fatalf("expected EMAIL_HOOK_NIL in log, got: %s", buf.String())
	}
}

func TestDispatch_TypedErrorSync(t *testing.T) {
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		return errors.New("boom")
	}
	var buf bytes.Buffer
	logger := captureLogger(&buf)
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail:     hook,
		DisableAsyncEmailDispatch: true,
		EmailDispatchTimeout:      time.Second,
	}, logger)
	d.DispatchVerification(context.Background(), VerificationEmailPayload{Token: "secret-token"})

	if !strings.Contains(buf.String(), "EMAIL_DISPATCH_FAILED") {
		t.Fatalf("expected EMAIL_DISPATCH_FAILED in log, got: %s", buf.String())
	}
	if strings.Contains(buf.String(), "boom") {
		t.Fatalf("hook error leaked into log: %s", buf.String())
	}
}

func TestDispatch_PanicRecovered(t *testing.T) {
	secret := "super-secret-token-value"
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		panic(secret)
	}
	var buf bytes.Buffer
	logger := captureLogger(&buf)
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail:     hook,
		DisableAsyncEmailDispatch: true,
		EmailDispatchTimeout:      time.Second,
	}, logger)

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped dispatcher: %v", r)
			}
		}()
		d.DispatchVerification(context.Background(), VerificationEmailPayload{Token: secret})
	}()

	if !strings.Contains(buf.String(), "EMAIL_DISPATCH_FAILED") {
		t.Fatalf("expected EMAIL_DISPATCH_FAILED in log, got: %s", buf.String())
	}
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("secret leaked into log: %s", buf.String())
	}
}

func TestDispatch_AsyncDefault(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		close(started)
		<-release
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail: hook,
	}, captureLogger(&bytes.Buffer{}))

	returned := make(chan struct{})
	go func() {
		d.DispatchVerification(context.Background(), VerificationEmailPayload{})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch blocked")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("hook did not start")
	}
	close(release)
}

func TestDispatch_AsyncNonBlocking(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		close(started)
		<-release
		close(done)
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail: hook,
		EmailDispatchTimeout:  time.Second,
	}, captureLogger(&bytes.Buffer{}))

	returned := make(chan struct{})
	go func() {
		d.DispatchVerification(context.Background(), VerificationEmailPayload{})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch blocked")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("hook did not start")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hook did not finish")
	}
}

func TestDispatch_VerificationBaseURLUsed(t *testing.T) {
	called := make(chan struct{})
	var got string
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		got = p.URL
		close(called)
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		BaseURL:                   "https://example.com/",
		SendVerificationEmail:     hook,
		DisableAsyncEmailDispatch: true,
	}, captureLogger(&bytes.Buffer{}))
	d.DispatchVerification(context.Background(), VerificationEmailPayload{Token: "tok 123"})

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("hook not called")
	}
	want := "https://example.com/auth/verify/email?token=tok+123"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDispatch_PasswordResetBaseURLUsed(t *testing.T) {
	called := make(chan struct{})
	var got string
	hook := func(ctx context.Context, p PasswordResetEmailPayload) error {
		got = p.URL
		close(called)
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		BaseURL:                   "https://example.com/",
		SendPasswordResetEmail:    hook,
		DisableAsyncEmailDispatch: true,
	}, captureLogger(&bytes.Buffer{}))
	d.DispatchPasswordReset(context.Background(), PasswordResetEmailPayload{Token: "tok 123"})

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("hook not called")
	}
	want := "https://example.com/auth/password/reset?token=tok+123"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDispatch_PasswordResetTypedErrorNoSecret(t *testing.T) {
	secret := "reset-secret-token"
	hook := func(ctx context.Context, p PasswordResetEmailPayload) error {
		return errors.New("reset failed: " + secret)
	}
	var buf bytes.Buffer
	logger := captureLogger(&buf)
	d := NewAsyncDispatcher(DispatcherConfig{
		SendPasswordResetEmail:    hook,
		DisableAsyncEmailDispatch: true,
		EmailDispatchTimeout:      time.Second,
	}, logger)
	d.DispatchPasswordReset(context.Background(), PasswordResetEmailPayload{Token: secret, URL: "https://example.com/auth/password/reset?token=" + secret})

	if !strings.Contains(buf.String(), "EMAIL_DISPATCH_FAILED") {
		t.Fatalf("expected EMAIL_DISPATCH_FAILED in log, got: %s", buf.String())
	}
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("secret leaked into log: %s", buf.String())
	}
}

func TestDispatch_PanicTypeOnly(t *testing.T) {
	// Ensure panic recovery logs type, not value, for non-string panics too.
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		panic(42)
	}
	var buf bytes.Buffer
	logger := captureLogger(&buf)
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail:     hook,
		DisableAsyncEmailDispatch: true,
		EmailDispatchTimeout:      time.Second,
	}, logger)
	d.DispatchVerification(context.Background(), VerificationEmailPayload{})

	if !strings.Contains(buf.String(), "EMAIL_DISPATCH_FAILED") {
		t.Fatalf("expected EMAIL_DISPATCH_FAILED in log, got: %s", buf.String())
	}

	if !strings.Contains(buf.String(), "int") {
		t.Fatalf("expected panic type in log, got: %s", buf.String())
	}
}

func TestDispatch_Timeout(t *testing.T) {
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return nil
		}
	}
	var buf bytes.Buffer
	logger := captureLogger(&buf)
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail:     hook,
		DisableAsyncEmailDispatch: true,
		EmailDispatchTimeout:      50 * time.Millisecond,
	}, logger)
	d.DispatchVerification(context.Background(), VerificationEmailPayload{})

	if !strings.Contains(buf.String(), "EMAIL_DISPATCH_TIMEOUT") {
		t.Fatalf("expected EMAIL_DISPATCH_TIMEOUT in log, got: %s", buf.String())
	}
}

func TestNewAsyncDispatcher_NilLogger(t *testing.T) {
	d := NewAsyncDispatcher(DispatcherConfig{DisableAsyncEmailDispatch: true}, nil)
	if d == nil {
		t.Fatal("nil dispatcher")
	}
	d.DispatchVerification(context.Background(), VerificationEmailPayload{})
}

func TestDispatch_EmptyUserIDZeroExpiresAt(t *testing.T) {
	called := make(chan struct{})
	var got VerificationEmailPayload
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		got = p
		close(called)
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail:     hook,
		DisableAsyncEmailDispatch: true,
		EmailDispatchTimeout:      time.Second,
	}, captureLogger(&bytes.Buffer{}))
	payload := VerificationEmailPayload{UserID: "", To: "a@b.com", Token: "t", URL: buildVerificationURL("https://example.com", "t"), ExpiresAt: time.Time{}}
	d.DispatchVerification(context.Background(), payload)
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("hook not called")
	}
	if got.UserID != "" {
		t.Errorf("UserID = %q, want empty", got.UserID)
	}
	if !got.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", got.ExpiresAt)
	}
}

func TestDispatch_NilContext(t *testing.T) {
	called := make(chan struct{})
	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		close(called)
		return nil
	}
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail:     hook,
		DisableAsyncEmailDispatch: true,
		EmailDispatchTimeout:      time.Second,
	}, captureLogger(&bytes.Buffer{}))

	// Should not panic when ctx is nil
	d.DispatchVerification(nil, VerificationEmailPayload{To: "nilctx@example.com"})
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("hook not called with nil context")
	}
}
