package email

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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

	// Should not panic when ctx is nil (nil via var to satisfy SA1012)
	var ctx context.Context
	d.DispatchVerification(ctx, VerificationEmailPayload{To: "nilctx@example.com"})
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("hook not called with nil context")
	}
}

func TestDispatch_SemaphoreSaturation(t *testing.T) {
	const capacity = emailDispatchSemaphoreSize // 128
	var startedWg sync.WaitGroup
	var completedWg sync.WaitGroup
	startedWg.Add(capacity)
	completedWg.Add(capacity + 1)

	releaseHooks := make(chan struct{})
	var hookCount atomic.Int32

	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		if hookCount.Add(1) <= capacity {
			startedWg.Done()
			<-releaseHooks
		}
		completedWg.Done()
		return nil
	}

	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail: hook,
		EmailDispatchTimeout:  10 * time.Second,
	}, captureLogger(&bytes.Buffer{}))

	payload := VerificationEmailPayload{
		UserID: "user-saturation",
		To:     "user@example.com",
		Token:  "tok-saturation",
	}

	// Dispatch 128 items to saturate the semaphore channel capacity.
	for i := 0; i < capacity; i++ {
		d.DispatchVerification(context.Background(), payload)
	}

	// Wait until all 128 goroutines have acquired a slot and started running.
	startedWg.Wait()

	if got := len(d.sem); got != capacity {
		t.Fatalf("expected semaphore to be fully saturated at %d, got %d", capacity, got)
	}

	// Dispatch the 129th item in a separate goroutine.
	// Because semaphore capacity is 128, DispatchVerification should block attempting to send to d.sem.
	dispatch129Acquiring := make(chan struct{})
	d.beforeAcquireSem = func() {
		close(dispatch129Acquiring)
	}
	dispatch129Finished := make(chan struct{})

	go func() {
		d.DispatchVerification(context.Background(), payload)
		close(dispatch129Finished)
	}()

	select {
	case <-dispatch129Acquiring:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for 129th dispatch to reach semaphore acquisition")
	}

	// Verify the 129th dispatch is indeed blocked on semaphore saturation.
	select {
	case <-dispatch129Finished:
		t.Fatal("expected 129th dispatch to block on saturated semaphore, but it returned prematurely")
	case <-time.After(50 * time.Millisecond):
		// Block confirmed.
	}

	// Release blocked workers so semaphore slots are freed.
	close(releaseHooks)

	// Verify the 129th dispatch now unblocks and finishes.
	select {
	case <-dispatch129Finished:
		// Succeeded unblocking.
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for 129th dispatch to complete after releasing semaphore")
	}

	// Wait for all 129 goroutines to finish.
	completedWg.Wait()
}

func TestBuildURL_AdversarialEscaping(t *testing.T) {
	baseURL := "https://example.com"

	payloads := []struct {
		name    string
		payload string
	}{
		{
			name:    "SQL injection quote and comment",
			payload: "' OR '1'='1' --",
		},
		{
			name:    "SQL injection union select",
			payload: "1' UNION SELECT 1,2,3--",
		},
		{
			name:    "XSS script tag",
			payload: `<script>alert("xss")</script>`,
		},
		{
			name:    "XSS image onerror event",
			payload: `<img src=x onerror=alert('xss')>`,
		},
		{
			name:    "query parameter injection with ampersand",
			payload: "token123&admin=true&role=superuser",
		},
		{
			name:    "path traversal and fragments",
			payload: "../../etc/passwd#section",
		},
		{
			name:    "whitespace and control characters",
			payload: "token with spaces\r\nand\tcontrol",
		},
		{
			name:    "double quotes and brackets",
			payload: `{"token": "evil"}[0]`,
		},
	}

	for _, tt := range payloads {
		t.Run(tt.name, func(t *testing.T) {
			verifyURL := BuildVerificationURL(baseURL, tt.payload)
			parsedVerify, err := url.Parse(verifyURL)
			if err != nil {
				t.Fatalf("failed to parse verification URL %q: %v", verifyURL, err)
			}

			// Ensure parameter injection did not succeed: 'token' query param must match payload exactly
			queryVerify := parsedVerify.Query()
			if gotToken := queryVerify.Get("token"); gotToken != tt.payload {
				t.Errorf("BuildVerificationURL: token query = %q, want %q", gotToken, tt.payload)
			}
			// Ensure no extra query parameters were injected (e.g. from &admin=true)
			if len(queryVerify) != 1 {
				t.Errorf("BuildVerificationURL: expected exactly 1 query parameter, got %d: %v", len(queryVerify), queryVerify)
			}

			resetURL := BuildResetURL(baseURL, tt.payload)
			parsedReset, err := url.Parse(resetURL)
			if err != nil {
				t.Fatalf("failed to parse reset URL %q: %v", resetURL, err)
			}

			queryReset := parsedReset.Query()
			if gotToken := queryReset.Get("token"); gotToken != tt.payload {
				t.Errorf("BuildResetURL: token query = %q, want %q", gotToken, tt.payload)
			}
			if len(queryReset) != 1 {
				t.Errorf("BuildResetURL: expected exactly 1 query parameter, got %d: %v", len(queryReset), queryReset)
			}
		})
	}
}
