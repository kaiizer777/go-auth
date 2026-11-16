package email

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatch_ContextCancelledOnSaturatedSemaphore(t *testing.T) {
	const capacity = emailDispatchSemaphoreSize // 128
	var startedWg sync.WaitGroup
	startedWg.Add(capacity)
	releaseHooks := make(chan struct{})

	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		startedWg.Done()
		<-releaseHooks
		return nil
	}

	var logBuf bytes.Buffer
	logger := captureLogger(&logBuf)
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail: hook,
		EmailDispatchTimeout:  5 * time.Second,
	}, logger)

	payload := VerificationEmailPayload{
		UserID: "user-test",
		To:     "user@example.com",
		Token:  "token-test",
	}

	// Saturate semaphore
	for i := 0; i < capacity; i++ {
		d.DispatchVerification(context.Background(), payload)
	}
	startedWg.Wait()

	// 129th dispatch with short context deadline should abort cleanly without hanging
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	dispatchDone := make(chan struct{})
	go func() {
		d.DispatchVerification(ctx, payload)
		close(dispatchDone)
	}()

	select {
	case <-dispatchDone:
		// Succeeded immediately on context cancellation
	case <-time.After(500 * time.Millisecond):
		t.Fatal("dispatch failed to return after context cancellation")
	}

	close(releaseHooks)
	_ = d.Shutdown(context.Background())

	if !strings.Contains(logBuf.String(), "email dispatch cancelled before acquisition") {
		t.Fatalf("expected cancellation log, got: %s", logBuf.String())
	}
}

func TestDispatch_GracefulShutdown(t *testing.T) {
	var inFlight atomic.Int32
	var completed atomic.Int32
	unblock := make(chan struct{})

	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		inFlight.Add(1)
		<-unblock
		completed.Add(1)
		return nil
	}

	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail: hook,
		EmailDispatchTimeout:  5 * time.Second,
	}, captureLogger(&bytes.Buffer{}))

	for i := 0; i < 5; i++ {
		d.DispatchVerification(context.Background(), VerificationEmailPayload{To: "a@b.com"})
	}

	// Wait briefly for jobs to start
	for i := 0; i < 50; i++ {
		if inFlight.Load() == 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- d.Shutdown(context.Background())
	}()

	// Ensure shutdown is waiting for in-flight jobs
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned before in-flight tasks completed")
	case <-time.After(50 * time.Millisecond):
	}

	// Unblock workers
	close(unblock)

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("unexpected shutdown error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown timed out")
	}

	if got := completed.Load(); got != 5 {
		t.Fatalf("completed = %d; want 5", got)
	}

	// Post-shutdown dispatch is ignored
	var postCalled atomic.Bool
	d.sendVerification = func(ctx context.Context, p VerificationEmailPayload) error {
		postCalled.Store(true)
		return nil
	}
	d.DispatchVerification(context.Background(), VerificationEmailPayload{To: "post@b.com"})
	if postCalled.Load() {
		t.Fatal("expected post-shutdown dispatch to be ignored")
	}
}

func TestDispatch_ShutdownTimeout(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	hook := func(ctx context.Context, p VerificationEmailPayload) error {
		<-block
		return nil
	}

	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail: hook,
		EmailDispatchTimeout:  5 * time.Second,
	}, captureLogger(&bytes.Buffer{}))

	d.DispatchVerification(context.Background(), VerificationEmailPayload{To: "a@b.com"})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := d.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestDispatch_RecipientCRLFInjectionRejected(t *testing.T) {
	tests := []struct {
		name string
		to   string
	}{
		{"CRLF injection", "victim@example.com\r\nBcc: attacker@example.com"},
		{"LF injection", "victim@example.com\nBcc: attacker@example.com"},
		{"Null byte", "victim@example.com\x00extra"},
		{"Tab in address", "victim\texample.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			hook := func(ctx context.Context, p VerificationEmailPayload) error {
				called = true
				return nil
			}
			var logBuf bytes.Buffer
			logger := captureLogger(&logBuf)
			d := NewAsyncDispatcher(DispatcherConfig{
				SendVerificationEmail:     hook,
				DisableAsyncEmailDispatch: true,
			}, logger)

			d.DispatchVerification(context.Background(), VerificationEmailPayload{To: tt.to})

			if called {
				t.Fatalf("hook should not have been called for invalid recipient %q", tt.to)
			}
			if !strings.Contains(logBuf.String(), "INVALID_EMAIL") {
				t.Fatalf("expected INVALID_EMAIL in log, got: %s", logBuf.String())
			}

			// Password reset payload check
			var resetCalled bool
			resetHook := func(ctx context.Context, p PasswordResetEmailPayload) error {
				resetCalled = true
				return nil
			}
			d.sendPasswordReset = resetHook
			d.DispatchPasswordReset(context.Background(), PasswordResetEmailPayload{To: tt.to})
			if resetCalled {
				t.Fatalf("password reset hook should not have been called for %q", tt.to)
			}
		})
	}
}

func TestDispatch_ErrorTypeLoggedWithoutSecret(t *testing.T) {
	type customNetworkError struct {
		secretToken string
	}
	var logBuf bytes.Buffer
	logger := captureLogger(&logBuf)
	d := NewAsyncDispatcher(DispatcherConfig{
		SendVerificationEmail:     func(ctx context.Context, p VerificationEmailPayload) error { return errors.New("smtp auth failed: secret-pwd-123") },
		DisableAsyncEmailDispatch: true,
	}, logger)

	d.DispatchVerification(context.Background(), VerificationEmailPayload{To: "a@b.com"})

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "error_type") {
		t.Fatalf("expected error_type in log, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "*errors.errorString") {
		t.Fatalf("expected *errors.errorString in log, got: %s", logOutput)
	}
	if strings.Contains(logOutput, "secret-pwd-123") {
		t.Fatalf("secret password leaked into log: %s", logOutput)
	}
}
