package email

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kaiizer777/go-auth/errors"
)

// Dispatcher defines the email dispatch contract.
type Dispatcher interface {
	DispatchVerification(ctx context.Context, payload VerificationEmailPayload)
	DispatchPasswordReset(ctx context.Context, payload PasswordResetEmailPayload)
}

// emailDispatchSemaphoreSize bounds concurrent async dispatch goroutines.
const emailDispatchSemaphoreSize = 128

// AsyncDispatcher dispatches email hooks asynchronously with panic recovery and timeout.
type AsyncDispatcher struct {
	baseURL           string
	sendVerification  SendVerificationEmailFunc
	sendPasswordReset SendPasswordResetEmailFunc
	timeout           time.Duration
	async             bool
	logger            *slog.Logger
	sem               chan struct{}
	beforeAcquireSem  func()
	wg                sync.WaitGroup
	mu                sync.RWMutex
	closed            bool
}

// NewAsyncDispatcher constructs an AsyncDispatcher from opts.
func NewAsyncDispatcher(opts DispatcherConfig, logger *slog.Logger) *AsyncDispatcher {
	d := &AsyncDispatcher{
		baseURL: strings.TrimRight(opts.BaseURL, "/"),
		logger:  slog.Default(),
		timeout: 10 * time.Second,
		async:   !opts.DisableAsyncEmailDispatch,
		sem:     make(chan struct{}, emailDispatchSemaphoreSize),
	}
	if logger != nil {
		d.logger = logger
	}
	d.sendVerification = opts.SendVerificationEmail
	d.sendPasswordReset = opts.SendPasswordResetEmail
	if opts.EmailDispatchTimeout != 0 {
		d.timeout = opts.EmailDispatchTimeout
	}
	if d.logger == nil {
		d.logger = slog.Default()
	}
	if d.timeout <= 0 {
		d.timeout = 10 * time.Second
	}
	return d
}

// containsControl reports whether s contains ASCII control characters or DEL.
func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 32 || b == 127 {
			return true
		}
	}
	return false
}

// DispatchVerification dispatches a verification email hook.
func (d *AsyncDispatcher) DispatchVerification(ctx context.Context, payload VerificationEmailPayload) {
	d.mu.RLock()
	closed := d.closed
	d.mu.RUnlock()
	if closed {
		d.logger.Warn("email dispatch ignored: dispatcher is closed", "op", "verification")
		return
	}

	if containsControl(payload.To) {
		d.logger.Error("email dispatch rejected: invalid recipient address", "op", "verification", "code", string(errors.CodeInvalidEmail))
		return
	}

	payload.URL = BuildVerificationURL(d.baseURL, payload.Token)
	d.dispatch(ctx, "verification", func(c context.Context) error {
		if d.sendVerification == nil {
			d.logger.Warn("email hook is nil", "op", "verification", "code", string(errors.CodeEmailHookNil))
			return nil
		}
		return d.sendVerification(c, payload)
	})
}

// DispatchPasswordReset dispatches a password reset email hook.
func (d *AsyncDispatcher) DispatchPasswordReset(ctx context.Context, payload PasswordResetEmailPayload) {
	d.mu.RLock()
	closed := d.closed
	d.mu.RUnlock()
	if closed {
		d.logger.Warn("email dispatch ignored: dispatcher is closed", "op", "password_reset")
		return
	}

	if containsControl(payload.To) {
		d.logger.Error("email dispatch rejected: invalid recipient address", "op", "password_reset", "code", string(errors.CodeInvalidEmail))
		return
	}

	payload.URL = BuildResetURL(d.baseURL, payload.Token)
	d.dispatch(ctx, "password_reset", func(c context.Context) error {
		if d.sendPasswordReset == nil {
			d.logger.Warn("email hook is nil", "op", "password_reset", "code", string(errors.CodeEmailHookNil))
			return nil
		}
		return d.sendPasswordReset(c, payload)
	})
}

// Shutdown gracefully waits for all active email dispatch tasks to finish or until ctx is done.
func (d *AsyncDispatcher) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *AsyncDispatcher) dispatch(ctx context.Context, op string, run func(context.Context) error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d.async {
		if d.beforeAcquireSem != nil {
			d.beforeAcquireSem()
		}
		select {
		case d.sem <- struct{}{}:
		case <-ctx.Done():
			d.logger.Error("email dispatch cancelled before acquisition", "op", op, "err", ctx.Err())
			return
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() { <-d.sem }()
			defer func() {
				if r := recover(); r != nil {
					d.logger.Error("email dispatch panicked", "op", op, "panic", fmt.Sprintf("%T", r), "code", string(errors.CodeEmailDispatchFailed))
				}
			}()
			d.execute(ctx, op, run)
		}()
		return
	}
	d.wg.Add(1)
	defer d.wg.Done()
	func() {
		defer func() {
			if r := recover(); r != nil {
				d.logger.Error("email dispatch panicked", "op", op, "panic", fmt.Sprintf("%T", r), "code", string(errors.CodeEmailDispatchFailed))
			}
		}()
		d.execute(ctx, op, run)
	}()
}

func (d *AsyncDispatcher) execute(ctx context.Context, op string, run func(context.Context) error) {
	timeout := d.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	err := run(cctx)
	if err == nil {
		return
	}
	code := errors.CodeEmailDispatchFailed
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(cctx.Err(), context.DeadlineExceeded) {
		code = errors.CodeEmailDispatchTimeout
	}
	d.logger.Error("email dispatch failed", "op", op, "code", string(code), "error_type", fmt.Sprintf("%T", err))
}
