package email

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// DispatchVerification dispatches a verification email hook.
func (d *AsyncDispatcher) DispatchVerification(ctx context.Context, payload VerificationEmailPayload) {
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
	payload.URL = BuildResetURL(d.baseURL, payload.Token)
	d.dispatch(ctx, "password_reset", func(c context.Context) error {
		if d.sendPasswordReset == nil {
			d.logger.Warn("email hook is nil", "op", "password_reset", "code", string(errors.CodeEmailHookNil))
			return nil
		}
		return d.sendPasswordReset(c, payload)
	})
}

func (d *AsyncDispatcher) dispatch(ctx context.Context, op string, run func(context.Context) error) {
	if d.async {
		if d.beforeAcquireSem != nil {
			d.beforeAcquireSem()
		}
		d.sem <- struct{}{}
		go func() {
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
	d.logger.Error("email dispatch failed", "op", op, "code", string(code))
}
