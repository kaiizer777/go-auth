// Package goauth provides a composable, modular authentication library for Go.
//
// All core implementations are encapsulated in subpackages. The root package serves
// as the public facade and configuration entrypoint.
package goauth

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/session"
)

// Auth is the main entry point for the authentication library.
type Auth struct {
	db              *gorm.DB
	cfg             config.Config
	emailDispatcher *email.AsyncDispatcher

	// Handler is the root HTTP handler with mounted routes and middleware.
	Handler http.Handler

	// Auth is the core authentication service.
	Auth auth.Service

	// Session is the session management service.
	Session session.Service

	// SessionHandler is the HTTP handler for session management.
	SessionHandler *handler.SessionHandler

	loginLimiter    *ratelimit.Limiter
	loginIPLimiter  *ratelimit.Limiter
	resetLimiter    *ratelimit.Limiter
	resetIPLimiter  *ratelimit.Limiter
	signupLimiter   *ratelimit.Limiter
	signupIPLimiter *ratelimit.Limiter
	limiterDone     chan struct{}
	closeErr        error
	closeOnce       sync.Once
}

var dbConnectFn = db.Connect

// NewWithDB initializes Auth using an existing GORM database connection.
func NewWithDB(database *gorm.DB, cfg config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidConfig, "goauth: invalid configuration")
	}

	emailHooks := cfg.EmailHooks
	if emailHooks.SendVerificationEmail == nil && cfg.SendVerificationEmail != nil {
		emailHooks.SendVerificationEmail = func(ctx context.Context, recipient, token string) error {
			return cfg.SendVerificationEmail(ctx, email.VerificationEmailPayload{
				To:    recipient,
				Token: token,
				URL:   email.BuildVerificationURL(cfg.BaseURL, token),
			})
		}
	}
	if emailHooks.SendPasswordResetEmail == nil && cfg.SendPasswordResetEmail != nil {
		emailHooks.SendPasswordResetEmail = func(ctx context.Context, recipient, token string) error {
			return cfg.SendPasswordResetEmail(ctx, email.PasswordResetEmailPayload{
				To:    recipient,
				Token: token,
				URL:   email.BuildResetURL(cfg.BaseURL, token),
			})
		}
	}

	authSvc, err := auth.New(cfg, database, emailHooks)
	if err != nil {
		return nil, err
	}

	sessionSvc := session.NewService(database, &cfg)

	loginLimiter := ratelimit.NewLimiter(cfg.RateLimitLoginWindow, cfg.RateLimitLoginMax)
	loginIPLimiter := ratelimit.NewLimiter(cfg.RateLimitLoginWindow, cfg.RateLimitLoginIPMax)
	resetLimiter := ratelimit.NewLimiter(cfg.RateLimitResetWindow, cfg.RateLimitResetMax)
	resetIPLimiter := ratelimit.NewLimiter(cfg.RateLimitResetWindow, cfg.RateLimitResetIPMax)
	signupLimiter := ratelimit.NewLimiter(cfg.RateLimitSignupWindow, cfg.RateLimitSignupMax)
	signupIPLimiter := ratelimit.NewLimiter(cfg.RateLimitSignupWindow, cfg.RateLimitSignupIPMax)

	limiterDone := make(chan struct{})
	cleanupTick := cfg.RateLimitCleanupTick
	if cleanupTick <= 0 {
		cleanupTick = config.DefaultConfig().RateLimitCleanupTick
	}
	loginLimiter.StartCleanup(cleanupTick, limiterDone)
	loginIPLimiter.StartCleanup(cleanupTick, limiterDone)
	resetLimiter.StartCleanup(cleanupTick, limiterDone)
	resetIPLimiter.StartCleanup(cleanupTick, limiterDone)
	signupLimiter.StartCleanup(cleanupTick, limiterDone)
	signupIPLimiter.StartCleanup(cleanupTick, limiterDone)

	sessHandler := handler.NewSessionHandler(sessionSvc, database, &cfg)

	h := handler.New(database, cfg, authSvc,
		handler.WithSessionService(sessionSvc),
		handler.WithSessionHandler(sessHandler),
		handler.WithRateLimiters(loginLimiter, resetLimiter, signupLimiter),
		handler.WithIPRateLimiters(loginIPLimiter, resetIPLimiter, signupIPLimiter),
	)

	a := &Auth{
		db:  database,
		cfg: cfg,
		emailDispatcher: email.NewAsyncDispatcher(email.DispatcherConfig{
			BaseURL:                   cfg.BaseURL,
			DisableAsyncEmailDispatch: cfg.DisableAsyncEmailDispatch,
			EmailDispatchTimeout:      cfg.EmailDispatchTimeout,
			SendVerificationEmail:     cfg.SendVerificationEmail,
			SendPasswordResetEmail:    cfg.SendPasswordResetEmail,
		}, slog.Default()),
		Handler:         h,
		Auth:            authSvc,
		Session:         sessionSvc,
		SessionHandler:  sessHandler,
		loginLimiter:    loginLimiter,
		loginIPLimiter:  loginIPLimiter,
		resetLimiter:    resetLimiter,
		resetIPLimiter:  resetIPLimiter,
		signupLimiter:   signupLimiter,
		signupIPLimiter: signupIPLimiter,
		limiterDone:     limiterDone,
	}
	return a, nil
}

// New validates runtime configuration, establishes database connectivity,
// runs pending migrations, and initializes the HTTP handler chain.
func New(cfg config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidConfig, "goauth: invalid configuration")
	}

	database, err := dbConnectFn(cfg)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "goauth: failed to connect to database")
	}

	a, err := NewWithDB(database, cfg)
	if err != nil {
		if sqlDB, dbErr := database.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		return nil, err
	}
	return a, nil
}

// Close terminates the underlying database connection pool and background cleanups.
// It is fully idempotent; subsequent calls return the result of the first close.
func (a *Auth) Close() error {
	a.closeOnce.Do(func() {
		if a.limiterDone != nil {
			close(a.limiterDone)
		}
		if a.loginLimiter != nil {
			a.loginLimiter.Close()
		}
		if a.loginIPLimiter != nil {
			a.loginIPLimiter.Close()
		}
		if a.resetLimiter != nil {
			a.resetLimiter.Close()
		}
		if a.resetIPLimiter != nil {
			a.resetIPLimiter.Close()
		}
		if a.signupLimiter != nil {
			a.signupLimiter.Close()
		}
		if a.signupIPLimiter != nil {
			a.signupIPLimiter.Close()
		}
		if a.emailDispatcher != nil {
			_ = a.emailDispatcher.Shutdown(context.Background())
		}
		if a.db != nil {
			if sqlDB, err := a.db.DB(); err != nil {
				a.closeErr = errors.New(errors.CodeDatabaseError, "failed to get sql.DB", err)
			} else if err := sqlDB.Close(); err != nil {
				a.closeErr = errors.New(errors.CodeDatabaseError, "failed to close database", err)
			}
		}
	})
	return a.closeErr
}

// RequireAuth returns middleware that validates session credentials from cookies or Bearer headers.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return handler.RequireAuth(a.Session, &a.cfg)(next)
}

// CSRF returns middleware that enforces Double Submit Cookie CSRF protection.
func (a *Auth) CSRF(next http.Handler) http.Handler {
	return csrf.Middleware(&a.cfg)(next)
}

// SessionService returns the configured session service.
func (a *Auth) SessionService() session.Service {
	return a.Session
}

// PurgeExpiredSessions deletes all sessions past their absolute expiration or idle timeout across all users.
func (a *Auth) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	if a == nil || a.Session == nil {
		return 0, nil
	}
	return a.Session.PurgeExpired(ctx)
}

// EmailDispatcher returns the configured email dispatcher.
func (a *Auth) EmailDispatcher() email.Dispatcher {
	if a == nil || a.emailDispatcher == nil {
		return nil
	}
	return a.emailDispatcher
}
