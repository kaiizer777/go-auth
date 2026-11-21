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
	"time"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/csrf"
	"github.com/kaiizer777/go-auth/db"
	gormstore "github.com/kaiizer777/go-auth/db/gorm"
	mongostore "github.com/kaiizer777/go-auth/db/mongo"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/handler"
	"github.com/kaiizer777/go-auth/oauth"
	"github.com/kaiizer777/go-auth/ratelimit"
	"github.com/kaiizer777/go-auth/session"
	"github.com/kaiizer777/go-auth/totp"
)

// Auth is the main entry point for the authentication library.
type Auth struct {
	db              *gorm.DB
	store           db.Store
	cfg             config.Config
	emailDispatcher *email.AsyncDispatcher

	// Handler is the root HTTP handler with mounted routes and middleware.
	Handler http.Handler

	// Auth is the core authentication service.
	Auth auth.Service

	// Session is the session management service.
	Session session.Service

	// OAuth is the external identity provider and social login service.
	OAuth oauth.Service

	// TOTP is the RFC 6238 TOTP two-factor authentication service.
	TOTP totp.Service

	// SessionHandler is the HTTP handler for session management.
	SessionHandler *handler.SessionHandler

	loginLimiter    *ratelimit.Limiter
	loginIPLimiter  *ratelimit.Limiter
	resetLimiter    *ratelimit.Limiter
	resetIPLimiter  *ratelimit.Limiter
	signupLimiter   *ratelimit.Limiter
	signupIPLimiter *ratelimit.Limiter
	totpLimiter     *ratelimit.Limiter
	limiterDone     chan struct{}
	closeErr        error
	closeOnce       sync.Once
}

var (
	dbConnectFn    = db.Connect
	mongoConnectFn = func(cfg config.Config) (db.Store, error) {
		return mongostore.Connect(cfg)
	}
)

// NewWithStore initializes Auth using an existing db.Store.
func NewWithStore(store db.Store, cfg config.Config) (*Auth, error) {
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

	authSvc, err := auth.NewWithStore(cfg, store, emailHooks)
	if err != nil {
		return nil, err
	}

	sessionSvc := session.NewServiceWithStore(store, &cfg)

	loginLimiter := ratelimit.NewLimiter(cfg.RateLimitLoginWindow, cfg.RateLimitLoginMax)
	loginIPLimiter := ratelimit.NewLimiter(cfg.RateLimitLoginWindow, cfg.RateLimitLoginIPMax)
	resetLimiter := ratelimit.NewLimiter(cfg.RateLimitResetWindow, cfg.RateLimitResetMax)
	resetIPLimiter := ratelimit.NewLimiter(cfg.RateLimitResetWindow, cfg.RateLimitResetIPMax)
	signupLimiter := ratelimit.NewLimiter(cfg.RateLimitSignupWindow, cfg.RateLimitSignupMax)
	signupIPLimiter := ratelimit.NewLimiter(cfg.RateLimitSignupWindow, cfg.RateLimitSignupIPMax)
	oauthIPLimiter := ratelimit.NewLimiter(cfg.RateLimitOAuthWindow, cfg.RateLimitOAuthIPMax)

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
	oauthIPLimiter.StartCleanup(cleanupTick, limiterDone)

	sessHandler := handler.NewSessionHandlerWithStore(sessionSvc, store, &cfg)

	providers := make(map[string]oauth.Provider)
	for id, pcfg := range cfg.OAuth.Providers {
		if !pcfg.Enabled {
			continue
		}
		p, err := oauth.NewProvider(id, pcfg)
		if err != nil {
			return nil, err
		}
		providers[id] = p
	}
	var oauthSvc oauth.Service
	var oauthOpt handler.Option
	if len(providers) > 0 {
		oauthSvc = oauth.NewServiceWithStore(store, sessionSvc, providers, &cfg)
		oauthOpt = handler.WithOAuthService(oauthSvc, providers)
	}

	var totpSvc totp.Service
	var totpLimiter *ratelimit.Limiter
	if cfg.TOTP.EncryptionKey != "" {
		window := cfg.TOTP.AttemptWindow
		if window <= 0 {
			window = 5 * time.Minute
		}
		maxAttempts := cfg.TOTP.MaxAttemptsPerWindow
		if maxAttempts <= 0 {
			maxAttempts = 5
		}
		totpLimiter = ratelimit.NewLimiter(window, maxAttempts)
		totpLimiter.StartCleanup(cleanupTick, limiterDone)
		totpSvc = totp.NewServiceWithStore(store, cfg.TOTP, totpLimiter, slog.Default())
	}

	handlerOpts := []handler.Option{
		handler.WithStore(store),
		handler.WithSessionService(sessionSvc),
		handler.WithSessionHandler(sessHandler),
		handler.WithRateLimiters(loginLimiter, resetLimiter, signupLimiter),
		handler.WithIPRateLimiters(loginIPLimiter, resetIPLimiter, signupIPLimiter),
		handler.WithOAuthIPLimiters(oauthIPLimiter),
	}
	if oauthOpt != nil {
		handlerOpts = append(handlerOpts, oauthOpt)
	}
	if totpSvc != nil {
		handlerOpts = append(handlerOpts, handler.WithTotpService(totpSvc))
	}
	if totpLimiter != nil {
		handlerOpts = append(handlerOpts, handler.WithTotpLimiter(totpLimiter))
	}
	h := handler.New(nil, cfg, authSvc, handlerOpts...)

	a := &Auth{
		store: store,
		cfg:   cfg,
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
		OAuth:           oauthSvc,
		TOTP:            totpSvc,
		SessionHandler:  sessHandler,
		loginLimiter:    loginLimiter,
		loginIPLimiter:  loginIPLimiter,
		resetLimiter:    resetLimiter,
		resetIPLimiter:  resetIPLimiter,
		signupLimiter:   signupLimiter,
		signupIPLimiter: signupIPLimiter,
		totpLimiter:     totpLimiter,
		limiterDone:     limiterDone,
	}
	return a, nil
}

// NewWithDB initializes Auth using an existing GORM database connection.
func NewWithDB(database *gorm.DB, cfg config.Config) (*Auth, error) {
	adapter := gormstore.New(database)
	a, err := NewWithStore(adapter, cfg)
	if err != nil {
		return nil, err
	}
	a.db = database
	return a, nil
}

// New validates runtime configuration, establishes database connectivity,
// runs pending migrations, and initializes the HTTP handler chain.
func New(cfg config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidConfig, "goauth: invalid configuration")
	}

	switch cfg.DatabaseType {
	case config.DatabaseTypePostgres, "", config.DatabaseTypeMySQL:
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
	case config.DatabaseTypeMongo, "mongo":
		store, err := mongoConnectFn(cfg)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "goauth: failed to connect to mongodb")
		}
		return NewWithStore(store, cfg)
	default:
		return nil, errors.Wrap(errors.ErrDatabaseUnsupported, errors.CodeDatabaseUnsupported, "unsupported database type: "+string(cfg.DatabaseType))
	}
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
		if a.totpLimiter != nil {
			a.totpLimiter.Close()
		}
		if a.emailDispatcher != nil {
			timeout := a.cfg.EmailDispatchTimeout
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := a.emailDispatcher.Shutdown(ctx); err != nil && a.closeErr == nil {
				a.closeErr = err
			}
		}
		if a.store != nil {
			if err := a.store.Close(); err != nil && a.closeErr == nil {
				a.closeErr = err
			}
		} else if a.db != nil {
			if sqlDB, err := a.db.DB(); err != nil {
				if a.closeErr == nil {
					a.closeErr = errors.New(errors.CodeDatabaseError, "failed to get sql.DB", err)
				}
			} else if err := sqlDB.Close(); err != nil {
				if a.closeErr == nil {
					a.closeErr = errors.New(errors.CodeDatabaseError, "failed to close database", err)
				}
			}
		}
	})
	return a.closeErr
}

// Store returns the underlying storage abstraction implementation.
func (a *Auth) Store() db.Store {
	if a == nil {
		return nil
	}
	return a.store
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

// OAuthService returns the configured OAuth service.
func (a *Auth) OAuthService() oauth.Service {
	return a.OAuth
}

// Totp returns the configured TOTP two-factor authentication service.
func (a *Auth) Totp() totp.Service {
	if a == nil {
		return nil
	}
	return a.TOTP
}

// TotpService returns the configured TOTP two-factor authentication service.
func (a *Auth) TotpService() totp.Service {
	if a == nil {
		return nil
	}
	return a.TOTP
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
