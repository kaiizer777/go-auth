// Package goauth provides a composable, modular authentication library for Go.
//
// All core implementations are encapsulated in subpackages. The root package serves
// as the public facade and configuration entrypoint.
package goauth

import (
	"context"
	"log/slog"
	"net/http"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/handler"
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
}

// New validates runtime configuration, establishes database connectivity,
// runs pending migrations, and initializes the HTTP handler chain.
func New(cfg config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidConfig, "goauth: invalid configuration")
	}

	database, err := db.Connect(cfg)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "goauth: failed to connect to database")
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

	h := handler.New(database, cfg, authSvc)
	return &Auth{
		db:  database,
		cfg: cfg,
		emailDispatcher: email.NewAsyncDispatcher(email.DispatcherConfig{
			BaseURL:                   cfg.BaseURL,
			DisableAsyncEmailDispatch: cfg.DisableAsyncEmailDispatch,
			EmailDispatchTimeout:      cfg.EmailDispatchTimeout,
			SendVerificationEmail:     cfg.SendVerificationEmail,
			SendPasswordResetEmail:    cfg.SendPasswordResetEmail,
		}, slog.Default()),
		Handler: h,
		Auth:    authSvc,
	}, nil
}

// Close terminates the underlying database connection pool.
func (a *Auth) Close() error {
	if a.db == nil {
		return nil
	}
	sqlDB, err := a.db.DB()
	if err != nil {
		return errors.New(errors.CodeDatabaseError, "failed to get sql.DB", err)
	}
	if err := sqlDB.Close(); err != nil {
		return errors.New(errors.CodeDatabaseError, "failed to close database", err)
	}
	return nil
}

// EmailDispatcher returns the configured email dispatcher.
func (a *Auth) EmailDispatcher() email.Dispatcher {
	if a == nil || a.emailDispatcher == nil {
		return nil
	}
	return a.emailDispatcher
}
