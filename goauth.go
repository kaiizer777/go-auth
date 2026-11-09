// Package goauth provides a composable, modular authentication library for Go.
//
// All core implementations are encapsulated in subpackages. The root package serves
// as the public facade and configuration entrypoint.
package goauth

import (
	"net/http"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
	"github.com/kaiizer777/go-auth/handler"
)

// Auth is the main entry point for the authentication library.
type Auth struct {
	db  *gorm.DB
	cfg config.Config

	// Handler is the root HTTP handler with mounted routes and middleware.
	Handler http.Handler
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

	h := handler.New(database, cfg)
	return &Auth{
		db:      database,
		cfg:     cfg,
		Handler: h,
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
