// Package goauth provides a composable, modular authentication library for Go.
//
// All core implementations are encapsulated in subpackages. The root package serves
// as the public facade and configuration entrypoint.
package goauth

import (
	"fmt"
	"net/http"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/handler"
)

// Auth is the main entry point for the authentication library.
type Auth struct {
	// DB is the underlying GORM database handle.
	DB *gorm.DB
	// Config contains the validated runtime configuration.
	Config config.Config
	// Handler is the root HTTP handler with mounted routes and middleware.
	Handler http.Handler
}

// New validates runtime configuration, establishes database connectivity,
// runs pending migrations, and initializes the HTTP handler chain.
func New(cfg config.Config) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("goauth: invalid configuration: %w", err)
	}

	database, err := db.Connect(cfg)
	if err != nil {
		return nil, fmt.Errorf("goauth: failed to connect to database: %w", err)
	}

	h := handler.New(database, cfg)
	return &Auth{
		DB:      database,
		Config:  cfg,
		Handler: h,
	}, nil
}
