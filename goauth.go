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
	DB      *gorm.DB
	Config  config.Config
	Handler http.Handler
}

// New establishes database connectivity, runs migrations, and initializes the HTTP handler chain.
func New(cfg config.Config) (*Auth, error) {
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
