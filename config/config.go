package config

import (
	"net/url"
	"strings"
	"time"

	"github.com/kaiizer777/go-auth/email"
	"github.com/kaiizer777/go-auth/errors"
)

// Re-exported payload and hook types owned by email package.
type VerificationEmailPayload = email.VerificationEmailPayload
type PasswordResetEmailPayload = email.PasswordResetEmailPayload
type SendVerificationEmailFunc = email.SendVerificationEmailFunc
type SendPasswordResetEmailFunc = email.SendPasswordResetEmailFunc

// Config holds all database, CORS, connection pool, and email hook settings.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL string
	// MigrationsPath is the path to database migration files or empty for embedded defaults.
	MigrationsPath string

	// AllowedOrigins specifies trusted origins for CORS headers.
	AllowedOrigins []string
	// AllowedMethods specifies HTTP methods permitted during CORS preflight.
	AllowedMethods []string
	// AllowedHeaders specifies HTTP headers permitted during CORS preflight.
	AllowedHeaders []string

	// MaxOpenConns sets the maximum number of open connections to the database.
	MaxOpenConns int
	// MaxIdleConns sets the maximum number of connections in the idle pool.
	MaxIdleConns int
	// ConnMaxLifetime sets the maximum amount of time a connection may be reused.
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime sets the maximum amount of time a connection may remain idle.
	ConnMaxIdleTime time.Duration

	// BaseURL is the public URL used to construct verification and password reset links.
	// Must be non-empty; Config.Validate() returns ErrBaseURLRequired if empty.
	BaseURL string

	// Email delivery hooks (provided by host app)
	SendVerificationEmail  SendVerificationEmailFunc
	SendPasswordResetEmail SendPasswordResetEmailFunc

	// DisableAsyncEmailDispatch opts out of background non-blocking execution.
	DisableAsyncEmailDispatch bool
	// EmailDispatchTimeout max duration for email callback execution (default: 10s).
	EmailDispatchTimeout time.Duration
}

// DefaultConfig returns safe default settings. AllowedOrigins is intentionally
// empty so callers must explicitly declare trusted origins.
func DefaultConfig() Config {
	return Config{
		MigrationsPath:       "db/migrations",
		MaxOpenConns:         25,
		MaxIdleConns:         10,
		ConnMaxLifetime:      time.Hour,
		ConnMaxIdleTime:      30 * time.Minute,
		AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:       []string{"Authorization", "Content-Type"},
		EmailDispatchTimeout: 10 * time.Second,
	}
}

// Validate ensures required fields are set and connection parameters are sane.
func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.ErrDatabaseURLRequired
	}
	if c.BaseURL == "" {
		return errors.ErrBaseURLRequired
	}
	baseURL, err := url.Parse(c.BaseURL)
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") {
		return errors.ErrBaseURLRequired
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.MigrationsPath == "" {
		c.MigrationsPath = "db/migrations"
	}
	if c.MaxOpenConns < 0 {
		return errors.ErrMaxOpenConnsNegative
	}
	if c.MaxIdleConns < 0 {
		return errors.ErrMaxIdleConnsNegative
	}
	if c.MaxOpenConns > 0 && c.MaxIdleConns > c.MaxOpenConns {
		return errors.ErrMaxIdleExceedsOpen
	}
	if c.ConnMaxLifetime < 0 {
		return errors.ErrConnMaxLifetimeNegative
	}
	if c.ConnMaxIdleTime < 0 {
		return errors.ErrConnMaxIdleTimeNegative
	}
	if c.EmailDispatchTimeout < 0 {
		return errors.ErrEmailDispatchTimeoutNegative
	}
	if c.EmailDispatchTimeout == 0 {
		c.EmailDispatchTimeout = 10 * time.Second
	}
	return nil
}
