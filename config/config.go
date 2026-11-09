package config

import (
	"errors"
	"time"
)

// Config holds all database, CORS, and connection pool settings.
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
}

// DefaultConfig returns safe default settings. AllowedOrigins is intentionally
// empty so callers must explicitly declare trusted origins.
func DefaultConfig() Config {
	return Config{
		MigrationsPath:  "db/migrations",
		MaxOpenConns:    25,
		MaxIdleConns:    10,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: 30 * time.Minute,
		AllowedMethods:  []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:  []string{"Authorization", "Content-Type"},
	}
}

// Validate ensures required fields are set and connection parameters are sane.
func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return errors.New("database URL is required")
	}
	if c.MigrationsPath == "" {
		c.MigrationsPath = "db/migrations"
	}
	if c.MaxOpenConns < 0 {
		return errors.New("max open conns cannot be negative")
	}
	if c.MaxIdleConns < 0 {
		return errors.New("max idle conns cannot be negative")
	}
	if c.MaxOpenConns > 0 && c.MaxIdleConns > c.MaxOpenConns {
		return errors.New("max idle conns cannot exceed max open conns")
	}
	if c.ConnMaxLifetime < 0 {
		return errors.New("conn max lifetime cannot be negative")
	}
	if c.ConnMaxIdleTime < 0 {
		return errors.New("conn max idle time cannot be negative")
	}
	return nil
}
