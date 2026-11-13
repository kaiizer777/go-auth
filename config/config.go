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

// Argon2Config defines cryptographic parameters for Argon2id password hashing.
type Argon2Config struct {
	Memory      uint32 // KiB per hash. Min: 19456. Default: 65536 (64 MiB)
	Time        uint32 // Iterations. Min: 2. Default: 3
	Parallelism uint8  // Threads. Min: 1. Default: 4
	SaltLength  uint32 // Bytes. Min: 16. Default: 16
	KeyLength   uint32 // Output bytes. Min: 32. Default: 32
}

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
	// Must be non-empty; Config.Validate() returns ErrBaseURLRequired if empty and
	// ErrBaseURLInvalid if it is not a well-formed http/https URL.
	BaseURL string

	// Email delivery hooks (provided by host app)
	SendVerificationEmail  SendVerificationEmailFunc
	SendPasswordResetEmail SendPasswordResetEmailFunc

	// DisableAsyncEmailDispatch opts out of background non-blocking execution.
	DisableAsyncEmailDispatch bool
	// EmailDispatchTimeout max duration for email callback execution (default: 10s).
	EmailDispatchTimeout time.Duration

	// Argon2 holds parameters for password hashing.
	Argon2 Argon2Config

	// PasswordMinLength specifies minimum allowed password length in Unicode code points. Min: 8. Default: 8.
	PasswordMinLength uint
	// PasswordMaxLength specifies maximum allowed password length in Unicode code points. Max: 128. Default: 128.
	PasswordMaxLength uint

	// RequireEmailVerification blocks login for unverified accounts when true.
	RequireEmailVerification bool
	// VerificationTokenExpiry defines the lifetime of email verification tokens [15m..60m]. Default: 30m.
	VerificationTokenExpiry time.Duration
	// PasswordResetTokenExpiry defines the lifetime of password reset tokens [15m..60m]. Default: 30m.
	PasswordResetTokenExpiry time.Duration

	// EmailHooks holds optional callbacks for transactional email events.
	EmailHooks email.Hooks
}

// DefaultConfig returns safe default settings. AllowedOrigins is intentionally
// empty so callers must explicitly declare trusted origins.
func DefaultConfig() Config {
	return Config{
		MigrationsPath:           "db/migrations",
		MaxOpenConns:             25,
		MaxIdleConns:             10,
		ConnMaxLifetime:          time.Hour,
		ConnMaxIdleTime:          30 * time.Minute,
		AllowedMethods:           []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:           []string{"Authorization", "Content-Type"},
		EmailDispatchTimeout:     10 * time.Second,
		Argon2: Argon2Config{
			Memory:      65536,
			Time:        3,
			Parallelism: 4,
			SaltLength:  16,
			KeyLength:   32,
		},
		PasswordMinLength:        8,
		PasswordMaxLength:        128,
		RequireEmailVerification: false,
		VerificationTokenExpiry:  30 * time.Minute,
		PasswordResetTokenExpiry: 30 * time.Minute,
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
		return errors.ErrBaseURLInvalid
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	for i, origin := range c.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			c.AllowedOrigins[i] = "*"
			continue
		}
		origin = strings.TrimRight(origin, "/")
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.ErrAllowedOriginInvalid
		}
		c.AllowedOrigins[i] = origin
	}
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

	if c.Argon2.Memory == 0 {
		c.Argon2.Memory = 65536
	}
	if c.Argon2.Time == 0 {
		c.Argon2.Time = 3
	}
	if c.Argon2.Parallelism == 0 {
		c.Argon2.Parallelism = 4
	}
	if c.Argon2.SaltLength == 0 {
		c.Argon2.SaltLength = 16
	}
	if c.Argon2.KeyLength == 0 {
		c.Argon2.KeyLength = 32
	}
	if c.Argon2.Memory < 19456 {
		return errors.ErrArgon2MemoryTooLow
	}
	if c.Argon2.Time < 2 {
		return errors.ErrArgon2TimeTooLow
	}
	if c.Argon2.Parallelism < 1 {
		return errors.ErrArgon2ParallelismZero
	}
	if c.Argon2.SaltLength < 16 {
		return errors.ErrArgon2SaltLengthTooShort
	}
	if c.Argon2.KeyLength < 32 {
		return errors.ErrArgon2KeyLengthTooShort
	}

	if c.PasswordMinLength == 0 {
		c.PasswordMinLength = 8
	}
	if c.PasswordMaxLength == 0 {
		c.PasswordMaxLength = 128
	}
	if c.PasswordMinLength < 8 {
		return errors.ErrPasswordMinLengthTooShort
	}
	if c.PasswordMaxLength <= c.PasswordMinLength || c.PasswordMaxLength > 128 {
		return errors.ErrPasswordMaxLengthInvalid
	}

	if c.VerificationTokenExpiry == 0 {
		c.VerificationTokenExpiry = 30 * time.Minute
	} else if c.VerificationTokenExpiry < 15*time.Minute || c.VerificationTokenExpiry > 60*time.Minute {
		return errors.ErrVerificationTokenExpiryInvalid
	}

	if c.PasswordResetTokenExpiry == 0 {
		c.PasswordResetTokenExpiry = 30 * time.Minute
	} else if c.PasswordResetTokenExpiry < 15*time.Minute || c.PasswordResetTokenExpiry > 60*time.Minute {
		return errors.ErrPasswordResetTokenExpiryInvalid
	}
	return nil
}
