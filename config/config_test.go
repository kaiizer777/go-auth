package config

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/errors"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MigrationsPath != "db/migrations" {
		t.Errorf("got %q, want %q", cfg.MigrationsPath, "db/migrations")
	}
	if cfg.MaxOpenConns != 25 {
		t.Errorf("got %d, want 25", cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns != 10 {
		t.Errorf("got %d, want 10", cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime != time.Hour {
		t.Errorf("got %v, want 1h", cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime != 30*time.Minute {
		t.Errorf("got %v, want 30m", cfg.ConnMaxIdleTime)
	}
	if len(cfg.AllowedOrigins) != 0 {
		t.Errorf("expected empty AllowedOrigins, got %v", cfg.AllowedOrigins)
	}
	if len(cfg.AllowedMethods) == 0 {
		t.Error("expected non-empty AllowedMethods")
	}
	if len(cfg.AllowedHeaders) == 0 {
		t.Error("expected non-empty AllowedHeaders")
	}
	if cfg.Argon2.Memory != 65536 {
		t.Errorf("got %d, want 65536", cfg.Argon2.Memory)
	}
	if cfg.Argon2.Time != 3 {
		t.Errorf("got %d, want 3", cfg.Argon2.Time)
	}
	if cfg.Argon2.Parallelism != 4 {
		t.Errorf("got %d, want 4", cfg.Argon2.Parallelism)
	}
	if cfg.Argon2.SaltLength != 16 {
		t.Errorf("got %d, want 16", cfg.Argon2.SaltLength)
	}
	if cfg.Argon2.KeyLength != 32 {
		t.Errorf("got %d, want 32", cfg.Argon2.KeyLength)
	}
	if cfg.PasswordMinLength != 8 {
		t.Errorf("got %d, want 8", cfg.PasswordMinLength)
	}
	if cfg.PasswordMaxLength != 128 {
		t.Errorf("got %d, want 128", cfg.PasswordMaxLength)
	}
	if cfg.RequireEmailVerification {
		t.Errorf("expected RequireEmailVerification false, got true")
	}
	if cfg.VerificationTokenExpiry != 30*time.Minute {
		t.Errorf("got %v, want 30m", cfg.VerificationTokenExpiry)
	}
	if cfg.PasswordResetTokenExpiry != 30*time.Minute {
		t.Errorf("got %v, want 30m", cfg.PasswordResetTokenExpiry)
	}
}

func TestConfigValidate_ZeroValueUsesAsyncEmailDispatch(t *testing.T) {
	cfg := Config{
		DatabaseURL:           "postgres://user:pass@localhost:5432/testdb",
		BaseURL:               "https://example.com",
		SessionIdleTimeout:    30 * time.Minute,
		SessionAbsoluteMaxAge: 24 * time.Hour,
		RateLimitLoginMax:     10,
		RateLimitResetMax:     5,
		RateLimitSignupMax:    10,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err = %v", err)
	}
	if cfg.DisableAsyncEmailDispatch {
		t.Fatal("zero-value config disabled async email dispatch")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name               string
		mutate             func(*Config)
		wantErr            error
		notWantErr         error
		wantMigrationsPath string
	}{
		{
			name: "valid configuration",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
			},
			wantErr:            nil,
			wantMigrationsPath: "db/migrations",
		},
		{
			name: "missing database URL",
			mutate: func(c *Config) {
				c.DatabaseURL = ""
			},
			wantErr: errors.ErrDatabaseURLRequired,
		},
		{
			name: "missing base URL",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = ""
			},
			wantErr:    errors.ErrBaseURLRequired,
			notWantErr: errors.ErrBaseURLInvalid,
		},
		{
			name: "negative max open connections",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxOpenConns = -1
			},
			wantErr: errors.ErrMaxOpenConnsNegative,
		},
		{
			name: "negative max idle connections",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxIdleConns = -1
			},
			wantErr: errors.ErrMaxIdleConnsNegative,
		},
		{
			name: "max idle exceeds max open",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxOpenConns = 5
				c.MaxIdleConns = 10
			},
			wantErr: errors.ErrMaxIdleExceedsOpen,
		},
		{
			name: "max open zero permits positive max idle (unlimited connections)",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxOpenConns = 0
				c.MaxIdleConns = 10
			},
			wantErr: nil,
		},
		{
			name: "max open equals max idle at boundary",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MaxOpenConns = 10
				c.MaxIdleConns = 10
			},
			wantErr: nil,
		},
		{
			name: "invalid base URL",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "example.com"
			},
			wantErr:    errors.ErrBaseURLInvalid,
			notWantErr: errors.ErrBaseURLRequired,
		},
		{
			name: "base URL with unparsable value",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = ":not-a-url"
			},
			wantErr:    errors.ErrBaseURLInvalid,
			notWantErr: errors.ErrBaseURLRequired,
		},
		{
			name: "base URL with non-http scheme",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "ftp://example.com"
			},
			wantErr:    errors.ErrBaseURLInvalid,
			notWantErr: errors.ErrBaseURLRequired,
		},
		{
			name: "base URL trailing slash removed",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com/"
			},
			wantErr: nil,
		},
		{
			name: "negative conn max lifetime",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.ConnMaxLifetime = -time.Second
			},
			wantErr: errors.ErrConnMaxLifetimeNegative,
		},
		{
			name: "negative conn max idle time",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.ConnMaxIdleTime = -time.Second
			},
			wantErr: errors.ErrConnMaxIdleTimeNegative,
		},
		{
			name: "negative email dispatch timeout",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.EmailDispatchTimeout = -time.Second
			},
			wantErr: errors.ErrEmailDispatchTimeoutNegative,
		},
		{
			name: "zero durations permitted as no-limit",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.ConnMaxLifetime = 0
				c.ConnMaxIdleTime = 0
			},
			wantErr:            nil,
			wantMigrationsPath: "db/migrations",
		},
		{
			name: "zero email dispatch timeout uses default",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.EmailDispatchTimeout = 0
			},
			wantErr: nil,
		},
		{
			name: "empty migrations path falls back to default",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MigrationsPath = ""
			},
			wantErr:            nil,
			wantMigrationsPath: "db/migrations",
		},
		{
			name: "custom migrations path preserved",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.MigrationsPath = "custom/migrations"
			},
			wantErr:            nil,
			wantMigrationsPath: "custom/migrations",
		},
		{
			name: "zero value struct defaults all phase 3 settings",
			mutate: func(c *Config) {
				*c = Config{
					DatabaseURL:           "postgres://user:pass@localhost:5432/testdb",
					BaseURL:               "https://example.com",
					SessionIdleTimeout:    30 * time.Minute,
					SessionAbsoluteMaxAge: 24 * time.Hour,
					RateLimitLoginMax:     10,
					RateLimitResetMax:     5,
					RateLimitSignupMax:    10,
				}
			},
			wantErr:            nil,
			wantMigrationsPath: "db/migrations",
		},
		{
			name: "argon2 memory too low",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.Memory = 19455
			},
			wantErr: errors.ErrArgon2MemoryTooLow,
		},
		{
			name: "argon2 memory at boundary",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.Memory = 19456
			},
			wantErr: nil,
		},
		{
			name: "argon2 time too low",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.Time = 1
			},
			wantErr: errors.ErrArgon2TimeTooLow,
		},
		{
			name: "argon2 time at boundary",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.Time = 2
			},
			wantErr: nil,
		},
		{
			name: "argon2 parallelism zero uses default",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.Parallelism = 0
			},
			wantErr: nil,
		},
		{
			name: "argon2 parallelism at boundary",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.Parallelism = 1
			},
			wantErr: nil,
		},
		{
			name: "argon2 salt length too short",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.SaltLength = 15
			},
			wantErr: errors.ErrArgon2SaltLengthTooShort,
		},
		{
			name: "argon2 salt length at boundary",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.SaltLength = 16
			},
			wantErr: nil,
		},
		{
			name: "argon2 key length too short",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.KeyLength = 31
			},
			wantErr: errors.ErrArgon2KeyLengthTooShort,
		},
		{
			name: "argon2 key length at boundary",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.KeyLength = 32
			},
			wantErr: nil,
		},
		{
			name: "password min length too short",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordMinLength = 7
			},
			wantErr: errors.ErrPasswordMinLengthTooShort,
		},
		{
			name: "password max length less than min length",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordMinLength = 10
				c.PasswordMaxLength = 9
			},
			wantErr: errors.ErrPasswordMaxLengthInvalid,
		},
		{
			name: "password max length equal to min length",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordMinLength = 10
				c.PasswordMaxLength = 10
			},
			wantErr: errors.ErrPasswordMaxLengthInvalid,
		},
		{
			name: "password max length exceeds 128",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordMaxLength = 129
			},
			wantErr: errors.ErrPasswordMaxLengthInvalid,
		},
		{
			name: "password limits at boundary",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordMinLength = 8
				c.PasswordMaxLength = 128
			},
			wantErr: nil,
		},
		{
			name: "verification token expiry below 15m",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.VerificationTokenExpiry = 14 * time.Minute
			},
			wantErr: errors.ErrVerificationTokenExpiryInvalid,
		},
		{
			name: "verification token expiry above 60m",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.VerificationTokenExpiry = 61 * time.Minute
			},
			wantErr: errors.ErrVerificationTokenExpiryInvalid,
		},
		{
			name: "verification token expiry boundaries valid",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.VerificationTokenExpiry = 15 * time.Minute
			},
			wantErr: nil,
		},
		{
			name: "password reset token expiry below 15m",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordResetTokenExpiry = 14 * time.Minute
			},
			wantErr: errors.ErrPasswordResetTokenExpiryInvalid,
		},
		{
			name: "password reset token expiry above 60m",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordResetTokenExpiry = 61 * time.Minute
			},
			wantErr: errors.ErrPasswordResetTokenExpiryInvalid,
		},
		{
			name: "password reset token expiry boundaries valid",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.PasswordResetTokenExpiry = 60 * time.Minute
			},
			wantErr: nil,
		},
		{
			name: "allowed origins valid with trimming",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.AllowedOrigins = []string{" https://app.example.com/ ", "*", "http://localhost:3000"}
			},
			wantErr: nil,
		},
		{
			name: "allowed origins invalid without scheme",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.AllowedOrigins = []string{"app.example.com"}
			},
			wantErr: errors.ErrAllowedOriginInvalid,
		},
		{
			name: "allowed origins invalid with non-http scheme",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.AllowedOrigins = []string{"ftp://app.example.com"}
			},
			wantErr: errors.ErrAllowedOriginInvalid,
		},
		{
			name: "allowed origins invalid with path",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.AllowedOrigins = []string{"https://app.example.com/api"}
			},
			wantErr: errors.ErrAllowedOriginInvalid,
		},
		{
			name: "allowed origins invalid empty string",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.AllowedOrigins = []string{""}
			},
			wantErr: errors.ErrAllowedOriginInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Validate() unexpected err = %v", err)
			}
			if tt.notWantErr != nil && errors.Is(err, tt.notWantErr) {
				t.Fatalf("Validate() err = %v, must not match %v", err, tt.notWantErr)
			}
			if tt.wantErr == nil && tt.wantMigrationsPath != "" && cfg.MigrationsPath != tt.wantMigrationsPath {
				t.Errorf("got migrations path %q, want %q", cfg.MigrationsPath, tt.wantMigrationsPath)
			}
			if tt.name == "zero email dispatch timeout uses default" && cfg.EmailDispatchTimeout != 10*time.Second {
				t.Errorf("got email dispatch timeout %v, want 10s", cfg.EmailDispatchTimeout)
			}
			if tt.name == "base URL trailing slash removed" && cfg.BaseURL != "https://example.com" {
				t.Errorf("got base URL %q, want %q", cfg.BaseURL, "https://example.com")
			}
			if tt.name == "argon2 parallelism zero uses default" && cfg.Argon2.Parallelism != 4 {
				t.Errorf("got parallelism %d, want 4", cfg.Argon2.Parallelism)
			}
			if tt.name == "allowed origins valid with trimming" {
				if cfg.AllowedOrigins[0] != "https://app.example.com" {
					t.Errorf("got origin %q, want https://app.example.com", cfg.AllowedOrigins[0])
				}
				if cfg.AllowedOrigins[1] != "*" {
					t.Errorf("got origin %q, want *", cfg.AllowedOrigins[1])
				}
				if cfg.AllowedOrigins[2] != "http://localhost:3000" {
					t.Errorf("got origin %q, want http://localhost:3000", cfg.AllowedOrigins[2])
				}
			}
		})
	}
}

func TestConfigValidate_PartialArgon2Overrides(t *testing.T) {
	cfg := Config{
		DatabaseURL:           "postgres://user:pass@localhost:5432/testdb",
		BaseURL:               "https://example.com",
		SessionIdleTimeout:    30 * time.Minute,
		SessionAbsoluteMaxAge: 24 * time.Hour,
		RateLimitLoginMax:     10,
		RateLimitResetMax:     5,
		RateLimitSignupMax:    10,
		Argon2: Argon2Config{
			Memory: 32768,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if cfg.Argon2.Memory != 32768 {
		t.Errorf("got Memory %d, want 32768", cfg.Argon2.Memory)
	}
	if cfg.Argon2.Time != 3 {
		t.Errorf("got Time %d, want 3", cfg.Argon2.Time)
	}
	if cfg.Argon2.Parallelism != 4 {
		t.Errorf("got Parallelism %d, want 4", cfg.Argon2.Parallelism)
	}
	if cfg.Argon2.SaltLength != 16 {
		t.Errorf("got SaltLength %d, want 16", cfg.Argon2.SaltLength)
	}
	if cfg.Argon2.KeyLength != 32 {
		t.Errorf("got KeyLength %d, want 32", cfg.Argon2.KeyLength)
	}
}

func TestConfigValidate_MaxOpenConnsZeroUnlimited(t *testing.T) {
	cfg := Config{
		DatabaseURL:           "postgres://user:pass@localhost:5432/testdb",
		BaseURL:               "https://example.com",
		SessionIdleTimeout:    30 * time.Minute,
		SessionAbsoluteMaxAge: 24 * time.Hour,
		RateLimitLoginMax:     10,
		RateLimitResetMax:     5,
		RateLimitSignupMax:    10,
		MaxOpenConns:          0,
		MaxIdleConns:          50,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err for MaxOpenConns=0 and MaxIdleConns=50: %v", err)
	}
	if cfg.MaxOpenConns != 0 {
		t.Fatalf("cfg.MaxOpenConns = %d; want 0", cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns != 50 {
		t.Fatalf("cfg.MaxIdleConns = %d; want 50", cfg.MaxIdleConns)
	}
}

func TestConfigValidate_EmailDispatchTimeoutRetention(t *testing.T) {
	cfg := Config{
		DatabaseURL:           "postgres://user:pass@localhost:5432/testdb",
		BaseURL:               "https://example.com",
		SessionIdleTimeout:    30 * time.Minute,
		SessionAbsoluteMaxAge: 24 * time.Hour,
		RateLimitLoginMax:     10,
		RateLimitResetMax:     5,
		RateLimitSignupMax:    10,
		EmailDispatchTimeout: 5 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err = %v", err)
	}
	if cfg.EmailDispatchTimeout != 5*time.Second {
		t.Fatalf("EmailDispatchTimeout = %v; want 5s", cfg.EmailDispatchTimeout)
	}
}

func TestConfigValidate_EmailDispatchTimeoutDefault(t *testing.T) {
	cfg := Config{
		DatabaseURL:           "postgres://user:pass@localhost:5432/testdb",
		BaseURL:               "https://example.com",
		SessionIdleTimeout:    30 * time.Minute,
		SessionAbsoluteMaxAge: 24 * time.Hour,
		RateLimitLoginMax:     10,
		RateLimitResetMax:     5,
		RateLimitSignupMax:    10,
		EmailDispatchTimeout: 0,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err = %v", err)
	}
	if cfg.EmailDispatchTimeout != 10*time.Second {
		t.Fatalf("EmailDispatchTimeout = %v; want 10s", cfg.EmailDispatchTimeout)
	}
}

func TestConfig_SessionDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.SessionIdleTimeout != 30*time.Minute {
		t.Errorf("SessionIdleTimeout = %v; want 30m", cfg.SessionIdleTimeout)
	}
	if cfg.SessionAbsoluteMaxAge != 24*time.Hour {
		t.Errorf("SessionAbsoluteMaxAge = %v; want 24h", cfg.SessionAbsoluteMaxAge)
	}
	if cfg.SessionCookieName != "sid" {
		t.Errorf("SessionCookieName = %q; want %q", cfg.SessionCookieName, "sid")
	}
	if cfg.SessionCookieDomain != "" {
		t.Errorf("SessionCookieDomain = %q; want empty string", cfg.SessionCookieDomain)
	}
	if cfg.SessionCookiePath != "/" {
		t.Errorf("SessionCookiePath = %q; want %q", cfg.SessionCookiePath, "/")
	}
	if !cfg.SessionCookieSecure {
		t.Errorf("SessionCookieSecure = %v; want true", cfg.SessionCookieSecure)
	}
	if cfg.SessionCookieSameSite != http.SameSiteLaxMode {
		t.Errorf("SessionCookieSameSite = %v; want %v", cfg.SessionCookieSameSite, http.SameSiteLaxMode)
	}
	if cfg.CSRFCookieName != "csrf_token" {
		t.Errorf("CSRFCookieName = %q; want %q", cfg.CSRFCookieName, "csrf_token")
	}
	if cfg.CSRFHeaderName != "X-CSRF-Token" {
		t.Errorf("CSRFHeaderName = %q; want %q", cfg.CSRFHeaderName, "X-CSRF-Token")
	}
	if cfg.RateLimitLoginWindow != 15*time.Minute {
		t.Errorf("RateLimitLoginWindow = %v; want 15m", cfg.RateLimitLoginWindow)
	}
	if cfg.RateLimitLoginMax != 10 {
		t.Errorf("RateLimitLoginMax = %d; want 10", cfg.RateLimitLoginMax)
	}
	if cfg.RateLimitResetWindow != 15*time.Minute {
		t.Errorf("RateLimitResetWindow = %v; want 15m", cfg.RateLimitResetWindow)
	}
	if cfg.RateLimitResetMax != 5 {
		t.Errorf("RateLimitResetMax = %d; want 5", cfg.RateLimitResetMax)
	}
	if cfg.RateLimitSignupWindow != 15*time.Minute {
		t.Errorf("RateLimitSignupWindow = %v; want 15m", cfg.RateLimitSignupWindow)
	}
	if cfg.RateLimitSignupMax != 10 {
		t.Errorf("RateLimitSignupMax = %d; want 10", cfg.RateLimitSignupMax)
	}
	if cfg.RateLimitCleanupTick != 5*time.Minute {
		t.Errorf("RateLimitCleanupTick = %v; want 5m", cfg.RateLimitCleanupTick)
	}
}

func TestConfig_SessionIdleTimeoutZero_Panics(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionIdleTimeout = 0

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on zero SessionIdleTimeout, got nil")
		}
		msg, ok := r.(string)
		if !ok || msg != "SessionIdleTimeout must be greater than zero" {
			t.Fatalf("panic message = %v; want %q", r, "SessionIdleTimeout must be greater than zero")
		}
	}()

	_ = cfg.Validate()
}

func TestConfig_AbsoluteLessThanIdle_Panics(t *testing.T) {
	tests := []struct {
		name        string
		idleTimeout time.Duration
		absoluteAge time.Duration
	}{
		{
			name:        "absolute age strictly less than idle timeout",
			idleTimeout: 30 * time.Minute,
			absoluteAge: 15 * time.Minute,
		},
		{
			name:        "absolute age equal to idle timeout",
			idleTimeout: 30 * time.Minute,
			absoluteAge: 30 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
			cfg.BaseURL = "https://example.com"
			cfg.SessionIdleTimeout = tt.idleTimeout
			cfg.SessionAbsoluteMaxAge = tt.absoluteAge

			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected panic when SessionAbsoluteMaxAge <= SessionIdleTimeout, got nil")
				}
				msg, ok := r.(string)
				if !ok || msg != "SessionAbsoluteMaxAge must be greater than SessionIdleTimeout" {
					t.Fatalf("panic message = %v; want %q", r, "SessionAbsoluteMaxAge must be greater than SessionIdleTimeout")
				}
			}()

			_ = cfg.Validate()
		})
	}
}

func TestConfig_SessionCookieSecureFalse_Warns(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	logger := slog.New(handler)
	prev := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() {
		slog.SetDefault(prev)
	})

	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionCookieSecure = false

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SessionCookieSecure is false — not safe for production") {
		t.Fatalf("expected warning log in output, got %q", output)
	}
	if !strings.Contains(output, "level=WARN") {
		t.Fatalf("expected level=WARN in log output, got %q", output)
	}
}

func TestConfig_RateLimitMax_Panics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name:   "RateLimitLoginMax zero",
			mutate: func(c *Config) { c.RateLimitLoginMax = 0 },
		},
		{
			name:   "RateLimitLoginMax negative",
			mutate: func(c *Config) { c.RateLimitLoginMax = -1 },
		},
		{
			name:   "RateLimitResetMax zero",
			mutate: func(c *Config) { c.RateLimitResetMax = 0 },
		},
		{
			name:   "RateLimitResetMax negative",
			mutate: func(c *Config) { c.RateLimitResetMax = -2 },
		},
		{
			name:   "RateLimitSignupMax zero",
			mutate: func(c *Config) { c.RateLimitSignupMax = 0 },
		},
		{
			name:   "RateLimitSignupMax negative",
			mutate: func(c *Config) { c.RateLimitSignupMax = -5 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
			cfg.BaseURL = "https://example.com"
			tt.mutate(&cfg)

			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected panic when rate limit max < 1, got nil")
				}
				msg, ok := r.(string)
				if !ok || msg != "rate limit max must be >= 1" {
					t.Fatalf("panic message = %v; want %q", r, "rate limit max must be >= 1")
				}
			}()

			_ = cfg.Validate()
		})
	}
}

func TestConfig_SessionIdleTimeoutNegative_Panics(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionIdleTimeout = -5 * time.Minute

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on negative SessionIdleTimeout, got nil")
		}
		msg, ok := r.(string)
		if !ok || msg != "SessionIdleTimeout must be greater than zero" {
			t.Fatalf("panic message = %v; want %q", r, "SessionIdleTimeout must be greater than zero")
		}
	}()

	_ = cfg.Validate()
}

func TestConfig_RateLimitWindowNegative_Panics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name:   "RateLimitLoginWindow negative",
			mutate: func(c *Config) { c.RateLimitLoginWindow = -1 * time.Minute },
		},
		{
			name:   "RateLimitResetWindow negative",
			mutate: func(c *Config) { c.RateLimitResetWindow = -2 * time.Minute },
		},
		{
			name:   "RateLimitSignupWindow negative",
			mutate: func(c *Config) { c.RateLimitSignupWindow = -3 * time.Minute },
		},
		{
			name:   "RateLimitCleanupTick negative",
			mutate: func(c *Config) { c.RateLimitCleanupTick = -10 * time.Second },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
			cfg.BaseURL = "https://example.com"
			tt.mutate(&cfg)

			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("expected panic on %s, got nil", tt.name)
				}
				msg, ok := r.(string)
				if !ok || msg != "rate limit window and cleanup tick must be greater than zero" {
					t.Fatalf("panic message = %v; want %q", r, "rate limit window and cleanup tick must be greater than zero")
				}
			}()

			_ = cfg.Validate()
		})
	}
}
