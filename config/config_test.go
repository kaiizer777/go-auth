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
	hasCSRFHeader := false
	for _, h := range cfg.AllowedHeaders {
		if h == "X-CSRF-Token" {
			hasCSRFHeader = true
			break
		}
	}
	if !hasCSRFHeader {
		t.Errorf("expected AllowedHeaders to contain X-CSRF-Token, got %v", cfg.AllowedHeaders)
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
		DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
		BaseURL:     "https://example.com",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err = %v", err)
	}
	if cfg.DisableAsyncEmailDispatch {
		t.Fatal("zero-value config disabled async email dispatch")
	}
}

func TestConfigValidate_MinimalStructLiteralDefaults(t *testing.T) {
	cfg := Config{
		DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
		BaseURL:     "https://example.com",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err = %v", err)
	}
	if cfg.SessionIdleTimeout != 30*time.Minute {
		t.Errorf("got SessionIdleTimeout %v, want 30m", cfg.SessionIdleTimeout)
	}
	if cfg.SessionAbsoluteMaxAge != 24*time.Hour {
		t.Errorf("got SessionAbsoluteMaxAge %v, want 24h", cfg.SessionAbsoluteMaxAge)
	}
	if cfg.RateLimitLoginMax != 10 {
		t.Errorf("got RateLimitLoginMax %d, want 10", cfg.RateLimitLoginMax)
	}
	if cfg.RateLimitResetMax != 5 {
		t.Errorf("got RateLimitResetMax %d, want 5", cfg.RateLimitResetMax)
	}
	if cfg.RateLimitSignupMax != 10 {
		t.Errorf("got RateLimitSignupMax %d, want 10", cfg.RateLimitSignupMax)
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
			name: "valid keyword value DSN with host and dbname",
			mutate: func(c *Config) {
				c.DatabaseURL = "host=localhost port=5432 user=alice password=secret dbname=mydb"
				c.BaseURL = "https://example.com"
			},
			wantErr: nil,
		},
		{
			name: "valid keyword value DSN with dbname only",
			mutate: func(c *Config) {
				c.DatabaseURL = "dbname=mydb sslmode=disable"
				c.BaseURL = "https://example.com"
			},
			wantErr: nil,
		},
		{
			name: "invalid database URL string lacking URL scheme and DSN keywords",
			mutate: func(c *Config) {
				c.DatabaseURL = "random-invalid-string"
				c.BaseURL = "https://example.com"
			},
			wantErr: errors.ErrDatabaseURLInvalid,
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
		EmailDispatchTimeout:  5 * time.Second,
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
		EmailDispatchTimeout:  0,
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

func TestConfig_SessionIdleTimeoutZero_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionIdleTimeout = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if cfg.SessionIdleTimeout != 30*time.Minute {
		t.Fatalf("SessionIdleTimeout = %v; want 30m", cfg.SessionIdleTimeout)
	}
}

func TestConfig_AbsoluteLessThanIdle_Error(t *testing.T) {
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

			err := cfg.Validate()
			if !errors.Is(err, errors.ErrSessionAbsoluteMaxAgeInvalid) {
				t.Fatalf("Validate() err = %v; want %v", err, errors.ErrSessionAbsoluteMaxAgeInvalid)
			}
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

func TestConfig_RateLimitMax_Error(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name:   "RateLimitLoginMax negative",
			mutate: func(c *Config) { c.RateLimitLoginMax = -1 },
		},
		{
			name:   "RateLimitResetMax negative",
			mutate: func(c *Config) { c.RateLimitResetMax = -2 },
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

			err := cfg.Validate()
			if !errors.Is(err, errors.ErrRateLimitMaxInvalid) {
				t.Fatalf("Validate() err = %v; want %v", err, errors.ErrRateLimitMaxInvalid)
			}
		})
	}
}

func TestConfig_RateLimitMaxZero_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.RateLimitLoginMax = 0
	cfg.RateLimitResetMax = 0
	cfg.RateLimitSignupMax = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if cfg.RateLimitLoginMax != 10 {
		t.Errorf("got RateLimitLoginMax %d, want 10", cfg.RateLimitLoginMax)
	}
	if cfg.RateLimitResetMax != 5 {
		t.Errorf("got RateLimitResetMax %d, want 5", cfg.RateLimitResetMax)
	}
	if cfg.RateLimitSignupMax != 10 {
		t.Errorf("got RateLimitSignupMax %d, want 10", cfg.RateLimitSignupMax)
	}
}

func TestConfig_SessionIdleTimeoutNegative_Error(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionIdleTimeout = -5 * time.Minute

	err := cfg.Validate()
	if !errors.Is(err, errors.ErrSessionIdleTimeoutInvalid) {
		t.Fatalf("Validate() err = %v; want %v", err, errors.ErrSessionIdleTimeoutInvalid)
	}
}

func TestConfig_RateLimitWindowNegative_Error(t *testing.T) {
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

			err := cfg.Validate()
			if !errors.Is(err, errors.ErrRateLimitWindowInvalid) {
				t.Fatalf("Validate() err = %v; want %v", err, errors.ErrRateLimitWindowInvalid)
			}
		})
	}
}

func TestConfig_SessionCookieSameSiteNoneWithoutSecure_Error(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionCookieSameSite = http.SameSiteNoneMode
	cfg.SessionCookieSecure = false

	err := cfg.Validate()
	if !errors.Is(err, errors.ErrSessionSameSiteNoneInsecure) {
		t.Fatalf("Validate() err = %v; want %v", err, errors.ErrSessionSameSiteNoneInsecure)
	}
}

func TestConfig_SessionCookieSameSiteNoneWithSecure_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	cfg.SessionCookieSameSite = http.SameSiteNoneMode
	cfg.SessionCookieSecure = true

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected err = %v", err)
	}
}

func TestConfig_CookieDefaults_AppliedInValidate(t *testing.T) {
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

	if cfg.SessionCookieName != "sid" {
		t.Errorf("SessionCookieName = %q; want %q", cfg.SessionCookieName, "sid")
	}
	if cfg.SessionCookiePath != "/" {
		t.Errorf("SessionCookiePath = %q; want %q", cfg.SessionCookiePath, "/")
	}
	if cfg.CSRFCookieName != "csrf_token" {
		t.Errorf("CSRFCookieName = %q; want %q", cfg.CSRFCookieName, "csrf_token")
	}
	if cfg.CSRFHeaderName != "X-CSRF-Token" {
		t.Errorf("CSRFHeaderName = %q; want %q", cfg.CSRFHeaderName, "X-CSRF-Token")
	}
	if cfg.SessionCookieSameSite != http.SameSiteLaxMode {
		t.Errorf("SessionCookieSameSite = %v; want %v", cfg.SessionCookieSameSite, http.SameSiteLaxMode)
	}
}

func TestConfig_CookieAndHeaderRFCValidation(t *testing.T) {
	baseCfg := func() Config {
		c := DefaultConfig()
		c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
		c.BaseURL = "https://example.com"
		return c
	}

	t.Run("invalid session cookie name", func(t *testing.T) {
		invalidNames := []string{"bad sid", "sid;name", "sid=val", "sid,name", "sid/name", "sid@domain", "sid{1}"}
		for _, name := range invalidNames {
			cfg := baseCfg()
			cfg.SessionCookieName = name
			err := cfg.Validate()
			if !errors.Is(err, errors.ErrSessionCookieNameInvalid) {
				t.Errorf("Validate(%q) err = %v; want ErrSessionCookieNameInvalid", name, err)
			}
			if !errors.Is(err, errors.ErrInvalidCookieName) {
				t.Errorf("Validate(%q) err = %v; want ErrInvalidCookieName alias", name, err)
			}
		}
	})

	t.Run("valid custom session cookie name", func(t *testing.T) {
		cfg := baseCfg()
		cfg.SessionCookieName = "custom_session-id.v1"
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected err = %v", err)
		}
	})

	t.Run("invalid session cookie path", func(t *testing.T) {
		invalidPaths := []string{"no-leading-slash", "/path;semicolon", "/path\x00null"}
		for _, p := range invalidPaths {
			cfg := baseCfg()
			cfg.SessionCookiePath = p
			err := cfg.Validate()
			if !errors.Is(err, errors.ErrSessionCookiePathInvalid) {
				t.Errorf("Validate(path=%q) err = %v; want ErrSessionCookiePathInvalid", p, err)
			}
			if !errors.Is(err, errors.ErrInvalidCookiePath) {
				t.Errorf("Validate(path=%q) err = %v; want ErrInvalidCookiePath alias", p, err)
			}
		}
	})

	t.Run("valid custom session cookie path", func(t *testing.T) {
		cfg := baseCfg()
		cfg.SessionCookiePath = "/api/v1/auth"
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected err = %v", err)
		}
	})

	t.Run("invalid session cookie domain", func(t *testing.T) {
		invalidDomains := []string{"example .com", "example;com", "example\x00.com"}
		for _, d := range invalidDomains {
			cfg := baseCfg()
			cfg.SessionCookieDomain = d
			err := cfg.Validate()
			if !errors.Is(err, errors.ErrSessionCookieDomainInvalid) {
				t.Errorf("Validate(domain=%q) err = %v; want ErrSessionCookieDomainInvalid", d, err)
			}
		}
	})

	t.Run("invalid CSRF cookie name", func(t *testing.T) {
		invalidNames := []string{"csrf token", "csrf;tok", "csrf@tok", "csrf/token"}
		for _, name := range invalidNames {
			cfg := baseCfg()
			cfg.CSRFCookieName = name
			err := cfg.Validate()
			if !errors.Is(err, errors.ErrCSRFCookieNameInvalid) {
				t.Errorf("Validate(csrf_cookie=%q) err = %v; want ErrCSRFCookieNameInvalid", name, err)
			}
		}
	})

	t.Run("valid custom CSRF cookie name", func(t *testing.T) {
		cfg := baseCfg()
		cfg.CSRFCookieName = "my-csrf_token.v2"
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected err = %v", err)
		}
	})

	t.Run("invalid CSRF header name", func(t *testing.T) {
		invalidHeaders := []string{"Bad Header", "Header:Name", "Header@Name", "Header/Name"}
		for _, h := range invalidHeaders {
			cfg := baseCfg()
			cfg.CSRFHeaderName = h
			err := cfg.Validate()
			if !errors.Is(err, errors.ErrCSRFHeaderNameInvalid) {
				t.Errorf("Validate(csrf_header=%q) err = %v; want ErrCSRFHeaderNameInvalid", h, err)
			}
		}
	})

	t.Run("valid custom CSRF header name", func(t *testing.T) {
		cfg := baseCfg()
		cfg.CSRFHeaderName = "X-App-CSRF-Token"
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() unexpected err = %v", err)
		}
	})
}

func TestConfig_DatabaseURL_Validation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr error
	}{
		{
			name:    "valid postgres scheme with port and db",
			url:     "postgres://user:pass@localhost:5432/mydb",
			wantErr: nil,
		},
		{
			name:    "valid postgresql scheme",
			url:     "postgresql://user:pass@127.0.0.1:5432/mydb?sslmode=disable",
			wantErr: nil,
		},
		{
			name:    "valid postgresql scheme with unix domain socket in host query",
			url:     "postgresql:///mydb?host=/var/run/postgresql",
			wantErr: nil,
		},
		{
			name:    "valid postgres scheme with unix domain socket in socket query",
			url:     "postgres:///mydb?socket=/var/run/postgresql/.s.PGSQL.5432",
			wantErr: nil,
		},
		{
			name:    "valid postgresql scheme with credentials and socket query",
			url:     "postgresql://user:pass@/mydb?host=/var/run/postgresql",
			wantErr: nil,
		},
		{
			name:    "missing host and query socket in postgres url",
			url:     "postgres:///mydb",
			wantErr: errors.ErrDatabaseURLInvalid,
		},
		{
			name:    "empty host query parameter in postgres url",
			url:     "postgresql:///mydb?host=",
			wantErr: errors.ErrDatabaseURLInvalid,
		},
		{
			name:    "empty database URL returns ErrDatabaseURLRequired",
			url:     "",
			wantErr: errors.ErrDatabaseURLRequired,
		},
		{
			name:    "malformed scheme prefix",
			url:     "://bad-url",
			wantErr: errors.ErrDatabaseURLInvalid,
		},
		{
			name:    "unsupported scheme http",
			url:     "http://localhost:5432/mydb",
			wantErr: errors.ErrDatabaseURLInvalid,
		},
		{
			name:    "unsupported scheme mysql",
			url:     "mysql://user:pass@localhost:3306/mydb",
			wantErr: errors.ErrDatabaseURLInvalid,
		},
		{
			name:    "missing host in postgres url",
			url:     "postgres://",
			wantErr: errors.ErrDatabaseURLInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.BaseURL = "https://example.com"
			cfg.DatabaseURL = tt.url

			err := cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() unexpected err = %v", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Validate() err = %v; want %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestConfig_CookieDomain_RFC6265Boundaries(t *testing.T) {
	baseCfg := func() Config {
		c := DefaultConfig()
		c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
		c.BaseURL = "https://example.com"
		return c
	}

	invalidDomains := []struct {
		name   string
		domain string
	}{
		{"contains port", "example.com:8080"},
		{"contains http scheme", "http://example.com"},
		{"contains https scheme", "https://example.com"},
		{"contains path slash", "example.com/path"},
		{"contains backslash", "example.com\\path"},
		{"contains space", "example .com"},
		{"contains semicolon", "example;com"},
		{"contains control char", "example\x00.com"},
		{"contains query param", "example.com?foo=bar"},
		{"contains fragment", "example.com#anchor"},
	}

	for _, tt := range invalidDomains {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			cfg := baseCfg()
			cfg.SessionCookieDomain = tt.domain
			err := cfg.Validate()
			if !errors.Is(err, errors.ErrSessionCookieDomainInvalid) {
				t.Fatalf("Validate(domain=%q) err = %v; want ErrSessionCookieDomainInvalid", tt.domain, err)
			}
		})
	}

	validDomains := []string{
		"",
		"example.com",
		".example.com",
		"auth.sub.example.com",
		"localhost",
	}

	for _, d := range validDomains {
		t.Run("accepts valid domain "+d, func(t *testing.T) {
			cfg := baseCfg()
			cfg.SessionCookieDomain = d
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate(domain=%q) unexpected err = %v", d, err)
			}
		})
	}
}

func TestConfig_PasswordLength_Boundaries(t *testing.T) {
	baseCfg := func() Config {
		c := DefaultConfig()
		c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
		c.BaseURL = "https://example.com"
		return c
	}

	t.Run("min length below 8 is rejected", func(t *testing.T) {
		cfg := baseCfg()
		cfg.PasswordMinLength = 7
		if err := cfg.Validate(); !errors.Is(err, errors.ErrPasswordMinLengthTooShort) {
			t.Fatalf("expected ErrPasswordMinLengthTooShort, got %v", err)
		}
	})

	t.Run("max length exceeding 128 is rejected", func(t *testing.T) {
		cfg := baseCfg()
		cfg.PasswordMinLength = 8
		cfg.PasswordMaxLength = 129
		if err := cfg.Validate(); !errors.Is(err, errors.ErrPasswordMaxLengthInvalid) {
			t.Fatalf("expected ErrPasswordMaxLengthInvalid, got %v", err)
		}
	})

	t.Run("min length greater than 128 is rejected via max length check", func(t *testing.T) {
		cfg := baseCfg()
		cfg.PasswordMinLength = 130
		cfg.PasswordMaxLength = 140
		if err := cfg.Validate(); !errors.Is(err, errors.ErrPasswordMaxLengthInvalid) {
			t.Fatalf("expected ErrPasswordMaxLengthInvalid, got %v", err)
		}
	})
}

func TestConfig_SecretRedaction_LogValue_String(t *testing.T) {
	t.Run("RedactURL credentials masking", func(t *testing.T) {
		cases := []struct {
			input string
			want  string
		}{
			{"postgres://user:secret@localhost:5432/mydb?sslmode=disable", "postgres://user:REDACTED@localhost:5432/mydb?sslmode=disable"},
			{"postgres://:secret@localhost:5432/mydb", "postgres://:REDACTED@localhost:5432/mydb"},
			{"postgres://localhost:5432/mydb", "postgres://localhost:5432/mydb"},
			{"postgres://localhost:5432/mydb?password=secret", "postgres://localhost:5432/mydb?password=REDACTED"},
			{"postgres://localhost:5432/mydb?token=topsecret&sslmode=disable", "postgres://localhost:5432/mydb?sslmode=disable&token=REDACTED"},
			{"postgres://localhost:5432/mydb?api_key=mykey&pass=mypass", "postgres://localhost:5432/mydb?api_key=REDACTED&pass=REDACTED"},
			{"postgres://user:secret1@localhost:5432/mydb?password=secret2&sslmode=disable", "postgres://user:REDACTED@localhost:5432/mydb?password=REDACTED&sslmode=disable"},
			{"postgresql:///mydb?host=/var/run/postgresql&password=secret", "postgresql:///mydb?host=%2Fvar%2Frun%2Fpostgresql&password=REDACTED"},
			{"host=localhost user=alice password=secret dbname=mydb", "host=localhost user=alice password=REDACTED dbname=mydb"},
			{`user=foo password="bar with spaces" dbname=baz`, `user=foo password=REDACTED dbname=baz`},
			{`user=foo password='bar with spaces' dbname=baz`, `user=foo password=REDACTED dbname=baz`},
			{`host=localhost user=alice password = "bar with spaces" dbname=mydb`, `host=localhost user=alice password = REDACTED dbname=mydb`},
			{`host=localhost pass="my pass" token='secret token' dbname=mydb`, `host=localhost pass=REDACTED token=REDACTED dbname=mydb`},
			{`user=foo password="bar \"with\" spaces" dbname=baz`, `user=foo password=REDACTED dbname=baz`},
			{"", ""},
		}

		for _, tc := range cases {
			if got := RedactURL(tc.input); got != tc.want {
				t.Errorf("RedactURL(%q) = %q; want %q", tc.input, got, tc.want)
			}
		}
	})

	t.Run("RedactURL unix socket and query secret", func(t *testing.T) {
		raw := "postgresql:///mydb?host=/var/run/postgresql&password=supersecret"
		got := RedactURL(raw)
		if strings.Contains(got, "supersecret") {
			t.Errorf("RedactURL leaked plaintext secret: %q", got)
		}
		if !strings.Contains(got, "password=REDACTED") {
			t.Errorf("expected password=REDACTED, got: %q", got)
		}
	})

	t.Run("RedactURL quoted DSN with spaces", func(t *testing.T) {
		raw := `user=foo password="bar with spaces" dbname=baz`
		got := RedactURL(raw)
		if strings.Contains(got, "bar with spaces") {
			t.Errorf("RedactURL leaked plaintext password: %q", got)
		}
		want := `user=foo password=REDACTED dbname=baz`
		if got != want {
			t.Errorf("RedactURL(%q) = %q; want %q", raw, got, want)
		}
	})

	t.Run("Config.LogValue redacts DatabaseURL", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DatabaseURL = "postgres://admin:supersecret@localhost:5432/auth_db"
		cfg.BaseURL = "https://auth.example.com"

		val := cfg.LogValue()
		if val.Kind() != slog.KindGroup {
			t.Fatalf("LogValue kind = %v; want KindGroup", val.Kind())
		}

		var dbURLValue string
		for _, attr := range val.Group() {
			if attr.Key == "database_url" {
				dbURLValue = attr.Value.String()
			}
		}

		if strings.Contains(dbURLValue, "supersecret") {
			t.Fatalf("DatabaseURL in LogValue leaked plaintext password: %q", dbURLValue)
		}
		if !strings.Contains(dbURLValue, "REDACTED") {
			t.Fatalf("DatabaseURL in LogValue expected REDACTED: %q", dbURLValue)
		}
	})

	t.Run("Config.String redacts DatabaseURL", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DatabaseURL = "postgres://admin:supersecret@localhost:5432/auth_db"

		str := cfg.String()
		if strings.Contains(str, "supersecret") {
			t.Fatalf("Config.String() leaked plaintext password: %q", str)
		}
		if !strings.Contains(str, "REDACTED") {
			t.Fatalf("Config.String() expected REDACTED, got: %q", str)
		}
	})

	t.Run("OAuthConfig redacts ClientSecret", func(t *testing.T) {
		oauthCfg := OAuthConfig{
			ClientID:     "my-client-id",
			ClientSecret: "top-secret-token",
			RedirectURL:  "https://example.com/callback",
		}

		val := oauthCfg.LogValue()
		var secretVal string
		for _, attr := range val.Group() {
			if attr.Key == "client_secret" {
				secretVal = attr.Value.String()
			}
		}
		if strings.Contains(secretVal, "top-secret-token") {
			t.Fatalf("OAuthConfig.LogValue leaked client secret: %q", secretVal)
		}
		if secretVal != "[REDACTED]" {
			t.Fatalf("OAuthConfig.LogValue expected [REDACTED], got: %q", secretVal)
		}

		str := oauthCfg.String()
		if strings.Contains(str, "top-secret-token") {
			t.Fatalf("OAuthConfig.String() leaked client secret: %q", str)
		}
	})
}
