package config

import (
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
					DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
					BaseURL:     "https://example.com",
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
			name: "argon2 parallelism zero",
			mutate: func(c *Config) {
				c.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
				c.BaseURL = "https://example.com"
				c.Argon2.Parallelism = 0
			},
			wantErr: errors.ErrArgon2ParallelismZero,
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
		})
	}
}
