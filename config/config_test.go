package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kaiizer777/go-auth/errors"
)

// TestConfigValidate_FailingValidationLeavesConfigUntouched pins the no-write
// contract: defaults and provider normalization are applied to a working copy,
// so a config rejected by a later check is not silently rewritten first.
func TestConfigValidate_FailingValidationLeavesConfigUntouched(t *testing.T) {
	cfg := validOAuthBase()
	cfg.SessionIdleTimeout = 0
	cfg.OAuth.Providers = map[string]ProviderConfig{
		"microsoft": {
			ClientID:     "ms-client-id",
			ClientSecret: "ms-client-secret",
			RedirectURL:  "https://example.com/auth/oauth/microsoft/callback",
			Enabled:      true,
			Tenant:       "  Contoso.OnMicrosoft.com  ",
		},
	}
	// Fails at the TOTP key check, which runs after the session defaults and
	// the provider-map normalization.
	cfg.TOTP.EncryptionKey = "not-a-64-byte-hex-key"
	want := cfg.clone()

	if err := cfg.Validate(); !errors.Is(err, errors.ErrTOTPEncryptionKeyInvalid) {
		t.Fatalf("Validate = %v; want %v", err, errors.ErrTOTPEncryptionKeyInvalid)
	}
	if cfg.SessionIdleTimeout != 0 {
		t.Fatalf("SessionIdleTimeout = %v; want 0 (default written before the failing check)", cfg.SessionIdleTimeout)
	}
	if got := cfg.OAuth.Providers["microsoft"].Tenant; got != "  Contoso.OnMicrosoft.com  " {
		t.Fatalf("microsoft tenant = %q; want the unnormalized input", got)
	}
	if !reflect.DeepEqual(cfg, *want) {
		t.Fatalf("rejected Validate mutated the config:\n got %#v\nwant %#v", cfg, *want)
	}
}

// TestValidateGraphVersion_ParityWithConfigValidate pins that Config.Validate
// applies the same grammar the exported validator exposes. The empty version is
// covered separately: applyProviderDefaults rewrites it to v19.0 before the
// validation loop, so it is not a grammar disagreement.
func TestValidateGraphVersion_ParityWithConfigValidate(t *testing.T) {
	versions := []string{
		"v19.0", "v22.0", "v100.10", "19.0", "v0x13", "v19.0 beta", "../x",
		"v18.9", "v19", "v19.0.1", " v19.0", "v19.0 ", "V19.0", "v019.0",
	}
	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			cfg := validOAuthBase()
			cfg.OAuth.Facebook = &FacebookConfig{
				AppID:        "fb-app-id",
				AppSecret:    "fb-app-secret",
				RedirectURI:  "https://example.com/callback",
				GraphVersion: version,
			}

			validateErr := ValidateGraphVersion(version)
			configErr := cfg.Validate()
			got := errors.Is(configErr, errors.ErrOAuthGraphVersionInvalid)
			want := errors.Is(validateErr, errors.ErrOAuthGraphVersionInvalid)
			if got != want {
				t.Fatalf("Config.Validate error = %v; ValidateGraphVersion error = %v", configErr, validateErr)
			}
			if validateErr == nil && configErr != nil {
				t.Fatalf("Config.Validate = %v; want nil", configErr)
			}
		})
	}

	cfg := validOAuthBase()
	cfg.OAuth.Facebook = &FacebookConfig{
		AppID:       "fb-app-id",
		AppSecret:   "fb-app-secret",
		RedirectURI: "https://example.com/callback",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate with an empty graph version = %v; want nil", err)
	}
	if got := cfg.OAuth.Providers["facebook"].GraphVersion; got != "v19.0" {
		t.Fatalf("resolved graph version = %q; want v19.0", got)
	}
}

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

	t.Run("CSRF cookie name collides with session cookie name", func(t *testing.T) {
		cfg := baseCfg()
		cfg.CSRFCookieName = cfg.SessionCookieName
		if err := cfg.Validate(); !errors.Is(err, errors.ErrCSRFCookieNameCollision) {
			t.Errorf("Validate() err = %v; want ErrCSRFCookieNameCollision", err)
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
			name:    "rejects postgres scheme with unsupported socket query parameter",
			url:     "postgres:///mydb?socket=/var/run/postgresql/.s.PGSQL.5432",
			wantErr: errors.ErrDatabaseURLInvalid,
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
		{
			name:    "valid keyword dsn with password containing scheme separator",
			url:     "host=localhost port=5432 user=postgres dbname=mydb password='https://secret-vault/token'",
			wantErr: nil,
		},
		{
			name:    "valid keyword dsn with double-quoted password containing scheme separator",
			url:     `host=localhost port=5432 user=postgres dbname=mydb password="custom://auth-token"`,
			wantErr: nil,
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

	t.Run("ProviderConfig redacts ClientSecret", func(t *testing.T) {
		oauthCfg := ProviderConfig{
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
			t.Fatalf("ProviderConfig.LogValue leaked client secret: %q", secretVal)
		}
		if secretVal != "[REDACTED]" {
			t.Fatalf("ProviderConfig.LogValue expected [REDACTED], got: %q", secretVal)
		}

		str := oauthCfg.String()
		if strings.Contains(str, "top-secret-token") {
			t.Fatalf("ProviderConfig.String() leaked client secret: %q", str)
		}
	})

	t.Run("TOTPConfig redacts EncryptionKey", func(t *testing.T) {
		totpCfg := TOTPConfig{
			EncryptionKey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Issuer:               "test-app",
			ChallengeTokenTTL:    10 * time.Minute,
			AttemptWindow:        5 * time.Minute,
			MaxAttemptsPerWindow: 5,
		}

		val := totpCfg.LogValue()
		var secretVal string
		for _, attr := range val.Group() {
			if attr.Key == "encryption_key" {
				secretVal = attr.Value.String()
			}
		}
		if strings.Contains(secretVal, "0123456789abcdef") {
			t.Fatalf("TOTPConfig.LogValue leaked encryption key: %q", secretVal)
		}
		if secretVal != "[REDACTED]" {
			t.Fatalf("TOTPConfig.LogValue expected [REDACTED], got: %q", secretVal)
		}

		str := totpCfg.String()
		if strings.Contains(str, "0123456789abcdef") {
			t.Fatalf("TOTPConfig.String() leaked encryption key: %q", str)
		}
		if !strings.Contains(str, "EncryptionKey: [REDACTED]") {
			t.Fatalf("TOTPConfig.String() expected EncryptionKey: [REDACTED], got: %q", str)
		}

		formatted := fmt.Sprintf("%+v", totpCfg)
		if strings.Contains(formatted, "0123456789abcdef") {
			t.Fatalf("fmt.Sprintf(%%+v) leaked encryption key: %q", formatted)
		}
		if !strings.Contains(formatted, "EncryptionKey: [REDACTED]") {
			t.Fatalf("fmt.Sprintf(%%+v) expected EncryptionKey: [REDACTED], got: %q", formatted)
		}

		emptyCfg := TOTPConfig{Issuer: "test-app"}
		if strings.Contains(emptyCfg.String(), "[REDACTED]") {
			t.Fatalf("empty EncryptionKey should not contain [REDACTED], got: %q", emptyCfg.String())
		}
	})
}
func TestConfigSecretsMaskedUnderFormatVerbs(t *testing.T) {
	const (
		dbPassword    = "db-super-secret"
		stateSecret   = "state-super-secret"
		tokenKEK      = "kek-super-secret"
		clientSecret  = "provider-super-secret"
		privateKey    = "private-key-super-secret"
		totpKey       = "totp-super-secret"
		msSecret      = "microsoft-super-secret"
		fbSecret      = "facebook-super-secret"
		discordSecret = "discord-super-secret"
		xSecret       = "x-super-secret"
	)

	provider := ProviderConfig{ClientID: "id", ClientSecret: clientSecret, PrivateKey: privateKey}
	oauthCfg := OAuthConfig{
		Providers: map[string]ProviderConfig{"google": provider},
		Microsoft: &MicrosoftConfig{
			ClientID:     "ms-id",
			ClientSecret: msSecret,
		},
		Facebook: &FacebookConfig{
			AppID:     "fb-id",
			AppSecret: fbSecret,
		},
		Discord: &DiscordConfig{
			ClientID:     "discord-id",
			ClientSecret: discordSecret,
		},
		X: &XConfig{
			ClientID:     "x-id",
			ClientSecret: xSecret,
		},
		StateSecret: stateSecret,
		TokenKEK:    tokenKEK,
	}
	cfg := Config{
		DatabaseURL: "postgres://admin:" + dbPassword + "@localhost:5432/auth",
		OAuth:       oauthCfg,
		TOTP:        TOTPConfig{EncryptionKey: totpKey},
	}

	cases := []struct {
		name    string
		value   any
		secrets []string
	}{
		{"Config", cfg, []string{dbPassword, stateSecret, tokenKEK, clientSecret, privateKey, totpKey}},
		{"OAuthConfig", oauthCfg, []string{stateSecret, tokenKEK, clientSecret, privateKey, msSecret, fbSecret, discordSecret, xSecret}},
		{"ProviderConfig", provider, []string{clientSecret, privateKey}},
		{"TOTPConfig", cfg.TOTP, []string{totpKey}},
		{"MicrosoftConfig", *oauthCfg.Microsoft, []string{msSecret}},
		{"FacebookConfig", *oauthCfg.Facebook, []string{fbSecret}},
		{"DiscordConfig", *oauthCfg.Discord, []string{discordSecret}},
		{"XConfig", *oauthCfg.X, []string{xSecret}},
	}
	for _, tc := range cases {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(verb, tc.value)
			for _, secret := range tc.secrets {
				if strings.Contains(out, secret) {
					t.Errorf("%s under %s leaked %q: %s", tc.name, verb, secret, out)
				}
			}
		}
	}
}
func TestConfigValidate_SecurityHeaders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	cfg.BaseURL = "https://example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf(`DefaultConfig Validate = %v`, err)
	}

	badFrame := DefaultConfig()
	badFrame.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	badFrame.BaseURL = "https://example.com"
	badFrame.SecurityHeaders.FrameOptions = `ALLOW`
	if err := badFrame.Validate(); err != errors.ErrFrameOptionsInvalid {
		t.Errorf(`FrameOptions err = %v`, err)
	}

	negHSTS := DefaultConfig()
	negHSTS.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	negHSTS.BaseURL = "https://example.com"
	negHSTS.SecurityHeaders.HSTSMaxAge = -time.Second
	if err := negHSTS.Validate(); err != errors.ErrHSTSMaxAgeNegative {
		t.Errorf(`HSTSMaxAge err = %v`, err)
	}

	subSecondHSTS := DefaultConfig()
	subSecondHSTS.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	subSecondHSTS.BaseURL = "https://example.com"
	subSecondHSTS.SecurityHeaders.HSTSMaxAge = 500 * time.Millisecond
	if err := subSecondHSTS.Validate(); err != errors.ErrHSTSMaxAgeTooSmall {
		t.Errorf(`sub-second HSTSMaxAge err = %v`, err)
	}

	badRef := DefaultConfig()
	badRef.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	badRef.BaseURL = "https://example.com"
	badRef.SecurityHeaders.ReferrerPolicy = `nope`
	if err := badRef.Validate(); err != errors.ErrReferrerPolicyInvalid {
		t.Errorf(`ReferrerPolicy err = %v`, err)
	}

	zeroCSRF := DefaultConfig()
	zeroCSRF.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	zeroCSRF.BaseURL = "https://example.com"
	zeroCSRF.CSRFCookieMaxAge = -time.Second
	if err := zeroCSRF.Validate(); err != errors.ErrCSRFCookieMaxAgeInvalid {
		t.Errorf(`CSRFCookieMaxAge err = %v`, err)
	}

	subSecondCSRF := DefaultConfig()
	subSecondCSRF.DatabaseURL = "postgres://user:pass@localhost:5432/testdb"
	subSecondCSRF.BaseURL = "https://example.com"
	subSecondCSRF.CSRFCookieMaxAge = 500 * time.Millisecond
	if err := subSecondCSRF.Validate(); err != errors.ErrCSRFCookieMaxAgeInvalid {
		t.Errorf(`sub-second CSRFCookieMaxAge err = %v`, err)
	}
}

func TestDatabaseType_Validation(t *testing.T) {
	t.Run("default empty is treated as postgres", func(t *testing.T) {
		cfg := Config{
			DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
			BaseURL:     "https://example.com",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if cfg.DatabaseType != DatabaseTypePostgres {
			t.Errorf("got %q, want %q", cfg.DatabaseType, DatabaseTypePostgres)
		}
	})

	t.Run("explicit postgres", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypePostgres,
			DatabaseURL:  "postgres://user:pass@localhost:5432/testdb",
			BaseURL:      "https://example.com",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("unsupported database type", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseType("sqlite"),
			DatabaseURL:  "sqlite://auth.db",
			BaseURL:      "https://example.com",
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for unsupported database type, got nil")
		}
		if !errors.Is(err, errors.ErrDatabaseUnsupported) {
			t.Errorf("got %v, want ErrDatabaseUnsupported", err)
		}
	})

	t.Run("mysql valid config", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMySQL,
			DatabaseURL:  "user:pass@tcp(127.0.0.1:3306)/auth?parseTime=true",
			BaseURL:      "https://example.com",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if cfg.MaxOpenConns != 25 {
			t.Errorf("expected MaxOpenConns 25, got %d", cfg.MaxOpenConns)
		}
	})

	t.Run("mysql missing DSN", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMySQL,
			BaseURL:      "https://example.com",
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for empty MySQL DSN, got nil")
		}
	})

	t.Run("mysql missing parseTime", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMySQL,
			DatabaseURL:  "user:pass@tcp(127.0.0.1:3306)/auth",
			BaseURL:      "https://example.com",
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for missing parseTime=true, got nil")
		}
	})

	t.Run("mongodb valid uri", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongo,
			DatabaseURL:  "mongodb://user:pass@localhost:27017/auth",
			BaseURL:      "https://example.com",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("mongodb valid srv uri", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongo,
			DatabaseURL:  "mongodb+srv://user:pass@cluster0.example.com/mydb",
			BaseURL:      "https://example.com",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("mongodb missing uri", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongo,
			BaseURL:      "https://example.com",
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for empty Mongo URI, got nil")
		}
	})

	t.Run("mongodb invalid prefix", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongo,
			DatabaseURL:  "http://localhost:27017/auth",
			BaseURL:      "https://example.com",
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for invalid Mongo URI prefix, got nil")
		}
	})

	t.Run("mongodb empty database returns ErrInvalidConfig", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongoDB,
			DatabaseURL:  "mongodb://user:pass@localhost:27017",
			BaseURL:      "https://example.com",
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for empty MongoDB database, got nil")
		}
		if !errors.Is(err, errors.ErrInvalidConfig) {
			t.Errorf("got %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("mongodb negative connect timeout returns ErrInvalidConfig", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongoDB,
			DatabaseURL:  "mongodb://user:pass@localhost:27017/auth",
			BaseURL:      "https://example.com",
			MongoDB: MongoDBConfig{
				Database:       "auth",
				ConnectTimeout: -1 * time.Second,
			},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for negative ConnectTimeout, got nil")
		}
		if !errors.Is(err, errors.ErrInvalidConfig) {
			t.Errorf("got %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("mongodb negative server selection timeout returns ErrInvalidConfig", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongoDB,
			DatabaseURL:  "mongodb://user:pass@localhost:27017/auth",
			BaseURL:      "https://example.com",
			MongoDB: MongoDBConfig{
				Database:               "auth",
				ServerSelectionTimeout: -1 * time.Second,
			},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for negative ServerSelectionTimeout, got nil")
		}
		if !errors.Is(err, errors.ErrInvalidConfig) {
			t.Errorf("got %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("mongodb negative max conn idle time returns ErrInvalidConfig", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongoDB,
			DatabaseURL:  "mongodb://user:pass@localhost:27017/auth",
			BaseURL:      "https://example.com",
			MongoDB: MongoDBConfig{
				Database:        "auth",
				MaxConnIdleTime: -1 * time.Second,
			},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for negative MaxConnIdleTime, got nil")
		}
		if !errors.Is(err, errors.ErrInvalidConfig) {
			t.Errorf("got %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("mongodb invalid query timeout returns ErrInvalidConfig", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongoDB,
			DatabaseURL:  "mongodb://user:pass@localhost:27017/auth?connectTimeoutMS=-5",
			BaseURL:      "https://example.com",
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for negative connectTimeoutMS query, got nil")
		}
		if !errors.Is(err, errors.ErrInvalidConfig) {
			t.Errorf("got %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("mongodb explicit valid config", func(t *testing.T) {
		cfg := Config{
			DatabaseType: DatabaseTypeMongoDB,
			DatabaseURL:  "mongodb://user:pass@localhost:27017",
			BaseURL:      "https://example.com",
			MongoDB: MongoDBConfig{
				Database:               "custom_auth",
				ConnectTimeout:         5 * time.Second,
				ServerSelectionTimeout: 5 * time.Second,
				MaxConnIdleTime:        10 * time.Minute,
			},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
		if cfg.MongoDB.Database != "custom_auth" {
			t.Errorf("got %q, want %q", cfg.MongoDB.Database, "custom_auth")
		}
	})
}

func TestRedactURL_Dialects(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "postgres standard",
			raw:      "postgres://admin:secret123@localhost:5432/mydb?sslmode=disable",
			expected: "postgres://admin:REDACTED@localhost:5432/mydb?sslmode=disable",
		},
		{
			name:     "mysql dsn",
			raw:      "root:secret123@tcp(127.0.0.1:3306)/auth?parseTime=true",
			expected: "root:REDACTED@tcp(127.0.0.1:3306)/auth?parseTime=true",
		},
		{
			name:     "mysql dsn password with @ symbol",
			raw:      "user:p@ss@word@tcp(127.0.0.1:3306)/db",
			expected: "user:REDACTED@tcp(127.0.0.1:3306)/db",
		},
		{
			name:     "mysql dsn unix socket password with @ symbol",
			raw:      "user:p@ss@word@unix(/var/run/mysqld/mysqld.sock)/db",
			expected: "user:REDACTED@unix(/var/run/mysqld/mysqld.sock)/db",
		},
		{
			name:     "mongo standard uri",
			raw:      "mongodb://admin:secret123@localhost:27017/auth",
			expected: "mongodb://admin:REDACTED@localhost:27017/auth",
		},
		{
			name:     "mongo srv uri",
			raw:      "mongodb+srv://admin:secret123@cluster0.example.com/auth",
			expected: "mongodb+srv://admin:REDACTED@cluster0.example.com/auth",
		},
		{
			name:     "no password",
			raw:      "localhost:5432/mydb",
			expected: "localhost:5432/mydb",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactURL(tc.raw)
			if got != tc.expected {
				t.Errorf("RedactURL(%q) = %q, want %q", tc.raw, got, tc.expected)
			}
		})
	}
}

func TestRedactURL_MySQLPasswordsWithAtSymbol(t *testing.T) {
	rawDSN := "user:p@ss@word@tcp(127.0.0.1:3306)/auth_db?charset=utf8mb4&parseTime=True"
	redacted := RedactURL(rawDSN)

	if strings.Contains(redacted, "p@ss@word") {
		t.Fatalf("RedactURL leaked password containing @: %s", redacted)
	}
	if !strings.Contains(redacted, "user:REDACTED@tcp(127.0.0.1:3306)/auth_db") {
		t.Fatalf("unexpected redacted DSN format: %s", redacted)
	}

	cfg := DefaultConfig()
	cfg.DatabaseType = DatabaseTypeMySQL
	cfg.DatabaseURL = rawDSN

	logVal := cfg.LogValue()
	logStr := fmt.Sprintf("%v", logVal)
	if strings.Contains(logStr, "p@ss@word") {
		t.Fatalf("Config.LogValue leaked password containing @: %s", logStr)
	}

	cfgStr := cfg.String()
	if strings.Contains(cfgStr, "p@ss@word") {
		t.Fatalf("Config.String leaked password containing @: %s", cfgStr)
	}
}

func TestConfigValidate_DeprecatedMongoOverridesRespected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseType = DatabaseTypeMongoDB
	cfg.DatabaseURL = "mongodb://localhost:27017/auth"
	cfg.BaseURL = "http://localhost:8080"
	cfg.Mongo.ConnectTimeout = 5 * time.Second
	cfg.Mongo.ServerSelectionTimeout = 3 * time.Second
	cfg.Mongo.MaxConnIdleTime = 15 * time.Minute

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if cfg.MongoDB.ConnectTimeout != 5*time.Second {
		t.Errorf("got MongoDB.ConnectTimeout %v, want 5s", cfg.MongoDB.ConnectTimeout)
	}
	if cfg.MongoDB.ServerSelectionTimeout != 3*time.Second {
		t.Errorf("got MongoDB.ServerSelectionTimeout %v, want 3s", cfg.MongoDB.ServerSelectionTimeout)
	}
	if cfg.MongoDB.MaxConnIdleTime != 15*time.Minute {
		t.Errorf("got MongoDB.MaxConnIdleTime %v, want 15m", cfg.MongoDB.MaxConnIdleTime)
	}
	if cfg.Mongo.ConnectTimeout != 5*time.Second {
		t.Errorf("got Mongo.ConnectTimeout %v, want 5s", cfg.Mongo.ConnectTimeout)
	}
	if cfg.Mongo.ServerSelectionTimeout != 3*time.Second {
		t.Errorf("got Mongo.ServerSelectionTimeout %v, want 3s", cfg.Mongo.ServerSelectionTimeout)
	}
	if cfg.Mongo.MaxConnIdleTime != 15*time.Minute {
		t.Errorf("got Mongo.MaxConnIdleTime %v, want 15m", cfg.Mongo.MaxConnIdleTime)
	}
}

func TestConfigValidate_MongoDBDefaultsAppliedWhenUnset(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DatabaseType = DatabaseTypeMongoDB
	cfg.DatabaseURL = "mongodb://localhost:27017/auth"
	cfg.BaseURL = "http://localhost:8080"

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if cfg.MongoDB.ConnectTimeout != 10*time.Second {
		t.Errorf("got MongoDB.ConnectTimeout %v, want 10s", cfg.MongoDB.ConnectTimeout)
	}
	if cfg.MongoDB.ServerSelectionTimeout != 10*time.Second {
		t.Errorf("got MongoDB.ServerSelectionTimeout %v, want 10s", cfg.MongoDB.ServerSelectionTimeout)
	}
	if cfg.MongoDB.MaxConnIdleTime != 30*time.Minute {
		t.Errorf("got MongoDB.MaxConnIdleTime %v, want 30m", cfg.MongoDB.MaxConnIdleTime)
	}
	if cfg.Mongo.ConnectTimeout != 10*time.Second {
		t.Errorf("got Mongo.ConnectTimeout %v, want 10s", cfg.Mongo.ConnectTimeout)
	}
}

func TestConfigValidate_DisabledProviderWithIncompleteCredentialsBoots(t *testing.T) {
	off := false
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "disabled provider in map with empty credentials",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"discord": {
						Enabled: false,
					},
				}
			},
		},
		{
			name: "disabled provider in map with partial credentials",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"google": {
						ClientID: "google-id",
						Enabled:  false,
					},
				}
			},
		},
		{
			name: "disabled provider in map with incomplete typed struct",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"microsoft": {
						Enabled: false,
					},
				}
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientID: "ms-client-id",
				}
			},
		},
		{
			name: "disabled typed provider with missing credentials",
			mutate: func(c *Config) {
				c.OAuth.Microsoft = &MicrosoftConfig{
					Enabled:  &off,
					ClientID: "ms-client-id",
				}
			},
		},
		{
			name: "typed disabled overrides enabled map entry with missing credentials",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"discord": {
						Enabled:  true,
						ClientID: "discord-id",
					},
				}
				c.OAuth.Discord = &DiscordConfig{
					Enabled: &off,
				}
			},
		},
		{
			name: "map disabled overrides typed enabled with missing credentials",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"facebook": {
						Enabled: false,
					},
				}
				c.OAuth.Facebook = &FacebookConfig{
					AppID: "fb-app-id",
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOAuthBase()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v; want nil for disabled provider", err)
			}
		})
	}
}

func TestConfigValidate_SplitCredentialsBoot(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		mutate   func(*Config)
		wantID   string
		wantSec  string
		wantURI  string
	}{
		{
			name:     "microsoft client ID in map and secret in typed",
			provider: "microsoft",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"microsoft": {
						ClientID:    "ms-map-id",
						RedirectURL: "https://example.com/callback",
						Enabled:     true,
					},
				}
				c.OAuth.Microsoft = &MicrosoftConfig{
					ClientSecret: "ms-typed-secret",
				}
			},
			wantID:  "ms-map-id",
			wantSec: "ms-typed-secret",
			wantURI: "https://example.com/callback",
		},
		{
			name:     "discord client secret in map and id/redirect in typed",
			provider: "discord",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"discord": {
						ClientSecret: "discord-map-secret",
						Enabled:      true,
					},
				}
				c.OAuth.Discord = &DiscordConfig{
					ClientID:    "discord-typed-id",
					RedirectURI: "https://example.com/discord/callback",
				}
			},
			wantID:  "discord-typed-id",
			wantSec: "discord-map-secret",
			wantURI: "https://example.com/discord/callback",
		},
		{
			name:     "facebook app id in typed and secret/redirect in map",
			provider: "facebook",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"facebook": {
						ClientSecret: "fb-map-secret",
						RedirectURL:  "https://example.com/fb/callback",
						Enabled:      true,
					},
				}
				c.OAuth.Facebook = &FacebookConfig{
					AppID: "fb-typed-id",
				}
			},
			wantID:  "fb-typed-id",
			wantSec: "fb-map-secret",
			wantURI: "https://example.com/fb/callback",
		},
		{
			name:     "x client id and redirect in map and secret in typed",
			provider: "x",
			mutate: func(c *Config) {
				c.OAuth.Providers = map[string]ProviderConfig{
					"x": {
						ClientID:    "x-map-id",
						RedirectURL: "https://example.com/x/callback",
						Enabled:     true,
					},
				}
				c.OAuth.X = &XConfig{
					ClientSecret: "x-typed-secret",
				}
			},
			wantID:  "x-map-id",
			wantSec: "x-typed-secret",
			wantURI: "https://example.com/x/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOAuthBase()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v; want nil for valid split-credential config", err)
			}
			p, ok := cfg.OAuth.Providers[tt.provider]
			if !ok {
				t.Fatalf("provider %q not found in merged Providers map", tt.provider)
			}
			if !p.Enabled {
				t.Fatalf("provider %q Enabled = false; want true", tt.provider)
			}
			if p.ClientID != tt.wantID {
				t.Errorf("ClientID = %q; want %q", p.ClientID, tt.wantID)
			}
			if p.ClientSecret != tt.wantSec {
				t.Errorf("ClientSecret = %q; want %q", p.ClientSecret, tt.wantSec)
			}
			if p.RedirectURL != tt.wantURI {
				t.Errorf("RedirectURL = %q; want %q", p.RedirectURL, tt.wantURI)
			}
		})
	}
}
